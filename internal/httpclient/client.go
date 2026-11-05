// Package httpclient is the HTTP client every scan request goes through. It
// applies the user's connection options (proxy, headers, authentication, TLS),
// limits concurrency, throttles, refuses out-of-scope URLs, never follows
// redirects on its own and counts requests and bytes for the report footer.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/cli"
)

// MaxBodySize is the largest response body read into memory. Longer bodies
// are cut and marked as truncated.
const MaxBodySize = 16 << 20

// ErrOutOfScope is returned for requests to hosts outside the scan scope.
var ErrOutOfScope = errors.New("URL is out of scope")

// Request is a request with per-request settings. Method defaults to GET and
// MaxBody to MaxBodySize.
type Request struct {
	Method  string
	URL     string
	Header  http.Header
	Body    []byte
	MaxBody int64
}

// Response is a fully read response.
type Response struct {
	URL        *url.URL
	StatusCode int
	Header     http.Header
	Body       []byte
	Truncated  bool // the body was longer than the read limit
	// Blocked names what refused the request instead of answering it: "rate
	// limit" for a 429, "server overload" for a 502, 503 or 504, or the
	// firewall whose block page came back ("Cloudflare challenge", …).
	// Such a response says nothing about the path that was asked for.
	Blocked string
	// SiteBlocked is set when the refusal covers the whole site (a rate
	// limit, an overload, a challenge or a lockout), not one path a
	// firewall rule matched.
	SiteBlocked bool
}

// IsRedirect reports whether the response is a 3xx with a Location header.
func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400 && r.Header.Get("Location") != ""
}

// Location returns the redirect target resolved against the request URL.
func (r *Response) Location() (*url.URL, error) {
	loc := r.Header.Get("Location")
	if loc == "" {
		return nil, errors.New("no Location header")
	}
	return r.URL.Parse(loc)
}

// Stats counts what the client sent and received. Byte counts are measured on
// the network connections, so they include headers, TLS and proxy overhead.
type Stats struct {
	Requests      int64
	BytesSent     int64
	BytesReceived int64
	Retries       int64 // requests sent again after a network error, a 429 or a 502-504
	Blocked       int64 // answers that were a rate limit, an overload or a firewall block page
}

// Client sends scan requests. It is safe for concurrent use.
type Client struct {
	hc        *http.Client
	userAgent string
	headers   http.Header
	cookie    string
	auth      *cli.Credentials
	sem       chan struct{}
	throttle  time.Duration

	throttleMu sync.Mutex
	nextSlot   time.Time

	scopeMu sync.RWMutex
	hosts   map[string]bool // exact hostnames
	domains []string        // "*.example.com" entries, stored as ".example.com"

	requests, sent, received atomic.Int64
	retries, blocked         atomic.Int64

	logMu sync.Mutex
	log   *os.File // --log-requests; nil when off

	// The circuit breaker: when the target keeps failing or refusing, the
	// scan is told once, through OnFailing, so that it stops instead of
	// reporting "nothing found" for everything that follows.
	healthMu    sync.Mutex
	consecutive int    // failed or blocked answers in a row
	lastBad     string // what the last of them was
	failing     string // why the breaker tripped; empty while healthy
	onFailing   func(reason string)
}

// Retry and circuit breaker settings.
const (
	maxRetries        = 2                // extra attempts for an idempotent request
	maxRetryAfter     = 30 * time.Second // the longest Retry-After honoured
	tripAfter         = 25               // failed or blocked answers in a row that trip the breaker
	maxConnectTimeout = 15 * time.Second
	blockPageBytes    = 8 << 10 // how much of a body is searched for a block page
)

// New builds a client from validated scan options. The target host is always
// in scope; o.Scope adds more hosts ("*.example.com" matches subdomains).
func New(o *cli.ScanOptions) (*Client, error) {
	threads := max(o.Threads, 1)
	c := &Client{
		userAgent: userAgentFor(o),
		headers:   o.Headers.Clone(),
		cookie:    o.Cookie,
		auth:      o.HTTPAuth,
		sem:       make(chan struct{}, threads),
		throttle:  o.Throttle,
		hosts:     map[string]bool{},
	}
	if o.Target != nil {
		c.AddScope(o.Target.Hostname())
	}
	for _, d := range o.Scope {
		c.AddScope(d)
	}

	jar, err := newScopedJar(c)
	if err != nil {
		return nil, err
	}
	if o.LogRequests != "" {
		f, err := os.OpenFile(o.LogRequests, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("--log-requests: %w", err)
		}
		target := ""
		if o.Target != nil {
			target = o.Target.String()
		}
		fmt.Fprintf(f, "# cmsrecon %s, %s, started %s\n# time\tmethod\tstatus\tbytes\tms\turl\terror\n", buildinfo.Version, target, time.Now().UTC().Format(time.RFC3339))
		c.log = f
	}
	resolve := o.Resolve
	// A host that does not answer at all is known after 15 seconds; a slow
	// page still gets the whole --timeout.
	dialer := &net.Dialer{Timeout: min(o.Timeout, maxConnectTimeout), KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// --resolve and --vhost: connect to the given address; the
			// Host header and TLS SNI keep the host name.
			if host, port, err := net.SplitHostPort(addr); err == nil {
				if ip, ok := resolve[strings.ToLower(host)]; ok {
					addr = net.JoinHostPort(ip, port)
				}
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &countingConn{Conn: conn, c: c}, nil
		},
		// Old WordPress hosts still run TLS 1.0/1.1; the scanner only reads
		// public pages, so compatibility wins over Go's 1.2 default.
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			InsecureSkipVerify: o.Insecure,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          threads * 2,
		MaxIdleConnsPerHost:   threads,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   o.Timeout,
		ExpectContinueTimeout: time.Second,
	}
	// Only an explicit --proxy is used; HTTP_PROXY and friends are ignored so
	// that scan traffic never takes a route the user did not ask for.
	if o.Proxy != nil {
		transport.Proxy = http.ProxyURL(o.Proxy)
	}
	c.hc = &http.Client{
		Transport: transport,
		Timeout:   o.Timeout,
		// Cookies the site sets (load balancer stickiness, cookie checks)
		// are sent back, to in-scope hosts only.
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

func userAgentFor(o *cli.ScanOptions) string {
	switch {
	case o.UserAgent != "":
		return o.UserAgent
	case o.RandomUserAgent:
		return browserUserAgents[rand.IntN(len(browserUserAgents))]
	default:
		return DefaultUserAgent()
	}
}

// DefaultUserAgent identifies cmsrecon and its version.
func DefaultUserAgent() string {
	return "cmsrecon/" + buildinfo.Version
}

// UserAgent returns the User-Agent the client sends.
func (c *Client) UserAgent() string { return c.userAgent }

// AddScope adds a hostname, or "*.domain" for every subdomain of domain.
func (c *Client) AddScope(host string) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return
	}
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if strings.HasPrefix(host, "*.") {
		c.domains = append(c.domains, host[1:])
		return
	}
	c.hosts[host] = true
}

// InScope reports whether requests to u are allowed. Only the hostname is
// compared, so other ports and schemes on an in-scope host are in scope.
func (c *Client) InScope(u *url.URL) bool {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	c.scopeMu.RLock()
	defer c.scopeMu.RUnlock()
	if c.hosts[host] {
		return true
	}
	for _, d := range c.domains {
		if strings.HasSuffix(host, d) {
			return true
		}
	}
	return false
}

// Scope lists the in-scope hosts and domain patterns.
func (c *Client) Scope() []string {
	c.scopeMu.RLock()
	defer c.scopeMu.RUnlock()
	out := make([]string, 0, len(c.hosts)+len(c.domains))
	for h := range c.hosts {
		out = append(out, h)
	}
	for _, d := range c.domains {
		out = append(out, "*"+d)
	}
	return out
}

// Stats returns the request and byte counters.
func (c *Client) Stats() Stats {
	return Stats{
		Requests:      c.requests.Load(),
		BytesSent:     c.sent.Load(),
		BytesReceived: c.received.Load(),
		Retries:       c.retries.Load(),
		Blocked:       c.blocked.Load(),
	}
}

// Get fetches rawURL with the default body limit.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.Do(ctx, Request{URL: rawURL})
}

// Close closes the request log, if there is one.
func (c *Client) Close() error {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if c.log == nil {
		return nil
	}
	err := c.log.Close()
	c.log = nil
	return err
}

// logRequest writes one line of the request log.
func (c *Client) logRequest(start time.Time, method, u string, res *Response, err error) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if c.log == nil {
		return
	}
	status, size, msg := "-", 0, ""
	if res != nil {
		status, size = fmt.Sprint(res.StatusCode), len(res.Body)
	}
	if err != nil {
		msg = shortError(err)
	}
	fmt.Fprintf(c.log, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", start.UTC().Format("2006-01-02T15:04:05.000Z"), method, status, size, time.Since(start).Milliseconds(), u, msg)
}

// OnFailing sets the function called, once, when the target keeps failing
// or refusing requests: tripAfter network errors, rate limits, overloads
// or firewall block pages in a row.
func (c *Client) OnFailing(f func(reason string)) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.onFailing = f
}

// Failing returns why the circuit breaker tripped, or "" while it has not.
func (c *Client) Failing() string {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	return c.failing
}

// Do sends r and reads the response body up to r.MaxBody bytes. Redirects
// are returned as they are, never followed. A GET or HEAD that fails with
// a network error, a 429 or a 502-504 is sent again, up to maxRetries
// times, after the Retry-After the server asks for or a short backoff.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	idempotent := method == http.MethodGet || method == http.MethodHead
	for attempt := 0; ; attempt++ {
		start := time.Now()
		res, err := c.doOnce(ctx, method, r)
		if !errors.Is(err, ErrOutOfScope) {
			c.logRequest(start, method, r.URL, res, err)
		}
		if errors.Is(err, ErrOutOfScope) || ctx.Err() != nil {
			return res, err
		}
		limit := maxRetries
		if isTimeout(err) {
			limit = 1 // a slow server gets one more chance, not two
		}
		retry := idempotent && attempt < limit && (transient(err) || (err == nil && retryStatus(res.StatusCode)))
		if !retry {
			c.record(res, err)
			return res, err
		}
		c.retries.Add(1)
		if err := sleep(ctx, retryDelay(res, attempt)); err != nil {
			return nil, err
		}
	}
}

// transient reports whether a network error may go away on its own: a
// timeout or a dropped connection. A refused connection, a DNS failure or
// a certificate error will not, so they are not retried.
func transient(err error) bool {
	if err == nil {
		return false
	}
	if isTimeout(err) {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "server closed idle connection") ||
		strings.Contains(msg, "GOAWAY") || strings.Contains(msg, "stream error")
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func retryStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

// retryDelay is the Retry-After a 429 or 503 asks for (seconds or an HTTP
// date, at most maxRetryAfter), or 1s, then 2s, with some jitter.
func retryDelay(res *Response, attempt int) time.Duration {
	if res != nil {
		if ra := strings.TrimSpace(res.Header.Get("Retry-After")); ra != "" {
			if secs, err := time.ParseDuration(ra + "s"); err == nil && secs >= 0 {
				return min(secs, maxRetryAfter)
			}
			if t, err := http.ParseTime(ra); err == nil {
				return min(max(time.Until(t), 0), maxRetryAfter)
			}
		}
	}
	base := time.Second << attempt
	return base + time.Duration(rand.Int64N(int64(base/2)))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// record feeds the circuit breaker with the final answer to a request.
func (c *Client) record(res *Response, err error) {
	bad := ""
	switch {
	case err != nil:
		bad = "network errors (" + shortError(err) + ")"
	case res.Blocked != "":
		c.blocked.Add(1)
		if res.SiteBlocked {
			bad = fmt.Sprintf("%s (HTTP %d)", res.Blocked, res.StatusCode)
		}
	}
	c.healthMu.Lock()
	if bad == "" {
		c.consecutive = 0
		c.healthMu.Unlock()
		return
	}
	c.consecutive++
	c.lastBad = bad
	var notify func(string)
	if c.consecutive >= tripAfter && c.failing == "" {
		c.failing = fmt.Sprintf("%d requests in a row failed or were refused: %s", c.consecutive, bad)
		notify = c.onFailing
	}
	reason := c.failing
	c.healthMu.Unlock()
	if notify != nil {
		notify(reason)
	}
}

func shortError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	if len(msg) > 80 {
		msg = msg[:80] + "…"
	}
	return msg
}

// blockPages are the pages firewalls and CDNs answer with instead of the
// site. Each pattern is matched case-insensitively in the first
// blockPageBytes of the body.
var blockPages = []struct {
	name, marker string
	site         bool // the whole site is refused, not one path
}{
	{"Cloudflare challenge", "cf-chl-", true},
	{"Cloudflare challenge", "<title>just a moment...</title>", true},
	{"Cloudflare block", "attention required! | cloudflare", false},
	{"Wordfence lockout", "your access to this site has been limited", true},
	{"Wordfence block", "generated by wordfence", false},
	{"Sucuri firewall block", "access denied - sucuri website firewall", true},
	{"Imperva/Incapsula block", "_incapsula_resource", true},
	{"Imperva/Incapsula block", "incapsula incident id", true},
	{"F5 firewall block", "the requested url was rejected. please consult with your administrator", false},
	{"Akamai block", "access denied</title>", false},
	{"ModSecurity block", "mod_security", false},
}

// blockedBy says what refused a request, or "" when the answer is the
// site's own, and whether the refusal covers the whole site.
func blockedBy(code int, h http.Header, body []byte) (string, bool) {
	switch {
	case code == http.StatusTooManyRequests:
		return "rate limit", true
	case h.Get("Cf-Mitigated") == "challenge":
		return "Cloudflare challenge", true
	}
	if code == http.StatusForbidden || code == http.StatusServiceUnavailable || code == http.StatusNotAcceptable {
		head := bytes.ToLower(body[:min(len(body), blockPageBytes)])
		for _, b := range blockPages {
			if bytes.Contains(head, []byte(b.marker)) {
				return b.name, b.site
			}
		}
	}
	if code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout {
		return "server overload", true
	}
	return "", false
}

func (c *Client) doOnce(ctx context.Context, method string, r Request) (*Response, error) {
	var body io.Reader
	if r.Body != nil {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		return nil, err
	}
	if !c.InScope(req.URL) {
		return nil, fmt.Errorf("%s: %w", r.URL, ErrOutOfScope)
	}
	c.setHeaders(req, r.Header)

	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer func() { <-c.sem }()
	if err := c.wait(ctx); err != nil {
		return nil, err
	}

	c.requests.Add(1)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limit := r.MaxBody
	if limit <= 0 || limit > MaxBodySize {
		limit = MaxBodySize
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	} else if err != nil {
		return nil, fmt.Errorf("reading %s: %w", r.URL, err)
	}
	blocked, site := blockedBy(resp.StatusCode, resp.Header, data)
	return &Response{
		URL:         req.URL,
		StatusCode:  resp.StatusCode,
		Header:      resp.Header,
		Body:        data,
		Truncated:   truncated,
		Blocked:     blocked,
		SiteBlocked: site,
	}, nil
}

func (c *Client) setHeaders(req *http.Request, extra http.Header) {
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	for name, values := range c.headers {
		if strings.EqualFold(name, "Host") {
			if len(values) > 0 {
				req.Host = values[len(values)-1]
			}
			continue
		}
		// Go decompresses gzip only when it asked for it itself; a copied
		// browser header would leave compressed bodies no check can read.
		if strings.EqualFold(name, "Accept-Encoding") {
			continue
		}
		req.Header.Del(name)
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	if c.cookie != "" {
		if existing := req.Header.Get("Cookie"); existing != "" {
			req.Header.Set("Cookie", existing+"; "+c.cookie)
		} else {
			req.Header.Set("Cookie", c.cookie)
		}
	}
	if c.auth != nil {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}
	for name, values := range extra {
		req.Header.Del(name)
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
}

func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// wait enforces the --throttle delay between the starts of two requests.
func (c *Client) wait(ctx context.Context) error {
	if c.throttle <= 0 {
		return nil
	}
	c.throttleMu.Lock()
	now := time.Now()
	slot := c.nextSlot
	if slot.Before(now) {
		slot = now
	}
	c.nextSlot = slot.Add(c.throttle)
	c.throttleMu.Unlock()

	d := time.Until(slot)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// countingConn counts the bytes read from and written to a connection.
type countingConn struct {
	net.Conn
	c *Client
}

func (cc *countingConn) Read(p []byte) (int, error) {
	n, err := cc.Conn.Read(p)
	cc.c.received.Add(int64(n))
	return n, err
}

func (cc *countingConn) Write(p []byte) (int, error) {
	n, err := cc.Conn.Write(p)
	cc.c.sent.Add(int64(n))
	return n, err
}
