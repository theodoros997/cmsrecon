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
	"strings"
	"sync"
	"sync/atomic"
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
}

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

	dialer := &net.Dialer{Timeout: o.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
	}
}

// Get fetches rawURL with the default body limit.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.Do(ctx, Request{URL: rawURL})
}

// Do sends r and reads the response body up to r.MaxBody bytes. Redirects
// are returned as they are, never followed.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
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
	return &Response{
		URL:        req.URL,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       data,
		Truncated:  truncated,
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
