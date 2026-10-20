package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

func options(t *testing.T, target string) *cli.ScanOptions {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return &cli.ScanOptions{Target: u, Threads: 5, Timeout: 5 * time.Second, Headers: http.Header{}}
}

func newClient(t *testing.T, o *cli.ScanOptions) *Client {
	t.Helper()
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRequestHeaders(t *testing.T) {
	var got http.Header
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, host = r.Header.Clone(), r.Host
	}))
	defer srv.Close()

	o := options(t, srv.URL)
	o.Headers.Set("X-Test", "1")
	o.Headers.Set("Cookie", "a=1")
	o.Headers.Set("Host", "vhost.example")
	o.Cookie = "b=2"
	o.HTTPAuth = &cli.Credentials{Username: "user", Password: "pa:ss"}
	c := newClient(t, o)
	if _, err := c.Get(context.Background(), srv.URL+"/x"); err != nil {
		t.Fatal(err)
	}

	if ua := got.Get("User-Agent"); !strings.HasPrefix(ua, "cmsrecon/") {
		t.Errorf("User-Agent = %q, want the cmsrecon default", ua)
	}
	if got.Get("X-Test") != "1" {
		t.Errorf("extra header missing: %v", got)
	}
	if got.Get("Cookie") != "a=1; b=2" {
		t.Errorf("Cookie = %q", got.Get("Cookie"))
	}
	if host != "vhost.example" {
		t.Errorf("Host = %q", host)
	}
	req := &http.Request{Header: got}
	if user, pass, ok := req.BasicAuth(); !ok || user != "user" || pass != "pa:ss" {
		t.Errorf("basic auth = %q %q %v", user, pass, ok)
	}
}

func TestUserAgentChoice(t *testing.T) {
	o := options(t, "http://example.com/")
	o.RandomUserAgent = true
	if ua := newClient(t, o).UserAgent(); !slices.Contains(browserUserAgents, ua) {
		t.Errorf("random UA %q is not from the browser list", ua)
	}
	o.UserAgent = "custom/1"
	if ua := newClient(t, o).UserAgent(); ua != "custom/1" {
		t.Errorf("explicit UA should win, got %q", ua)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		t.Errorf("redirect was followed to %s", r.URL)
	}))
	defer srv.Close()

	res, err := newClient(t, options(t, srv.URL)).Get(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsRedirect() {
		t.Fatalf("status = %d, want a redirect", res.StatusCode)
	}
	loc, err := res.Location()
	if err != nil || loc.String() != srv.URL+"/elsewhere" {
		t.Errorf("Location = %v, %v", loc, err)
	}
}

func TestBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 100)))
	}))
	defer srv.Close()
	c := newClient(t, options(t, srv.URL))

	res, err := c.Do(context.Background(), Request{URL: srv.URL, MaxBody: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Body) != 10 || !res.Truncated {
		t.Errorf("got %d bytes, truncated=%v; want 10, true", len(res.Body), res.Truncated)
	}
	res, err = c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Body) != 100 || res.Truncated {
		t.Errorf("got %d bytes, truncated=%v; want 100, false", len(res.Body), res.Truncated)
	}
}

func TestScope(t *testing.T) {
	o := options(t, "http://Example.com:8080/")
	o.Scope = []string{"cdn.example.net", "*.static.example.org"}
	c := newClient(t, o)
	tests := map[string]bool{
		"http://example.com/":             true,
		"https://example.com:8443/x":      true, // other port and scheme on the target host
		"http://www.example.com/":         false,
		"http://cdn.example.net/a.js":     true,
		"http://a.static.example.org/":    true,
		"http://static.example.org/":      false, // the wildcard only covers subdomains
		"http://evil-static.example.org/": false,
		"ftp://example.com/":              false,
	}
	for raw, want := range tests {
		u, _ := url.Parse(raw)
		if got := c.InScope(u); got != want {
			t.Errorf("InScope(%s) = %v, want %v", raw, got, want)
		}
	}
	_, err := c.Get(context.Background(), "http://outside.example/")
	if !errors.Is(err, ErrOutOfScope) {
		t.Errorf("out-of-scope request error = %v", err)
	}
	if c.Stats().Requests != 0 {
		t.Error("an out-of-scope request must not be sent")
	}
}

func TestStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("b", 1000)))
	}))
	defer srv.Close()
	c := newClient(t, options(t, srv.URL))
	for range 3 {
		if _, err := c.Get(context.Background(), srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	s := c.Stats()
	if s.Requests != 3 || s.BytesSent < 3*50 || s.BytesReceived < 3000 {
		t.Errorf("stats = %+v", s)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var cur, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cur.Add(1)
		defer cur.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}))
	defer srv.Close()

	o := options(t, srv.URL)
	o.Threads = 2
	c := newClient(t, o)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := c.Get(context.Background(), srv.URL); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if p := peak.Load(); p > 2 {
		t.Errorf("%d concurrent requests, want at most 2", p)
	}
}

func TestThrottle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	o := options(t, srv.URL)
	o.Threads, o.Throttle = 1, 40*time.Millisecond
	c := newClient(t, o)
	start := time.Now()
	for range 3 {
		if _, err := c.Get(context.Background(), srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 80*time.Millisecond {
		t.Errorf("3 throttled requests took %s, want at least 80ms", d)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	o := options(t, srv.URL)
	o.Timeout = 50 * time.Millisecond
	if _, err := newClient(t, o).Get(context.Background(), srv.URL); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestInsecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	o := options(t, srv.URL)
	if _, err := newClient(t, o).Get(context.Background(), srv.URL); err == nil {
		t.Error("a self-signed certificate should be rejected without --insecure")
	}
	o.Insecure = true
	if _, err := newClient(t, o).Get(context.Background(), srv.URL); err != nil {
		t.Errorf("--insecure should accept a self-signed certificate: %v", err)
	}
}

func TestHTTPProxy(t *testing.T) {
	var proxied atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A forward proxy receives the absolute target URL.
		if r.URL.Host == "wp.example" && r.Header.Get("Proxy-Authorization") != "" {
			proxied.Store(true)
		}
		w.Write([]byte("via proxy"))
	}))
	defer proxy.Close()

	o := options(t, "http://wp.example/")
	o.Proxy, _ = url.Parse(strings.Replace(proxy.URL, "http://", "http://u:p@", 1))
	res, err := newClient(t, o).Get(context.Background(), "http://wp.example/")
	if err != nil {
		t.Fatal(err)
	}
	if !proxied.Load() || string(res.Body) != "via proxy" {
		t.Error("request did not go through the proxy with its credentials")
	}
}
