package scan

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// probeHit is a brute-forced path that exists.
type probeHit struct {
	url     string
	status  int
	listing []string // directory listing entries, when the server lists the directory
	listed  bool
}

// confidence is how sure a hit is that the path exists: a listing proves
// it, a 200 is good, a 403 or 401 (common for directories without an
// index) a little less, a 500 (a theme's index.php failing outside
// WordPress) less still.
func (h probeHit) confidence() int {
	switch {
	case h.listed:
		return 100
	case h.status == http.StatusOK:
		return 80
	case h.status == http.StatusForbidden || h.status == http.StatusUnauthorized:
		return 70
	default:
		return 60
	}
}

// probe requests each URL and returns the ones that exist, in input
// order. label names the run for progress reports.
func (s *Scanner) probe(ctx context.Context, label string, urls []string) []probeHit {
	if len(urls) == 0 {
		return nil
	}
	hits := make([]*probeHit, len(urls))
	jobs := make(chan int)
	var done atomic.Int64
	var wg sync.WaitGroup
	workers := min(max(s.opts.Threads, 1), len(urls))
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				if h, ok := s.probeOne(ctx, urls[i]); ok {
					hits[i] = &h
				}
				s.progress(label, int(done.Add(1)), len(urls))
			}
		})
	}
feed:
	for i := range urls {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	var out []probeHit
	for _, h := range hits {
		if h != nil {
			out = append(out, *h)
		}
	}
	return out
}

func (s *Scanner) progress(label string, done, total int) {
	if s.Progress != nil {
		s.Progress(label, done, total)
	}
}

// probeOne decides whether u exists. It sends a HEAD request, which has no
// body to download. A 404 or 410 answers the question; so does a status
// that differs from the answer to a random path in the same directory.
// When the status is the same as the random path's (a catch-all site, a
// "403 for everything" WAF), only the bodies can tell, so it falls back
// to a GET and the soft-404 comparison. Servers that refuse HEAD get GETs
// for the rest of the scan.
func (s *Scanner) probeOne(ctx context.Context, u string) (probeHit, bool) {
	ref, err := url.Parse(u)
	if err != nil {
		return probeHit{}, false
	}
	b := s.baselineFor(ctx, ref)
	if s.headRefused.Load() {
		return s.probeGet(ctx, u, ref)
	}
	res := s.do(ctx, httpclient.Request{Method: http.MethodHead, URL: u})
	if res == nil {
		return probeHit{}, false
	}
	switch {
	case res.StatusCode == http.StatusMethodNotAllowed || res.StatusCode == http.StatusNotImplemented:
		s.headRefused.Store(true)
		return s.probeGet(ctx, u, ref)
	case res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone:
		return probeHit{}, false
	case b != nil && res.StatusCode == b.resp.StatusCode:
		return s.probeGet(ctx, u, ref)
	case res.IsRedirect():
		// A directory may redirect to itself (adding a slash, switching
		// scheme); a redirect anywhere else, such as a login page, says
		// nothing about the path.
		loc, err := res.Location()
		if err != nil || !strings.HasPrefix(loc.Path, strings.TrimSuffix(ref.Path, "/")) {
			return probeHit{}, false
		}
	}
	return probeHit{url: u, status: res.StatusCode}, true
}

func (s *Scanner) probeGet(ctx context.Context, u string, ref *url.URL) (probeHit, bool) {
	res := s.do(ctx, httpclient.Request{URL: u})
	if res == nil || res.IsRedirect() || s.isNotFound(ctx, ref, res) {
		return probeHit{}, false
	}
	h := probeHit{url: u, status: res.StatusCode}
	h.listing, h.listed = s.dirListing(res)
	return h, true
}
