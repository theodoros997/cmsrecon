package scan

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

func TestMaxScanDuration(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	// Every check that guesses a path waits on a slow server.
	f.fallback = func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		wpNotFound(w, r)
	}
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = fullEnumeration()
	o.MaxScanDuration = 700 * time.Millisecond
	start := time.Now()
	r := runScan(t, o)
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("the scan took %s despite a 700ms limit", elapsed)
	}
	if r.Status != StatusTimedOut {
		t.Fatalf("status = %q, want %q", r.Status, StatusTimedOut)
	}
	if !slices.ContainsFunc(r.Notices, func(n string) bool { return strings.Contains(n, "--max-scan-duration 700ms") }) {
		t.Errorf("notices = %q", r.Notices)
	}
	// What was found before the limit is kept.
	if r.WordPress == nil || !r.WordPress.Detected || r.Version == nil || r.Version.Number != "6.4.2" {
		t.Errorf("partial results lost: wordpress %+v, version %+v", r.WordPress, r.Version)
	}
	if len(r.Errors) != 0 {
		t.Errorf("requests cut short by the limit are not errors: %+v", r.Errors)
	}
}

// recorder keeps the steps a scan reports.
type recorder struct {
	mu      sync.Mutex
	started []string
	ended   map[string]string
}

func (r *recorder) Start(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, step)
}
func (r *recorder) Update(string, string) {}
func (r *recorder) Done(step, result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended[step] = result
}
func (r *recorder) Fail(step, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended[step] = "failed: " + reason
}

func TestScanReportsEveryStep(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = fullEnumeration()
	o.Enumerate.Timthumbs = true
	o.Enumerate.Media = &cli.IDRange{From: 1, To: 3}
	o.DataDir = writeData(t)
	c, err := httpclient.New(o)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{ended: map[string]string{}}
	s := New(o, c)
	s.Steps = rec
	s.Run(context.Background(), nil)

	for _, step := range rec.started {
		if _, ok := rec.ended[step]; !ok {
			t.Errorf("step %q started and never ended", step)
		}
	}
	for step, want := range map[string]string{
		stepPreflight: "WordPress at " + f.URL(), stepVersion: "5.8.1", stepMainTheme: "twentytwenty",
		stepPlugins: "found", stepUsers: "found", stepVulns: "confirmed", stepFindings: "found",
	} {
		if !strings.Contains(rec.ended[step], want) {
			t.Errorf("%s ended with %q, want it to mention %q", step, rec.ended[step], want)
		}
	}
	for _, step := range []string{stepData, stepPages, stepThemes, stepJS, stepMedia, stepFolders, stepTimthumbs} {
		if _, ok := rec.ended[step]; !ok {
			t.Errorf("step %q was not reported: %v", step, rec.started)
		}
	}

	t.Run("a stopped scan fails pre-flight", func(t *testing.T) {
		f := newFakeWP(t)
		f.routes["/"] = respond(200, "text/html", "<html><body>Not WordPress</body></html>")
		f.fallback = respond(404, "text/html", "<html><body>Not found</body></html>")
		o := options(f.URL(), cli.ModeMixed)
		c, _ := httpclient.New(o)
		rec := &recorder{ended: map[string]string{}}
		s := New(o, c)
		s.Steps = rec
		s.Run(context.Background(), nil)
		if !strings.HasPrefix(rec.ended[stepPreflight], "failed: The site does not look like WordPress") {
			t.Errorf("pre-flight = %q", rec.ended[stepPreflight])
		}
	})
}
