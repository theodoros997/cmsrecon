package scan

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/theodoros997/cmsrecon/internal/cli"
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
