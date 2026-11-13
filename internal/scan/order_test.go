package scan

import (
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

// guess reports whether a request is one of the scan's guesses: a path
// that only exists when something was left behind.
func guess(req string) bool {
	for _, part := range []string{"wp-config.php", "wp-config.", ".sql", "debug.log", ".git/", ".env", "phpinfo", "error_log", "updraft", "backups", "emergency.php", "searchreplacedb"} {
		if strings.Contains(req, part) {
			return true
		}
	}
	return false
}

// TestQuietChecksRunBeforeTheGuesses: what the site shows (its version,
// its theme, the readmes of its plugins) is read before the first guess,
// so that a firewall which bans guesses cannot cost those results.
func TestQuietChecksRunBeforeTheGuesses(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = fullEnumeration()
	o.Threads = 1 // one request at a time: the order is the scan's own
	runScan(t, o)

	reqs := f.requested()
	first := slices.IndexFunc(reqs, guess)
	if first < 0 {
		t.Fatalf("no guess among the requests: %v", reqs)
	}
	for _, want := range []string{
		"GET /feed/", "GET /wp-content/plugins/contact-form-7/readme.txt", "GET /wp-content/plugins/wordpress-seo/readme.txt",
		"GET /wp-content/themes/twentytwenty/style.css", "GET /wp-json/wp/v2/users",
		"POST /xmlrpc.php", "GET /robots.txt",
	} {
		i := slices.IndexFunc(reqs, func(r string) bool { return strings.HasPrefix(r, want) })
		if i < 0 {
			t.Errorf("%s was never requested", want)
		} else if i > first {
			t.Errorf("%s came after the first guess (%s): request %d, guess %d", want, reqs[first], i, first)
		}
	}
}

// TestBlockedDuringTheGuessesKeepsTheResults is the scan of a site whose
// firewall bans the client at its first guess: the scan ends as blocked,
// but the version, the theme, the plugins with their versions and the
// users are complete, and their steps did not end as cut short.
func TestBlockedDuringTheGuessesKeepsTheResults(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	var banned atomic.Bool
	inner := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guess(r.Method + " " + r.URL.RequestURI()) {
			banned.Store(true)
		}
		if banned.Load() {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		inner.ServeHTTP(w, r)
	})
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = fullEnumeration()
	o.DataDir = writeData(t)
	rec := &recorder{ended: map[string]string{}}
	r := runScanWith(t, o, rec)

	if r.Status != StatusBlocked {
		t.Fatalf("status = %q, want blocked", r.Status)
	}
	if r.Version == nil || r.Version.Number != "5.8.1" {
		t.Errorf("version = %+v", r.Version)
	}
	if r.MainTheme == nil || r.MainTheme.Slug != "twentytwenty" || r.MainTheme.Version.Number != "1.8" {
		t.Errorf("main theme = %+v", r.MainTheme)
	}
	cf7 := pluginBySlug(r, "contact-form-7")
	if cf7 == nil || cf7.Version.Number != "5.3.1" || len(cf7.Vulnerabilities) != 1 {
		t.Errorf("contact-form-7 = %+v", cf7)
	}
	if len(r.Users) < 2 {
		t.Errorf("users = %+v", r.Users)
	}
	for _, step := range []string{stepVersion, stepMainTheme, stepPlugins, stepUsers} {
		if res := rec.ended[step]; res == "" || strings.Contains(res, "cut short") {
			t.Errorf("%s ended with %q: it finished before the ban", step, res)
		}
	}
	if res := rec.ended[stepFindings]; !strings.Contains(res, "cut short") {
		t.Errorf("the findings step ended with %q, want cut short", res)
	}
	if !slices.ContainsFunc(r.Notices, func(n string) bool { return strings.Contains(n, "The steps that finished before that are complete") }) {
		t.Errorf("notices = %q", r.Notices)
	}
	if r.Stats.Pauses != 2 || r.Stats.Slowdowns == 0 {
		t.Errorf("the scan should slow down and pause twice before giving up: %+v", r.Stats)
	}
}

// TestSlowsDownInsteadOfStopping: a site that rate-limits now and then is
// scanned to the end, more slowly, and the report says so.
func TestSlowsDownInsteadOfStopping(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	var n atomic.Int32
	inner := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := n.Add(1); c > 10 && c%7 == 0 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		inner.ServeHTTP(w, r)
	})
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = fullEnumeration()
	r := runScan(t, o)
	if r.Status != StatusCompleted {
		t.Fatalf("status = %q: %q", r.Status, r.Notices)
	}
	if r.Stats.Slowdowns == 0 || !slices.ContainsFunc(r.Notices, func(n string) bool { return strings.Contains(n, "The scan slowed down") }) {
		t.Errorf("stats = %+v, notices = %q", r.Stats, r.Notices)
	}
	if pluginBySlug(r, "contact-form-7") == nil || findingByID(r, idConfigBackup) == nil {
		t.Errorf("results are missing after the slowdown: plugins %d, findings %v", len(r.Plugins), findingIDs(r))
	}
}

// TestLikelyNamesByDefault: a default scan tries the likeliest backup
// names only; --aggressive tries them all.
func TestLikelyNamesByDefault(t *testing.T) {
	count := func(thorough bool) (configs, exports, folders, notFound int) {
		f := newFakeWP(t).addBaseSite()
		o := options(f.URL(), cli.ModeMixed)
		o.Enumerate = fullEnumeration()
		o.Thorough = thorough
		r := runScan(t, o)
		for _, req := range f.requested() {
			switch {
			case strings.Contains(req, "wp-config"):
				configs++
			case strings.Contains(req, ".sql") || strings.HasSuffix(req, ".zip") || strings.HasSuffix(req, ".tar.gz"):
				exports++
			case strings.Contains(req, "backup") || strings.Contains(req, "updraft") || strings.Contains(req, "snapshots"):
				folders++
			}
		}
		return configs, exports, folders, int(r.Stats.NotFound)
	}
	c, e, b, nf := count(false)
	if c != likelyConfigBackups || e > 30 || b > likelyBackupFolders+2 {
		t.Errorf("default scan: %d config backups, %d exports, %d backup folders", c, e, b)
	}
	C, E, B, NF := count(true)
	if C != len(configBackupNames) || E < 2*e || B <= b {
		t.Errorf("--aggressive: %d config backups, %d exports, %d backup folders", C, E, B)
	}
	if nf == 0 || NF <= nf {
		t.Errorf("not found answers: %d by default, %d with --aggressive", nf, NF)
	}
}

func TestCountSummary(t *testing.T) {
	for _, tc := range []struct {
		n           int
		found, want string
	}{
		{1, "pages read for plugins and themes", "1 page read for plugins and themes"},
		{2, "pages read for plugins and themes", "2 pages read for plugins and themes"},
		{1, "other themes found", "1 other theme found"},
		{1, "files found", "1 file found"},
		{1, "warnings", "1 warning"},
		{1, "found", "1 found"},
		{0, "found", "none"},
	} {
		if got := countSummary(tc.n, tc.found, "none"); got != tc.want {
			t.Errorf("countSummary(%d, %q) = %q, want %q", tc.n, tc.found, got, tc.want)
		}
	}
}
