package scan

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

// aggressiveIDs are the findings that need a request to a specific path.
var aggressiveIDs = []string{
	idRobots, idReadme, idDebugLog, idFullPath, idBackupDB, idDuplicatorLog, idMultisite,
	idRegistration, idUploadListing, idTmmDBMigrate, idUploadSQLDump, idEmergencyScript,
	idWPCron, idPHPDisabled, idFantastico, idSearchReplaceDB,
}

func TestMixedScanFindsEverything(t *testing.T) {
	f := newFakeWP(t).addBaseSite().addExposures()
	r := runScan(t, options(f.URL(), cli.ModeMixed))

	if r.Status != StatusCompleted {
		t.Fatalf("status = %s, stop = %+v", r.Status, r.Stop)
	}
	want := []string{
		idHeaders, idRobots, idXMLRPC, idReadme, idDebugLog, idFullPath, idBackupDB, idDuplicatorLog,
		idMuPlugins, idRegistration, idUploadListing, idTmmDBMigrate, idUploadSQLDump, idEmergencyScript,
		idWPCron, idPHPDisabled, idFantastico, idSearchReplaceDB,
	}
	if got := findingIDs(r); !slices.Equal(got, want) {
		t.Errorf("findings =\n%v\nwant\n%v", got, want)
	}
	if len(r.Errors) > 0 {
		t.Errorf("unexpected request errors: %+v", r.Errors)
	}

	x := findingByID(r, idXMLRPC)
	if x.Data["pingback_ping"] != true || x.Data["system_multicall"] != true || x.Data["methods"] != 4 {
		t.Errorf("xmlrpc data = %v", x.Data)
	}
	if x.Title != "XML-RPC is enabled" || x.Severity != SeverityLow {
		t.Errorf("xmlrpc = %q / %s", x.Title, x.Severity)
	}
	if fpd := findingByID(r, idFullPath); fpd.Data["path"] != "/var/www/html/wp-includes/template-loader.php" {
		t.Errorf("full path = %v", fpd.Data["path"])
	}
	robots := findingByID(r, idRobots)
	if !slices.Contains(robots.Entries, "Disallow: /secret-backup/") || slices.Contains(robots.Entries, "Disallow: /wp-admin/") {
		t.Errorf("robots entries = %v", robots.Entries)
	}
	if listing := findingByID(r, idUploadListing); !slices.Equal(listing.Entries, []string{"2026/", "dump.sql"}) {
		t.Errorf("uploads listing = %v", listing.Entries)
	}
	if h := findingByID(r, idHeaders); !slices.Contains(h.Entries, "X-Powered-By: PHP/8.2.12") {
		t.Errorf("headers = %v", h.Entries)
	}

	if r.Version == nil || r.Version.Number != "6.4.2" || r.Version.Confidence < 95 {
		t.Errorf("version = %+v", r.Version)
	}
	if r.WebServer.Family != "apache" {
		t.Errorf("web server = %+v", r.WebServer)
	}

	th := r.MainTheme
	if th == nil || th.Slug != "lab-child" || th.Name != "Lab Child" || th.Version.Number != "1.0.3" {
		t.Fatalf("main theme = %+v", th)
	}
	if th.Parent == nil || th.Parent.Slug != "twentytwentyone" || th.Parent.Version.Number != "2.0" || th.Parent.Author != "the WordPress team" {
		t.Errorf("parent theme = %+v", th.Parent)
	}
	if r.Stats.Requests == 0 || r.Stats.BytesReceived == 0 {
		t.Errorf("stats = %+v", r.Stats)
	}
}

func TestPassiveModeOnlyFetchesPagesItWouldReadAnyway(t *testing.T) {
	f := newFakeWP(t).addBaseSite().addExposures()
	r := runScan(t, options(f.URL(), cli.ModePassive))

	// The REST API index is read because the homepage links to it.
	allowed := map[string]bool{"GET /": true, "GET /feed/": true, "GET /comments/feed/": true, "GET /wp-json/": true}
	for _, req := range f.requested() {
		// The 404 page is a random directory under the base URL.
		if allowed[req] || (strings.HasPrefix(req, "GET /") && strings.Count(req, "/") == 2 && strings.HasSuffix(req, "/") && len(req) == len("GET /0123456789abcdef/")) {
			continue
		}
		t.Errorf("passive mode requested %s", req)
	}
	if got, want := findingIDs(r), []string{idHeaders, idXMLRPC, idMuPlugins}; !slices.Equal(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	for _, f := range r.InterestingFindings {
		for _, e := range f.Evidence {
			if e.Mode != modePassive {
				t.Errorf("%s has %s evidence in passive mode", f.ID, e.Mode)
			}
		}
	}
	if r.Version.Number != "6.4.2" {
		t.Errorf("version = %+v", r.Version)
	}
	// Without the style.css request, the version comes from ?ver= on the
	// theme's stylesheet link.
	if r.MainTheme == nil || r.MainTheme.Slug != "lab-child" || r.MainTheme.Version.Number != "1.0.3" ||
		r.MainTheme.Version.Confidence != confThemeStyleVer || r.MainTheme.Name != "" {
		t.Errorf("main theme = %+v, version %+v", r.MainTheme, r.MainTheme.Version)
	}
}

func TestThemeStyleVerIgnoresTheCoreVersion(t *testing.T) {
	// A theme that enqueues style.css without a version gets WordPress's own.
	f := newFakeWP(t).addBaseSite()
	f.fallback = http.NotFound
	f.routes["/"] = respond(200, "text/html", `<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="{{URL}}wp-content/themes/plain/style.css?ver=6.4.2" />`)
	r := runScan(t, options(f.URL(), cli.ModePassive))
	if r.MainTheme == nil || r.MainTheme.Slug != "plain" || r.MainTheme.Version.Number != "" {
		t.Errorf("main theme = %+v, version %+v", r.MainTheme, r.MainTheme.Version)
	}
}

func TestAggressiveModeSkipsPassiveChecks(t *testing.T) {
	f := newFakeWP(t).addBaseSite().addExposures()
	r := runScan(t, options(f.URL(), cli.ModeAggressive))

	ids := findingIDs(r)
	if slices.Contains(ids, idHeaders) {
		t.Error("the headers finding is passive and must not run in aggressive mode")
	}
	for _, id := range aggressiveIDs {
		if id != idMultisite && !slices.Contains(ids, id) {
			t.Errorf("missing aggressive finding %s", id)
		}
	}
	for _, f := range r.InterestingFindings {
		for _, e := range f.Evidence {
			if e.Mode != modeAggressive {
				t.Errorf("%s has %s evidence in aggressive mode", f.ID, e.Mode)
			}
		}
	}
	if r.MainTheme != nil {
		t.Errorf("main theme detection is passive, got %+v", r.MainTheme)
	}
	for _, e := range r.Version.Evidence {
		if e.Mode != modeAggressive {
			t.Errorf("version evidence %+v in aggressive mode", e)
		}
	}
	if r.Version.Number != "6.4.2" {
		t.Errorf("version = %+v", r.Version)
	}
}

func TestCatchAllSiteHasNoAggressiveFalsePositives(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		// Every unknown path gets the homepage (fresh nonce each time).
		"homepage for everything": homepage,
		// Every unknown path gets the same 403 page.
		"403 for everything": respond(403, "text/html", "<html><body><h1>Request blocked</h1><p>Reference #1234567</p></body></html>"),
		// Every unknown path gets a 200 "not found" page that echoes the path.
		"soft 404 page": func(w http.ResponseWriter, r *http.Request) {
			respond(200, "text/html", "<html><body><h1>Oops</h1><p>Nothing at "+r.URL.Path+" (WordPress lab)</p></body></html>")(w, r)
		},
	}
	for name, fallback := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFakeWP(t)
			f.routes["/"] = homepage
			f.routes["/xmlrpc.php"] = xmlrpc
			f.fallback = fallback
			o := options(f.URL(), cli.ModeMixed)
			o.Force = true
			r := runScan(t, o)
			if r.Status != StatusCompleted {
				t.Fatalf("status = %s, stop = %+v", r.Status, r.Stop)
			}
			for _, id := range findingIDs(r) {
				if slices.Contains(aggressiveIDs, id) {
					t.Errorf("false positive: %s %+v", id, findingByID(r, id))
				}
			}
			if mu := findingByID(r, idMuPlugins); mu != nil {
				for _, e := range mu.Evidence {
					if e.Mode == modeAggressive {
						t.Errorf("mu-plugins folder reported from a catch-all answer: %+v", e)
					}
				}
			}
		})
	}
}

func TestMultisite(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"signup form":           respond(200, "text/html", `<div id="signup-content"><form id="setupform" method="post" action="wp-signup.php">`),
		"redirect to main site": redirect(302, "http://main.example/wp-signup.php"),
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFakeWP(t).addBaseSite()
			f.routes["/wp-signup.php"] = h
			r := runScan(t, options(f.URL(), cli.ModeAggressive))
			if findingByID(r, idMultisite) == nil {
				t.Errorf("multisite not detected: %v", findingIDs(r))
			}
		})
	}
	f := newFakeWP(t).addBaseSite()
	if r := runScan(t, options(f.URL(), cli.ModeAggressive)); findingByID(r, idMultisite) != nil {
		t.Error("a single site (wp-signup.php -> wp-login.php?action=register) was reported as multisite")
	}
}

func TestRedirects(t *testing.T) {
	t.Run("http to https on the same host is followed", func(t *testing.T) {
		tlsSite := newFakeWP(t).addBaseSite()
		tls := httptest.NewUnstartedServer(tlsSite)
		tls.Config.ErrorLog = log.New(io.Discard, "", 0)
		tls.StartTLS()
		defer tls.Close()
		plain := newFakeWP(t)
		plain.fallback = redirect(301, tls.URL+"/")

		o := options(plain.URL(), cli.ModeMixed)
		o.Insecure = true
		r := runScan(t, o)
		if r.Status != StatusCompleted || r.Target.EffectiveURL != tls.URL+"/" {
			t.Fatalf("status = %s, effective URL = %s, stop = %+v", r.Status, r.Target.EffectiveURL, r.Stop)
		}
		if len(r.Target.Redirects) != 1 || !r.Target.Redirects[0].Followed || r.Target.Redirects[0].Reason != RedirectInScope {
			t.Errorf("redirects = %+v", r.Target.Redirects)
		}
	})

	t.Run("another path on the target host is in scope", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		f.routes["/"] = redirect(302, "{{URL}}blog/")
		f.routes["/blog/"] = homepage
		r := runScan(t, options(f.URL(), cli.ModePassive))
		if r.Status != StatusCompleted || !strings.HasSuffix(r.Target.EffectiveURL, "/blog/") {
			t.Fatalf("status = %s, effective URL = %s, stop = %+v", r.Status, r.Target.EffectiveURL, r.Stop)
		}
		if r.Target.Redirects[0].Reason != RedirectInScope {
			t.Errorf("redirects = %+v", r.Target.Redirects)
		}
	})

	// Off-host redirects go from 127.0.0.1 to localhost: another host name
	// for the same machine.
	offHost := func(t *testing.T) (target string, other *fakeWP) {
		other = newFakeWP(t).addBaseSite()
		f := newFakeWP(t)
		f.fallback = redirect(301, strings.Replace(other.URL(), "127.0.0.1", "localhost", 1))
		return f.URL(), other
	}

	t.Run("an out-of-scope redirect stops", func(t *testing.T) {
		target, other := offHost(t)
		r := runScan(t, options(target, cli.ModeMixed))
		if r.Status != StatusStopped || r.Stop.Code != StopRedirect {
			t.Fatalf("status = %s, stop = %+v", r.Status, r.Stop)
		}
		for _, want := range []string{"--follow-redirect", "--scope localhost"} {
			if !strings.Contains(r.Stop.Hint, want) {
				t.Errorf("hint %q does not mention %s", r.Stop.Hint, want)
			}
		}
		if red := r.Target.Redirects; len(red) != 1 || red[0].Followed || red[0].Reason != RedirectOutOfScope {
			t.Errorf("redirects = %+v", red)
		}
		if n := len(other.requested()); n != 0 {
			t.Errorf("the out-of-scope host got %d requests", n)
		}
	})

	t.Run("a redirect to a --scope host is followed", func(t *testing.T) {
		target, _ := offHost(t)
		o := options(target, cli.ModePassive)
		o.Scope = []string{"localhost"}
		r := runScan(t, o)
		if r.Status != StatusCompleted || !strings.Contains(r.Target.EffectiveURL, "//localhost:") {
			t.Fatalf("status = %s, effective URL = %s, stop = %+v", r.Status, r.Target.EffectiveURL, r.Stop)
		}
		if red := r.Target.Redirects; len(red) != 1 || red[0].Reason != RedirectInScope {
			t.Errorf("redirects = %+v", red)
		}
	})

	t.Run("an out-of-scope redirect is followed with --follow-redirect", func(t *testing.T) {
		target, _ := offHost(t)
		o := options(target, cli.ModePassive)
		o.FollowRedirect = true
		r := runScan(t, o)
		if r.Status != StatusCompleted || !strings.Contains(r.Target.EffectiveURL, "//localhost:") {
			t.Fatalf("status = %s, effective URL = %s, stop = %+v", r.Status, r.Target.EffectiveURL, r.Stop)
		}
		if red := r.Target.Redirects; len(red) != 1 || red[0].Reason != RedirectFollowFlag {
			t.Errorf("redirects = %+v", red)
		}
		if !slices.Contains(r.Target.Scope, "localhost") {
			t.Errorf("the followed host should join the scope: %v", r.Target.Scope)
		}
	})

	t.Run("redirect loop stops", func(t *testing.T) {
		f := newFakeWP(t)
		f.routes["/"] = redirect(302, "{{URL}}a/")
		f.routes["/a/"] = redirect(302, "{{URL}}")
		o := options(f.URL(), cli.ModeMixed)
		o.FollowRedirect = true
		r := runScan(t, o)
		if r.Status != StatusStopped || r.Stop.Code != StopRedirect {
			t.Fatalf("status = %s, stop = %+v", r.Status, r.Stop)
		}
	})

	for _, installer := range []string{"wp-admin/install.php", "wp-admin/setup-config.php"} {
		t.Run("unfinished install via "+installer, func(t *testing.T) {
			f := newFakeWP(t)
			f.routes["/"] = redirect(302, "{{URL}}"+installer)
			r := runScan(t, options(f.URL(), cli.ModeMixed))
			if r.Status != StatusStopped || r.Stop.Code != StopUnfinishedInstall {
				t.Fatalf("status = %s, stop = %+v", r.Status, r.Stop)
			}
			fi := findingByID(r, idUnfinishedInstall)
			if fi == nil || fi.Severity != SeverityCritical || !strings.HasSuffix(fi.URL, installer) {
				t.Errorf("finding = %+v", fi)
			}
		})
	}
}

func TestPreflightStops(t *testing.T) {
	notWP := respond(200, "text/html", "<html><body>Just a static site</body></html>")
	tests := []struct {
		name     string
		home     http.HandlerFunc
		force    bool
		wantCode string // empty: the scan completes
	}{
		{"401", respond(401, "text/html", "auth", "WWW-Authenticate", `Basic realm="lab"`), false, StopHTTPAuthRequired},
		{"407", respond(407, "text/html", "proxy auth"), false, StopProxyAuthRequired},
		{"403", respond(403, "text/html", "forbidden"), false, StopForbidden},
		{"403 with --force", respond(403, "text/html", `<meta name="generator" content="WordPress 6.4.2" />`), true, ""},
		{"not WordPress", notWP, false, StopNotWordPress},
		{"not WordPress with --force", notWP, true, ""},
		{"WordPress.com", respond(200, "text/html", `<meta name="generator" content="WordPress.com" /><link rel="stylesheet" href="https://s0.wp.com/wp-content/themes/h4/global.css">`), true, StopWordPressCom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeWP(t)
			f.routes["/"] = tt.home
			f.fallback = http.NotFound
			o := options(f.URL(), cli.ModePassive)
			o.Force = tt.force
			r := runScan(t, o)
			switch {
			case tt.wantCode == "" && r.Status != StatusCompleted:
				t.Errorf("status = %s, stop = %+v; want completed", r.Status, r.Stop)
			case tt.wantCode != "" && (r.Stop == nil || r.Stop.Code != tt.wantCode):
				t.Errorf("stop = %+v, want %s", r.Stop, tt.wantCode)
			}
		})
	}

	t.Run("connection failure", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		u := srv.URL + "/"
		srv.Close()
		r := runScan(t, options(u, cli.ModeMixed))
		if r.Stop == nil || r.Stop.Code != StopConnectionFailed {
			t.Errorf("stop = %+v", r.Stop)
		}
	})

	t.Run("WordPress found by the login page in mixed mode", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		f.routes["/"] = notWP
		r := runScan(t, options(f.URL(), cli.ModeMixed))
		if r.Status != StatusCompleted || !r.WordPress.Detected {
			t.Errorf("status = %s, wordpress = %+v", r.Status, r.WordPress)
		}
	})
}

func TestChildThemeFromTheHomepageAlone(t *testing.T) {
	parentLink := `<link rel='stylesheet' href='{{URL}}wp-content/themes/twentytwentyone/style.css?ver=2.0' />`
	childLink := `<link rel='stylesheet' href='{{URL}}wp-content/themes/lab-child/style.css?ver=1.0.3' />`
	assets := `<script src="{{URL}}wp-content/themes/twentytwentyone/a.js"></script><script src="{{URL}}wp-content/themes/twentytwentyone/b.js"></script>`
	tests := map[string]string{
		"child linked last (passive signal)":           parentLink + childLink,
		"parent linked last (Template header decides)": childLink + parentLink,
	}
	for name, links := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFakeWP(t).addBaseSite()
			f.fallback = http.NotFound
			f.routes["/"] = respond(200, "text/html", `<meta name="generator" content="WordPress 6.4.2" />`+links+assets)
			r := runScan(t, options(f.URL(), cli.ModeMixed))
			th := r.MainTheme
			if th == nil || th.Slug != "lab-child" || th.Parent == nil || th.Parent.Slug != "twentytwentyone" {
				t.Fatalf("main theme = %+v", th)
			}
			if th.Version.Number != "1.0.3" || th.Parent.Version.Number != "2.0" {
				t.Errorf("versions = %+v / %+v", th.Version, th.Parent.Version)
			}
		})
	}
}

func TestFullPathDisclosureTriesSeveralFiles(t *testing.T) {
	leak := func(file string) http.HandlerFunc {
		return respond(500, "text/html", "<b>Fatal error</b>:  Uncaught Error: Call to undefined function add_action() in /srv/www/"+file+":12")
	}
	t.Run("stops at the first leak", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		f.routes["/wp-includes/rss.php"] = leak("wp-includes/rss.php")
		f.routes["/wp-includes/template-loader.php"] = leak("wp-includes/template-loader.php")
		r := runScan(t, options(f.URL(), cli.ModeAggressive))
		if fpd := findingByID(r, idFullPath); fpd == nil || fpd.Data["path"] != "/srv/www/wp-includes/rss.php" {
			t.Fatalf("finding = %+v", fpd)
		}
		if slices.Contains(f.requested(), "GET /wp-includes/template-loader.php") {
			t.Error("the check should stop at the first leak")
		}
	})
	t.Run("Hello Dolly is the last resort", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		f.routes["/wp-content/plugins/hello.php"] = leak("wp-content/plugins/hello.php")
		r := runScan(t, options(f.URL(), cli.ModeAggressive))
		if fpd := findingByID(r, idFullPath); fpd == nil || fpd.Data["path"] != "/srv/www/wp-content/plugins/hello.php" {
			t.Fatalf("finding = %+v", fpd)
		}
	})
	t.Run("display_errors off", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		for _, p := range fullPathFiles {
			f.routes["/"+p] = respond(500, "text/html", "")
		}
		if r := runScan(t, options(f.URL(), cli.ModeAggressive)); findingByID(r, idFullPath) != nil {
			t.Error("no path was disclosed")
		}
	})
}

func TestTmmDBMigrateReportsWhatWasSeen(t *testing.T) {
	tests := []struct {
		name, body   string
		wantSeverity string
		wantEntries  []string
	}{
		{"archive with content", "PK\x03\x04" + strings.Repeat("x", 1000), SeverityHigh,
			[]string{"Size: 1004 bytes", "Content-Type: application/zip"}},
		// An empty zip is just the 22-byte end-of-central-directory record.
		{"empty archive", "PK\x05\x06" + strings.Repeat("\x00", 18), SeverityLow,
			[]string{"Size: 22 bytes", "Content-Type: application/zip", "The archive is empty; the plugin may have exported here before"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeWP(t).addBaseSite()
			f.routes["/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip"] = respond(200, "application/zip", tt.body)
			r := runScan(t, options(f.URL(), cli.ModeAggressive))
			fi := findingByID(r, idTmmDBMigrate)
			if fi == nil || fi.Severity != tt.wantSeverity {
				t.Fatalf("finding = %+v", fi)
			}
			for _, want := range tt.wantEntries {
				if !slices.Contains(fi.Entries, want) {
					t.Errorf("entries %q lack %q", fi.Entries, want)
				}
			}
			if strings.Contains(fi.Title, "database export exposed") {
				t.Errorf("title %q claims more than was observed", fi.Title)
			}
		})
	}
}
