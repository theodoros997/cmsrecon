package scan

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/fsutil"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// pluginHomepage loads two plugins' assets, prints Yoast's comment and
// links to the REST API, like the test lab's homepage.
const pluginHomepage = `<!DOCTYPE html><html><head>
<title>Lab</title>
<link rel="alternate" type="application/rss+xml" href="{{URL}}feed/" />
<meta name="generator" content="WordPress 5.8.1" />
<!-- This site is optimized with the Yoast SEO plugin v15.0 - https://yoast.com/wordpress/plugins/seo/ -->
<link rel='stylesheet' href='{{URL}}wp-includes/css/dist/block-library/style.min.css?ver=5.8.1' />
<link rel='stylesheet' href='{{URL}}wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1' />
<link rel='stylesheet' href='{{URL}}wp-content/themes/twentytwenty/style.css?ver=1.8' />
<script src='{{URL}}wp-includes/js/jquery/jquery.min.js?ver=3.6.0'></script>
<script src='{{URL}}wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2'></script>
<script src='{{URL}}wp-content/plugins/contact-form-7/includes/js/scripts.js?ver=5.3.1'></script>
<script src='{{URL}}wp-content/plugins/contact-form-7/includes/js/vendor/select2.min.js?ver=4.0.13'></script>
<script src='{{URL}}wp-content/themes/twentytwenty/assets/js/index.js?ver=1.8'></script>
<script src='{{URL}}wp-content/themes/twentytwenty/assets/js/bootstrap.min.js'></script>
<script src='https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.1/moment.min.js'></script>
</head><body class="home blog">
<article><a href="{{URL}}author/alice/">Alice Author</a></article>
</body></html>`

const pluginFeed = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>Lab</title><generator>https://wordpress.org/?v=5.8.1</generator>
<item><title>Post by alice</title><dc:creator><![CDATA[Alice Author]]></dc:creator></item>
<item><title>Post by bob</title><dc:creator><![CDATA[Bob Editor]]></dc:creator></item>
</channel></rss>`

func readme(name, stable string, changelog ...string) string {
	r := "=== " + name + " ===\nContributors: lab\nRequires at least: 5.0\nStable tag: " + stable + "\n\n== Description ==\nA plugin.\n\n== Changelog ==\n"
	for _, c := range changelog {
		r += "\n= " + c + " =\n* Fixes.\n"
	}
	return r + "\n== Upgrade Notice ==\n= 9.9.9 =\nNot a changelog entry.\n"
}

// addComponentSite is a WordPress 5.8.1 site with plugins, themes, users,
// exposed backups and JavaScript libraries.
func (f *fakeWP) addComponentSite() *fakeWP {
	f.routes["/"] = respond(200, "text/html; charset=UTF-8", pluginHomepage, "Link", `<{{URL}}wp-json/>; rel="https://api.w.org/"`)
	f.fallback = respond(404, "text/html", `<html><head><title>Page not found</title><link rel='stylesheet' href='{{URL}}wp-content/themes/twentytwenty/style.css?ver=1.8' /></head><body class="error404">Nothing here</body></html>`)
	f.routes["/feed/"] = respond(200, "application/rss+xml", pluginFeed)
	f.routes["/wp-json/"] = respond(200, "application/json", `{"name":"Lab","namespaces":["oembed/1.0","contact-form-7/v1","yoast/v1","wp/v2","wp-site-health/v1","redirection/v1","mystery-plugin/v2"],"routes":{}}`)

	// Plugins: Contact Form 7 and Yoast are active, Duplicator inactive
	// (only brute force finds it) and Akismet's readme is blocked.
	f.routes["/wp-content/plugins/contact-form-7/readme.txt"] = respond(200, "text/plain", readme("Contact Form 7", "5.3.1", "5.3.1", "5.3", "5.2.2"))
	f.routes["/wp-content/plugins/wordpress-seo/readme.txt"] = respond(200, "text/plain", readme("Yoast SEO", "15.0", "15.0", "14.9"))
	f.routes["/wp-content/plugins/duplicator/"] = respond(200, "text/html", "")
	f.routes["/wp-content/plugins/duplicator/readme.txt"] = respond(200, "text/plain", readme("Duplicator", "1.3.26", "1.3.26"))
	f.routes["/wp-content/plugins/akismet/"] = respond(403, "text/html", "<h1>Forbidden</h1>")
	f.routes["/wp-content/plugins/akismet/readme.txt"] = respond(403, "text/html", "<h1>Forbidden</h1>")

	// Themes: twentytwenty is active, twentynineteen installed.
	f.routes["/wp-content/themes/twentytwenty/style.css"] = respond(200, "text/css", "/*\nTheme Name: Twenty Twenty\nVersion: 1.8\nAuthor: the WordPress team\n*/\n")
	f.routes["/wp-content/themes/twentynineteen/"] = respond(500, "text/html", "")
	f.routes["/wp-content/themes/twentynineteen/style.css"] = respond(200, "text/css", "/*\nTheme Name: Twenty Nineteen\nVersion: 2.1\n*/\n")
	f.routes["/wp-content/themes/twentytwenty/assets/js/bootstrap.min.js"] = respond(200, "application/javascript", "/*!\n  * Bootstrap v4.1.3 (https://getbootstrap.com/)\n  */\n!function(){}();")

	// Users.
	f.routes["/wp-json/wp/v2/users"] = respond(200, "application/json",
		`[{"id":1,"name":"labadmin","slug":"labadmin"},{"id":2,"name":"Alice Author","slug":"alice"}]`, "X-WP-TotalPages", "1")
	f.routes["/?author=1"] = redirect(301, "{{URL}}author/labadmin/")
	f.routes["/?author=2"] = redirect(301, "{{URL}}author/alice/")
	f.routes["/?author=3"] = respond(200, "text/html", `<html><head><title>Bob Editor, Author at Lab</title></head><body class="archive author author-bob author-3">`)
	f.routes["/wp-sitemap-users-1.xml"] = respond(200, "application/xml",
		`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{{URL}}author/alice/</loc></url><url><loc>{{URL}}author/bob/</loc></url></urlset>`)

	// Exposed files.
	f.routes["/wp-config.php.bak"] = respond(200, "application/octet-stream",
		"<?php\ndefine( 'DB_NAME', 'wordpress' );\ndefine( 'DB_USER', 'wordpress' );\ndefine( 'DB_PASSWORD', 'lab-secret-pw' );\n$table_prefix = 'wp_';\n")
	f.routes["/backup.sql"] = respond(200, "application/sql", "-- MySQL dump 10.13\nCREATE TABLE `wp_users` (`ID` int);\n")
	f.routes["/wp-content/updraft/"] = respond(200, "text/html",
		`<html><head><title>Index of /wp-content/updraft</title></head><body><h1>Index of /wp-content/updraft</h1><a href="/wp-content/">Parent Directory</a><a href="backup_lab-db.gz">backup_lab-db.gz</a></body></html>`)
	f.routes["/wp-cron.php"] = respond(200, "text/html", "")
	return f
}

// writeData stores vulnerability data and WordPress.org lists for the
// component site in a temporary data directory.
func writeData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	r := func(to string, incl bool) []vulndb.Range { return []vulndb.Range{{To: to, ToInclusive: incl}} }
	wf := &vulndb.SourceFile{Source: vulndb.SourceWordfence, UpdatedAt: time.Now().UTC(), Vulnerabilities: []*vulndb.Vuln{
		{ID: "wf-cf7", Title: "Contact Form 7 <= 5.3.1 - Unrestricted File Upload", Kind: vulndb.KindPlugin, Slug: "contact-form-7",
			Affected: r("5.3.1", true), Fixed: []string{"5.3.2"}, CVE: []string{"CVE-2020-35489"}, CVSS: 10, Severity: "critical"},
		{ID: "wf-dup", Title: "Duplicator <= 1.3.26 - Arbitrary File Download", Kind: vulndb.KindPlugin, Slug: "duplicator",
			Affected: r("1.3.26", true), Fixed: []string{"1.3.28"}, CVE: []string{"CVE-2020-11738"}, CVSS: 7.5, Severity: "high"},
		{ID: "wf-dup-old", Title: "Duplicator < 1.2.42 - Unauthenticated Stored XSS", Kind: vulndb.KindPlugin, Slug: "duplicator",
			Affected: r("1.2.42", false), Fixed: []string{"1.2.42"}},
		{ID: "wf-akismet", Title: "Akismet <= 3.1.4 - Unauthenticated Stored XSS", Kind: vulndb.KindPlugin, Slug: "akismet",
			Affected: r("3.1.4", true), Fixed: []string{"3.1.5"}, Severity: "medium"},
		{ID: "wf-core", Title: "WordPress Core < 5.8.3 - SQL Injection via WP_Query", Kind: vulndb.KindCore, Slug: vulndb.CoreSlug,
			Affected: []vulndb.Range{{From: "5.8", FromInclusive: true, To: "5.8.2", ToInclusive: true}}, Fixed: []string{"5.8.3"}, CVE: []string{"CVE-2022-21661"}, Severity: "high"},
		{ID: "wf-theme", Title: "Twenty Twenty <= 1.8 - Fake XSS", Kind: vulndb.KindTheme, Slug: "twentytwenty",
			Affected: r("1.8", true), Unfixed: true, Severity: "low"},
	}}
	if err := vulndb.WriteSource(filepath.Join(dir, vulndb.WordfenceFile), wf); err != nil {
		t.Fatal(err)
	}
	w := &wordlists.WPOrg{UpdatedAt: time.Now().UTC(), CoreLatest: "6.6.2",
		Plugins: []wordlists.Item{{Slug: "akismet", Version: "5.3"}, {Slug: "contact-form-7", Version: "6.1"}, {Slug: "duplicator", Version: "1.5.7"}, {Slug: "not-installed"}},
		Themes:  []wordlists.Item{{Slug: "twentytwenty", Version: "2.7"}, {Slug: "twentynineteen", Version: "2.9"}, {Slug: "astra"}},
	}
	if err := wordlists.WriteWPOrg(filepath.Join(dir, wordlists.WPOrgFile), w); err != nil {
		t.Fatal(err)
	}
	retire := `{"jquery": {"extractors": {}, "vulnerabilities": [{"atOrAbove": "1.2", "below": "3.5.0", "severity": "medium", "identifiers": {"summary": "jQuery XSS", "CVE": ["CVE-2020-11022"]}}]},
	 "bootstrap": {"extractors": {}, "vulnerabilities": [{"below": "4.3.1", "severity": "medium", "identifiers": {"summary": "XSS in data-template", "CVE": ["CVE-2019-8331"]}}]}}`
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, vulndb.RetireFile), []byte(retire)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func pluginBySlug(r *Result, slug string) *Plugin {
	for _, p := range r.Plugins {
		if p.Slug == slug {
			return p
		}
	}
	return nil
}

func themeBySlug(themes []*Theme, slug string) *Theme {
	for _, t := range themes {
		if t.Slug == slug {
			return t
		}
	}
	return nil
}

func methods(ev []Evidence) []string {
	var out []string
	for _, e := range ev {
		out = append(out, e.Method)
	}
	return out
}

func fullEnumeration() cli.Enumeration {
	return cli.Enumeration{Plugins: cli.ItemsPopular, Themes: cli.ItemsPopular, ConfigBackups: true, DBExports: true,
		BackupFolders: true, Users: &cli.IDRange{From: 1, To: 5}}
}

func TestComponentsAndVulnerabilities(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = fullEnumeration()
	o.DataDir = writeData(t)
	r := runScan(t, o)
	if r.Status != StatusCompleted {
		t.Fatalf("status = %s, stop = %+v", r.Status, r.Stop)
	}
	if len(r.Errors) > 0 {
		t.Errorf("request errors: %+v", r.Errors)
	}

	// Core.
	if r.Version.Number != "5.8.1" || r.Version.Latest != "6.6.2" || !r.Version.Outdated {
		t.Errorf("version = %+v", r.Version)
	}
	if len(r.CoreVulnerabilities) != 1 || r.CoreVulnerabilities[0].Verdict != VerdictConfirmed || r.CoreVulnerabilities[0].FixedIn != "5.8.3" {
		t.Errorf("core vulnerabilities = %+v", r.CoreVulnerabilities)
	}

	// Plugins.
	var slugs []string
	for _, p := range r.Plugins {
		slugs = append(slugs, p.Slug)
	}
	if want := []string{"akismet", "contact-form-7", "duplicator", "redirection", "wordpress-seo"}; !slices.Equal(slugs, want) {
		t.Errorf("plugins = %v, want %v", slugs, want)
	}
	cf7 := pluginBySlug(r, "contact-form-7")
	if cf7.Version.Number != "5.3.1" || cf7.Version.Confidence < 95 || cf7.Name != "Contact Form 7" || !cf7.Version.Outdated || cf7.Version.Latest != "6.1" {
		t.Errorf("contact-form-7 = %+v, version %+v", cf7, cf7.Version)
	}
	for _, m := range []string{"URLs in the homepage", "REST API namespace", "readme.txt"} {
		if !slices.Contains(methods(cf7.Evidence), m) {
			t.Errorf("contact-form-7 evidence lacks %q: %v", m, methods(cf7.Evidence))
		}
	}
	for _, e := range cf7.Version.Evidence {
		if e.Value == "4.0.13" || e.Value == "9.9.9" {
			t.Errorf("a bundled library's ?ver= or the upgrade notice was taken for the version: %+v", e)
		}
	}
	if len(cf7.Vulnerabilities) != 1 || cf7.Vulnerabilities[0].Verdict != VerdictConfirmed || cf7.Vulnerabilities[0].FixedIn != "5.3.2" {
		t.Errorf("contact-form-7 vulnerabilities = %+v", cf7.Vulnerabilities)
	}
	yoast := pluginBySlug(r, "wordpress-seo")
	if yoast.Version.Number != "15.0" || !slices.Contains(methods(yoast.Evidence), "Yoast SEO HTML comment") {
		t.Errorf("wordpress-seo = %+v", yoast)
	}
	dup := pluginBySlug(r, "duplicator")
	if dup.Version.Number != "1.3.26" || !slices.Contains(methods(dup.Evidence), "Known location") {
		t.Errorf("duplicator = %+v", dup)
	}
	if len(dup.Vulnerabilities) != 1 || dup.Vulnerabilities[0].Title != "Duplicator <= 1.3.26 - Arbitrary File Download" {
		t.Errorf("duplicator vulnerabilities = %+v (the fixed older one must not match)", dup.Vulnerabilities)
	}
	ak := pluginBySlug(r, "akismet")
	if ak.Version.Number != "" || ak.Confidence != 70 || len(ak.Vulnerabilities) != 1 || ak.Vulnerabilities[0].Verdict != VerdictPossible {
		t.Errorf("akismet = %+v, vulnerabilities %+v", ak, ak.Vulnerabilities)
	}
	if red := pluginBySlug(r, "redirection"); red == nil || red.Confidence != confPluginRESTKnown {
		t.Errorf("redirection (REST namespace only) = %+v", red)
	}
	if pluginBySlug(r, "mystery-plugin") != nil {
		t.Error("an unknown namespace must not become a plugin")
	}

	// Themes.
	if r.MainTheme == nil || r.MainTheme.Slug != "twentytwenty" || r.MainTheme.Version.Number != "1.8" || !r.MainTheme.Version.Outdated {
		t.Fatalf("main theme = %+v", r.MainTheme)
	}
	if len(r.MainTheme.Vulnerabilities) != 1 || !r.MainTheme.Vulnerabilities[0].Unfixed {
		t.Errorf("main theme vulnerabilities = %+v", r.MainTheme.Vulnerabilities)
	}
	if len(r.Themes) != 1 || r.Themes[0].Slug != "twentynineteen" || r.Themes[0].Name != "Twenty Nineteen" || r.Themes[0].Version.Number != "2.1" {
		t.Errorf("other themes = %+v", r.Themes)
	}

	// Users: display names are merged into the accounts, never listed as usernames.
	var users []string
	for _, u := range r.Users {
		users = append(users, fmt.Sprintf("%d:%s:%s", u.ID, u.Username, u.DisplayName))
	}
	if want := []string{"1:labadmin:labadmin", "2:alice:Alice Author", "3:bob:Bob Editor"}; !slices.Equal(users, want) {
		t.Errorf("users = %v, want %v", users, want)
	}

	// Exposed files.
	cb := findingByID(r, idConfigBackup)
	if cb == nil || cb.Severity != SeverityCritical || !strings.HasSuffix(cb.URL, "/wp-config.php.bak") {
		t.Fatalf("config backup = %+v", cb)
	}
	if strings.Contains(fmt.Sprint(cb), "lab-secret-pw") {
		t.Error("the report must not contain the database password")
	}
	if dbe := findingByID(r, idDBExport); dbe == nil || !strings.HasSuffix(dbe.URL, "/backup.sql") || dbe.Severity != SeverityHigh {
		t.Errorf("db export = %+v", dbe)
	}
	if bf := findingByID(r, idBackupFolder); bf == nil || !slices.Equal(bf.Entries, []string{"backup_lab-db.gz"}) {
		t.Errorf("backup folder = %+v", bf)
	}

	// JavaScript libraries.
	libs := map[string]*JSLibrary{}
	for _, l := range r.JSLibraries {
		libs[l.Name] = l
	}
	if l := libs["jquery"]; l == nil || l.Version.Number != "3.6.0" || len(l.Vulnerabilities) != 0 {
		t.Errorf("jquery = %+v", l)
	}
	if l := libs["jquery-migrate"]; l == nil || l.Version.Number != "3.3.2" {
		t.Errorf("jquery-migrate = %+v", l)
	}
	if l := libs["moment.js"]; l == nil || l.Version.Number != "2.29.1" {
		t.Errorf("moment.js from a CDN URL = %+v", l)
	}
	if l := libs["bootstrap"]; l == nil || l.Version.Number != "4.1.3" || len(l.Vulnerabilities) != 1 || l.Vulnerabilities[0].Verdict != VerdictConfirmed {
		t.Errorf("bootstrap from its banner = %+v", l)
	}

	c := r.VulnerabilityCounts
	if c.Confirmed != 5 || c.Possible != 1 {
		t.Errorf("counts = %+v", c)
	}
	if r.VulnerabilityData == nil || len(r.VulnerabilityData.Sources) != 3 {
		t.Errorf("vulnerability data = %+v", r.VulnerabilityData)
	}
	for _, n := range r.Notices {
		if strings.Contains(n, "No vulnerability data") {
			t.Errorf("unexpected notice %q", n)
		}
	}
}

func TestVulnerablePluginList(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	o := options(f.URL(), cli.ModeAggressive)
	o.Enumerate = cli.Enumeration{Plugins: cli.ItemsVulnerable}
	o.DataDir = writeData(t)
	r := runScan(t, o)
	if pluginBySlug(r, "duplicator") == nil || pluginBySlug(r, "akismet") == nil {
		t.Errorf("plugins = %+v", r.Plugins)
	}
	// Only the vulnerable slugs are requested.
	for _, req := range f.requested() {
		if strings.Contains(req, "/plugins/not-installed/") {
			t.Errorf("-e vp requested a plugin with no known vulnerability: %s", req)
		}
	}
}

func TestPluginsWithoutData(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = cli.Enumeration{Plugins: cli.ItemsVulnerable}
	o.DataDir = t.TempDir()
	r := runScan(t, o)
	// The built-in popular list still finds the inactive plugin.
	if dup := pluginBySlug(r, "duplicator"); dup == nil || dup.Version.Number != "1.3.26" || len(dup.Vulnerabilities) != 0 {
		t.Errorf("duplicator = %+v", dup)
	}
	var notices string
	for _, n := range r.Notices {
		notices += n + "\n"
	}
	for _, want := range []string{"No vulnerability data", "popular plugins were checked instead"} {
		if !strings.Contains(notices, want) {
			t.Errorf("notices lack %q:\n%s", want, notices)
		}
	}
}

func TestBruteForceOnCatchAllSites(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"homepage for everything": homepage,
		"403 for everything":      respond(403, "text/html", "<html><body><h1>Request blocked</h1><p>Reference #1234567</p></body></html>"),
		"soft 404 page": func(w http.ResponseWriter, r *http.Request) {
			respond(200, "text/html", "<html><body><h1>Oops</h1><p>Nothing at "+r.URL.Path+" (WordPress lab)</p></body></html>")(w, r)
		},
	}
	for name, fallback := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFakeWP(t)
			f.routes["/"] = homepage
			f.fallback = fallback
			o := options(f.URL(), cli.ModeMixed)
			o.Force = true
			o.Enumerate = fullEnumeration()
			r := runScan(t, o)
			for _, p := range r.Plugins {
				if slices.Contains(methods(p.Evidence), "Known location") {
					t.Errorf("false positive plugin %s: %+v", p.Slug, p.Evidence)
				}
			}
			for _, th := range r.Themes {
				if slices.Contains(methods(th.Evidence), "Known location") {
					t.Errorf("false positive theme %s: %+v", th.Slug, th.Evidence)
				}
			}
			for _, id := range []string{idConfigBackup, idDBExport, idBackupFolder} {
				if fi := findingByID(r, id); fi != nil {
					t.Errorf("false positive %s: %+v", id, fi)
				}
			}
			for _, u := range r.Users {
				t.Errorf("false positive user %+v", u)
			}
		})
	}
}

func TestBruteForceWhenHEADIsRefused(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	site := f.srv.Config.Handler
	var heads atomic.Int32
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			heads.Add(1)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		site.ServeHTTP(w, r)
	})
	o := options(f.URL(), cli.ModeAggressive)
	o.Enumerate = cli.Enumeration{Plugins: cli.ItemsPopular}
	o.DataDir = t.TempDir()
	o.Threads = 1
	r := runScan(t, o)
	if pluginBySlug(r, "duplicator") == nil || pluginBySlug(r, "akismet") == nil {
		t.Errorf("plugins = %+v", r.Plugins)
	}
	if n := heads.Load(); n > 2 {
		t.Errorf("HEAD was retried %d times after the server refused it", n)
	}
}

func TestRESTInventory(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:abcd efgh ijkl"))
	guarded := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != auth {
				respond(401, "application/json", `{"code":"rest_cannot_view_plugins"}`)(w, r)
				return
			}
			respond(200, "application/json", body)(w, r)
		}
	}
	f.routes["/wp-json/wp/v2/plugins"] = guarded(`[{"plugin":"akismet/akismet","status":"inactive","name":"Akismet Anti-Spam","version":"4.1.12"},
		{"plugin":"contact-form-7/wp-contact-form-7","status":"active","name":"Contact Form 7","version":"5.3.1"},
		{"plugin":"hello","status":"inactive","name":"Hello Dolly","version":"1.7.2"}]`)
	f.routes["/wp-json/wp/v2/themes"] = guarded(`[{"stylesheet":"twentytwenty","template":"twentytwenty","status":"active","version":"1.8","name":{"raw":"Twenty Twenty"}},
		{"stylesheet":"twentynineteen","template":"twentynineteen","status":"inactive","version":"2.1","name":{"raw":"Twenty Nineteen"}}]`)

	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = cli.Enumeration{Plugins: cli.ItemsAll, Themes: cli.ItemsAll}
	o.DataDir = writeData(t)
	o.WPAuth = &cli.Credentials{Username: "admin", Password: "abcd efgh ijkl"}
	r := runScan(t, o)

	var slugs []string
	for _, p := range r.Plugins {
		slugs = append(slugs, p.Slug+"@"+p.Version.Number)
	}
	if !slices.Equal(slugs, []string{"akismet@4.1.12", "contact-form-7@5.3.1", "hello@1.7.2"}) {
		t.Errorf("plugins = %v", slugs)
	}
	if cf7 := pluginBySlug(r, "contact-form-7"); len(cf7.Vulnerabilities) != 1 || cf7.Vulnerabilities[0].Verdict != VerdictConfirmed {
		t.Errorf("contact-form-7 vulnerabilities = %+v", cf7.Vulnerabilities)
	}
	if r.MainTheme == nil || r.MainTheme.Slug != "twentytwenty" || r.MainTheme.Version.Number != "1.8" || len(r.Themes) != 1 {
		t.Errorf("themes = %+v / %+v", r.MainTheme, r.Themes)
	}
	for _, req := range f.requested() {
		if strings.HasPrefix(req, "HEAD ") {
			t.Errorf("the inventory replaces brute force, but %s was sent", req)
		}
	}

	// Wrong credentials: a notice, and enumeration as usual.
	o.WPAuth.Password = "wrong"
	r = runScan(t, o)
	if pluginBySlug(r, "duplicator") == nil {
		t.Errorf("enumeration should run when the inventory fails: %+v", r.Plugins)
	}
	found := false
	for _, n := range r.Notices {
		found = found || strings.Contains(n, "--wp-auth") && strings.Contains(n, "rejected")
	}
	if !found {
		t.Errorf("notices = %v", r.Notices)
	}
}

func TestParseReadme(t *testing.T) {
	info, ok := parseReadme([]byte(readme("Contact Form 7", "5.3.1", "5.3", "5.3.1", "5.2.2")))
	if !ok || info.name != "Contact Form 7" || info.stableTag != "5.3.1" || info.changelog != "5.3.1" {
		t.Errorf("info = %+v", info)
	}
	md := "# Plugin Name\n**Contributors:** lab\n**Stable tag:** 2.4.1\n\n## Changelog\n### 2.4.1\n* Fix\n### 2.4.0\n## Upgrade Notice\n### 3.0\n"
	if info, ok := parseReadme([]byte(md)); !ok || info.stableTag != "2.4.1" || info.changelog != "2.4.1" {
		t.Errorf("markdown info = %+v", info)
	}
	trunk := "=== X ===\nStable tag: trunk\n== Changelog ==\n= 1.0 =\n"
	if info, _ := parseReadme([]byte(trunk)); info.stableTag != "" || info.changelog != "1.0" {
		t.Errorf("trunk info = %+v", info)
	}
	if _, ok := parseReadme([]byte("<html><body>Not found</body></html>")); ok {
		t.Error("an HTML page is not a readme")
	}
}

func TestSiteAlias(t *testing.T) {
	tests := []struct {
		host, base string
		want       bool
	}{
		{"cdn.example.com", "www.example.com", true},
		{"www.example.com", "example.com", true},
		{"static.example.co.uk", "example.co.uk", true},
		{"other.example.com", "www.example.com", false},
		{"cdn.other.com", "www.example.com", false},
		{"127.0.0.2", "127.0.0.1", false},
	}
	for _, tt := range tests {
		if got := siteAlias(tt.host, tt.base); got != tt.want {
			t.Errorf("siteAlias(%s, %s) = %v", tt.host, tt.base, got)
		}
	}
}
