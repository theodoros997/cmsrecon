package scan

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path"
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
	notFound := respond(404, "text/html", `<html><head><title>Page not found</title><link rel='stylesheet' href='{{URL}}wp-content/themes/twentytwenty/style.css?ver=1.8' /></head><body class="error404">Nothing here</body></html>`)
	// Like a real site, the scripts and stylesheets the pages load exist.
	f.fallback = func(w http.ResponseWriter, r *http.Request) {
		if ext := path.Ext(r.URL.Path); (ext == ".js" || ext == ".css") && strings.HasPrefix(r.URL.Path, "/wp-") {
			respond(200, "text/css", "/* asset */")(w, r)
			return
		}
		notFound(w, r)
	}
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
		Plugins: []wordlists.Item{{Slug: "akismet", Version: "5.3", LastUpdated: "2019-01-01"}, {Slug: "contact-form-7", Version: "6.1", LastUpdated: "2026-09-30"},
			{Slug: "duplicator", Version: "1.5.7"}, {Slug: "wordpress-seo", LastUpdated: "2020-05-01"}, {Slug: "not-installed"}},
		Themes: []wordlists.Item{{Slug: "twentytwenty", Version: "2.7"}, {Slug: "twentynineteen", Version: "2.9"}, {Slug: "astra"}},
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
	o.PluginsDetection, o.ThemesDetection = cli.ModeMixed, cli.ModeMixed
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
	// Its version is unknown and its one vulnerability was fixed long ago:
	// counted as possible, not listed.
	ak := pluginBySlug(r, "akismet")
	if ak.Version.Number != "" || ak.Confidence != 70 || len(ak.Vulnerabilities) != 0 ||
		ak.Possible == nil || ak.Possible.Count != 1 || ak.Possible.FixedIn != "3.1.5" || ak.Possible.Listed {
		t.Errorf("akismet = %+v, possible %+v", ak, ak.Possible)
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
	o.PluginsDetection = cli.ModeMixed
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
	o.PluginsDetection = cli.ModeMixed
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
			o.PluginsDetection, o.ThemesDetection = cli.ModeMixed, cli.ModeMixed
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
	o.PluginsDetection = cli.ModeAggressive
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
	o.PluginsDetection, o.ThemesDetection = cli.ModeMixed, cli.ModeMixed
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

// addDiscoverySite extends the component site with pages that each load a
// plugin the homepage does not: an inner page, a product page listed in
// the sitemap, a post with a comment form, and the login page.
func (f *fakeWP) addDiscoverySite() *fakeWP {
	f.addComponentSite()
	home := strings.Replace(pluginHomepage, "<article>", `<nav><a href="{{URL}}contact/">Contact</a> <a href="{{URL}}contact/#form">Form</a>
<a href="{{URL}}2026/10/hello-world/">Hello</a> <a href="{{URL}}wp-admin/">Admin</a> <a href="{{URL}}?add-to-cart=12">Buy</a>
<a href="https://other.example/">Elsewhere</a> <a href="{{URL}}wp-content/uploads/2026/10/file.pdf">PDF</a></nav><article>`, 1)
	f.routes["/"] = respond(200, "text/html; charset=UTF-8", home, "Link", `<{{URL}}wp-json/>; rel="https://api.w.org/"`)
	page := func(body string) http.HandlerFunc {
		return respond(200, "text/html; charset=UTF-8", "<html><head><title>Lab</title>"+body+"</head><body></body></html>")
	}
	f.routes["/contact/"] = page(`<link rel='stylesheet' href='{{URL}}wp-content/plugins/wpforms-lite/assets/css/wpforms-full.min.css?ver=1.6.3' />`)
	f.routes["/2026/10/hello-world/"] = page(`</head><body><form id="commentform"><input type="hidden" name="ak_js" value="1" /></form>`)
	f.routes["/product/hoodie/"] = page(`<meta name="generator" content="WooCommerce 5.1.0" /><script src='{{URL}}wp-content/plugins/woocommerce-gateway-stripe/assets/js/stripe.min.js?ver=5.0.0'></script>`)
	f.routes["/about/"] = page(`<script src='{{URL}}wp-content/plugins/smart-slider-3/Public/SmartSlider3/Application/Frontend/Assets/dist/smartslider-frontend.min.js?ver=3.5.0.8'></script>`)
	f.routes["/wp-login.php"] = page(`<link rel='stylesheet' href='{{URL}}wp-content/plugins/limit-login-attempts-reloaded/assets/css/login-page-styles.css?ver=2.25.0' />
</head><body><form name="loginform" id="loginform" action="wp-login.php" method="post">`)
	f.routes["/wp-sitemap.xml"] = respond(200, "application/xml", `<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<sitemap><loc>{{URL}}wp-sitemap-posts-page-1.xml</loc></sitemap>
<sitemap><loc>{{URL}}wp-sitemap-posts-product-1.xml</loc></sitemap>
<sitemap><loc>{{URL}}wp-sitemap-taxonomies-category-1.xml</loc></sitemap>
<sitemap><loc>{{URL}}wp-sitemap-users-1.xml</loc></sitemap></sitemapindex>`)
	f.routes["/wp-sitemap-posts-page-1.xml"] = respond(200, "application/xml",
		`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{{URL}}</loc></url><url><loc>{{URL}}about/</loc></url></urlset>`)
	f.routes["/wp-sitemap-posts-product-1.xml"] = respond(200, "application/xml",
		`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{{URL}}product/hoodie/</loc></url></urlset>`)
	return f
}

func TestDefaultScanDiscoversWithoutBruteForce(t *testing.T) {
	f := newFakeWP(t).addDiscoverySite()
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = cli.Enumeration{Plugins: cli.ItemsAll, Themes: cli.ItemsVulnerable}
	o.DataDir = writeData(t)
	r := runScan(t, o)

	var slugs []string
	for _, p := range r.Plugins {
		slugs = append(slugs, p.Slug)
	}
	want := []string{"akismet", "contact-form-7", "limit-login-attempts-reloaded", "redirection", "smart-slider-3",
		"woocommerce", "woocommerce-gateway-stripe", "wordpress-seo", "wpforms-lite"}
	if !slices.Equal(slugs, want) {
		t.Errorf("plugins = %v\nwant %v", slugs, want)
	}
	wc := pluginBySlug(r, "woocommerce")
	if wc == nil || !slices.Contains(methods(wc.Evidence), "Post type in the sitemap") || wc.Version.Number != "5.1.0" {
		t.Errorf("woocommerce = %+v", wc)
	}
	if wp := pluginBySlug(r, "wpforms-lite"); wp == nil || wp.Evidence[0].Mode != modeAggressive || wp.Version.Number != "1.6.3" || wp.Version.Confidence != 40 {
		t.Errorf("wpforms-lite (crawled contact page) = %+v", wp)
	}
	if pluginBySlug(r, "duplicator") != nil {
		t.Error("an inactive plugin can only be found by brute force or a listing, and neither applies")
	}
	cf7 := pluginBySlug(r, "contact-form-7")
	if len(cf7.Vulnerabilities) != 1 || cf7.Vulnerabilities[0].Verdict != VerdictConfirmed {
		t.Errorf("vulnerabilities are still matched on discovered plugins: %+v", cf7.Vulnerabilities)
	}

	reqs := f.requested()
	for _, req := range reqs {
		// HEAD on a plugin folder is brute force; HEAD on a file the page
		// loads only confirms the link is live.
		bruteForce := strings.HasPrefix(req, "HEAD ") && strings.HasSuffix(req, "/")
		if bruteForce || req == "GET /wp-admin/" || strings.Contains(req, "add-to-cart") || strings.Contains(req, ".pdf") || strings.Contains(req, "other.example") {
			t.Errorf("unexpected request %s", req)
		}
	}
	if !slices.Contains(reqs, "GET /product/hoodie/") || !slices.Contains(reqs, "GET /contact/") || !slices.Contains(reqs, "GET /about/") {
		t.Errorf("the crawl missed a page: %v", reqs)
	}
	if len(reqs) > 120 {
		t.Errorf("%d requests; discovery should need far fewer", len(reqs))
	}
	t.Logf("%d requests", len(reqs))

	found := false
	for _, n := range r.Notices {
		found = found || strings.Contains(n, "--plugins-detection mixed")
	}
	if !found {
		t.Errorf("-e ap without brute force should say how to brute-force: %v", r.Notices)
	}
}

func TestDirectoryListingDiscovery(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	f.routes["/wp-content/plugins/"] = respond(200, "text/html",
		`<html><head><title>Index of /wp-content/plugins</title></head><body><h1>Index of /wp-content/plugins</h1><a href="/wp-content/">Parent Directory</a><a href="akismet/">akismet/</a><a href="duplicator/">duplicator/</a><a href="hello.php">hello.php</a><a href="index.php">index.php</a></body></html>`)
	f.routes["/wp-content/themes/"] = respond(200, "text/html",
		`<html><head><title>Index of /wp-content/themes</title></head><body><h1>Index of /wp-content/themes</h1><a href="twentynineteen/">twentynineteen/</a><a href="twentytwenty/">twentytwenty/</a></body></html>`)
	o := options(f.URL(), cli.ModeMixed)
	o.DataDir = writeData(t)
	r := runScan(t, o)
	dup := pluginBySlug(r, "duplicator")
	if dup == nil || !slices.Contains(methods(dup.Evidence), "Directory listing") || dup.Version.Number != "1.3.26" || len(dup.Vulnerabilities) != 1 {
		t.Errorf("duplicator from the listing = %+v", dup)
	}
	if pluginBySlug(r, "hello.php") != nil || pluginBySlug(r, "index.php") != nil {
		t.Error("files in the listing are not plugins")
	}
	if len(r.Themes) != 1 || r.Themes[0].Slug != "twentynineteen" {
		t.Errorf("themes from the listing = %+v (the main theme stays out of the list)", r.Themes)
	}
}

func TestCrawlIsOff(t *testing.T) {
	for name, o := range map[string]func(*cli.ScanOptions){
		"passive mode": func(o *cli.ScanOptions) { o.DetectionMode = cli.ModePassive },
		"--crawl 0":    func(o *cli.ScanOptions) { o.CrawlPages = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeWP(t).addDiscoverySite()
			opts := options(f.URL(), cli.ModeMixed)
			o(opts)
			runScan(t, opts)
			for _, req := range f.requested() {
				if strings.Contains(req, "/contact/") || strings.Contains(req, "sitemap") {
					t.Errorf("crawled %s", req)
				}
			}
		})
	}
}

// TestNoHallucinatedComponents covers what pages contain that looks like a
// plugin or theme but is not one: template placeholders around plugin
// paths, links to files of plugins and themes removed since, and REST
// namespaces or meta generators that happen to match a slug.
func TestNoHallucinatedComponents(t *testing.T) {
	site := func(t *testing.T) *fakeWP {
		f := newFakeWP(t).addComponentSite()
		home := strings.Replace(pluginHomepage, "</head>", `<meta name="generator" content="performance-lab 3.2.0; plugins: webp-uploads" />
<script>var tpl = "{{URL}}wp-content/plugins/${slug}/x.js", fmt = "{{URL}}wp-content/plugins/%s/y.js", hb = "{{URL}}wp-content/plugins/{{name}}/z.js";</script>
<img src="{{URL}}wp-content/plugins/old-gallery/images/photo.jpg" />
<img src="{{URL}}wp-content/themes/old-theme/images/header.jpg" />
</head>`, 1)
		f.routes["/"] = respond(200, "text/html; charset=UTF-8", home, "Link", `<{{URL}}wp-json/>; rel="https://api.w.org/"`)
		f.routes["/wp-json/"] = respond(200, "application/json", `{"namespaces":["wp/v2","contact-form-7/v1","loco-translate/v1","updraftplus/v1"]}`)
		f.routes["/wp-content/plugins/updraftplus/"] = respond(200, "text/html", "")
		return f
	}
	plugins := func(r *Result) []string {
		var out []string
		for _, p := range r.Plugins {
			out = append(out, p.Slug)
		}
		return out
	}

	t.Run("mixed mode verifies", func(t *testing.T) {
		f := site(t)
		r := runScan(t, options(f.URL(), cli.ModeMixed))
		got := plugins(r)
		for _, bad := range []string{"${slug}", "%s", "{{name}}", "old-gallery", "loco-translate", "performance-lab"} {
			if slices.Contains(got, bad) {
				t.Errorf("reported %q: %v", bad, got)
			}
		}
		up := pluginBySlug(r, "updraftplus")
		if up == nil || up.Location == "" {
			t.Errorf("a guessed plugin whose folder answers is confirmed: %+v (%v)", up, got)
		}
		if themeBySlug(r.Themes, "old-theme") != nil {
			t.Errorf("a theme whose style.css is gone was reported: %+v", r.Themes)
		}
		// A plugin known only from its REST namespace has no observed folder.
		if red := pluginBySlug(r, "redirection"); red != nil && red.Location != "" {
			t.Errorf("redirection location %q was never seen", red.Location)
		}
		if cf7 := pluginBySlug(r, "contact-form-7"); cf7 == nil || cf7.Location == "" {
			t.Errorf("contact-form-7 = %+v", cf7)
		}
	})

	t.Run("passive mode keeps links but drops guesses", func(t *testing.T) {
		f := site(t)
		r := runScan(t, options(f.URL(), cli.ModePassive))
		got := plugins(r)
		if !slices.Contains(got, "old-gallery") {
			t.Errorf("without requests a link is all the evidence there is: %v", got)
		}
		for _, bad := range []string{"loco-translate", "updraftplus", "performance-lab", "${slug}", "%s"} {
			if slices.Contains(got, bad) {
				t.Errorf("an unconfirmed guess was reported in passive mode: %q in %v", bad, got)
			}
		}
	})
}

func TestValidSlug(t *testing.T) {
	for s, want := range map[string]bool{
		"contact-form-7": true, "LayerSlider": true, "js_composer": true, "wp-plugin.v2": true,
		"${slug}": false, "%s": false, "{{name}}": false, "..": false, ".": false, "": false, "a b": false, "%E2%9C%93": false,
	} {
		if validSlug(s) != want {
			t.Errorf("validSlug(%q) = %v", s, !want)
		}
	}
}
