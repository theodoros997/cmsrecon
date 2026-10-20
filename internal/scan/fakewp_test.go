package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// fakeWP is an httptest WordPress site. Pages are built from the request's
// own scheme and host, so the same fake works behind redirects.
type fakeWP struct {
	srv      *httptest.Server
	routes   map[string]http.HandlerFunc // "path" or "path?query"
	fallback http.HandlerFunc            // unknown paths; the WordPress 404 page by default

	mu       sync.Mutex
	requests []string
}

func newFakeWP(t *testing.T) *fakeWP {
	f := &fakeWP{routes: map[string]http.HandlerFunc{}}
	f.fallback = wpNotFound
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if h, ok := f.routes[r.URL.Path+"?"+r.URL.RawQuery]; ok && r.URL.RawQuery != "" {
		h(w, r)
		return
	}
	if h, ok := f.routes[r.URL.Path]; ok {
		h(w, r)
		return
	}
	f.fallback(w, r)
}

func (f *fakeWP) URL() string { return f.srv.URL + "/" }

// requested returns the request URIs seen so far.
func (f *fakeWP) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func siteURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/"
}

func respond(status int, contentType, body string, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], strings.ReplaceAll(headers[i+1], "{{URL}}", siteURL(r)))
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, strings.ReplaceAll(body, "{{URL}}", siteURL(r)))
	}
}

func redirect(status int, to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.ReplaceAll(to, "{{URL}}", siteURL(r)), status)
	}
}

const homepageHTML = `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8" />
<title>Lab Site</title>
<link rel="alternate" type="application/rss+xml" title="Lab Site &raquo; Feed" href="{{URL}}feed/" />
<link rel="alternate" type="application/rss+xml" title="Lab Site &raquo; Comments Feed" href="{{URL}}comments/feed/" />
<script>
window._wpemojiSettings = {"source":{"concatemoji":"{{URL}}wp-includes\/js\/wp-emoji-release.min.js?ver=6.4.2"}};
</script>
<link rel='stylesheet' id='wp-block-library-css' href='{{URL}}wp-includes/css/dist/block-library/style.min.css?ver=6.4.2' media='all' />
<link rel='stylesheet' id='parent-style-css' href='{{URL}}wp-content/themes/twentytwentyone/style.css?ver=2.0' media='all' />
<link rel='stylesheet' id='child-style-css' href='{{URL}}wp-content/themes/lab-child/style.css?ver=1.0.3' media='all' />
<script src="{{URL}}wp-includes/js/jquery/jquery.min.js?ver=3.7.1" id="jquery-core-js"></script>
<script src="{{URL}}wp-content/mu-plugins/lab-loader/loader.js?ver=1" id="mu-js"></script>
<link rel="https://api.w.org/" href="{{URL}}wp-json/" />
<link rel="pingback" href="{{URL}}xmlrpc.php" />
<meta name="generator" content="WordPress 6.4.2" />
</head>
<body class="home blog wp-embed-responsive">
<form><input type="hidden" name="_wpnonce" value="NONCE" /></form>
<p>Posted TIME</p>
<script src="{{URL}}wp-includes/js/comment-reply.min.js?ver=6.4.2"></script>
<script src="{{URL}}wp-content/themes/twentytwentyone/assets/js/polyfills.js?ver=2.0"></script>
</body>
</html>`

// homepage serves homepageHTML with a fresh nonce and time on every request,
// as WordPress does.
func homepage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Apache/2.4.57 (Debian)")
	w.Header().Set("X-Powered-By", "PHP/8.2.12")
	w.Header().Set("Link", "<"+siteURL(r)+"wp-json/>; rel=\"https://api.w.org/\"")
	w.Header().Set("X-Pingback", siteURL(r)+"xmlrpc.php")
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	body := strings.ReplaceAll(homepageHTML, "{{URL}}", siteURL(r))
	body = strings.ReplaceAll(body, "NONCE", randomName()[:10])
	body = strings.ReplaceAll(body, "TIME", time.Now().Format(time.RFC3339Nano))
	fmt.Fprint(w, body)
}

const notFoundHTML = `<!DOCTYPE html>
<html lang="en-US"><head><title>Page not found &#8211; Lab Site</title>
<link rel='stylesheet' href='{{URL}}wp-content/themes/lab-child/style.css?ver=1.0.3' media='all' />
<meta name="generator" content="WordPress 6.4.2" />
</head>
<body class="error404 wp-embed-responsive">
<h1>Nothing here</h1><p>It looks like nothing was found at this location.</p>
</body></html>`

func wpNotFound(w http.ResponseWriter, r *http.Request) {
	respond(404, "text/html; charset=UTF-8", notFoundHTML)(w, r)
}

const rssFeed = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0">
<channel><title>Lab Site</title>
<generator>https://wordpress.org/?v=6.4.2</generator>
</channel></rss>`

const listMethodsResponse = `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><string>system.multicall</string></value>
<value><string>system.listMethods</string></value>
<value><string>pingback.ping</string></value>
<value><string>wp.getUsersBlogs</string></value>
</data></array></value></param></params></methodResponse>`

func xmlrpc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respond(405, "text/plain", "XML-RPC server accepts POST requests only.")(w, r)
		return
	}
	respond(200, "text/xml; charset=UTF-8", listMethodsResponse)(w, r)
}

// addBaseSite adds a healthy WordPress site with no exposures.
func (f *fakeWP) addBaseSite() *fakeWP {
	f.routes["/"] = homepage
	f.routes["/feed/"] = respond(200, "application/rss+xml", rssFeed)
	f.routes["/comments/feed/"] = respond(200, "application/rss+xml", rssFeed)
	f.routes["/xmlrpc.php"] = xmlrpc
	f.routes["/wp-login.php"] = respond(200, "text/html", `<form name="loginform" id="loginform" action="wp-login.php" method="post">`)
	f.routes["/wp-signup.php"] = redirect(302, "{{URL}}wp-login.php?action=register")
	f.routes["/wp-login.php?action=register"] = redirect(302, "{{URL}}wp-login.php?registration=disabled")
	f.routes["/wp-content/themes/lab-child/style.css"] = respond(200, "text/css", "/*\nTheme Name: Lab Child\nTemplate: twentytwentyone\nVersion: 1.0.3\nAuthor: Lab Team\n*/\n")
	f.routes["/wp-content/themes/twentytwentyone/style.css"] = respond(200, "text/css",
		"/*\nTheme Name: Twenty Twenty-One\nTheme URI: https://wordpress.org/themes/twentytwentyone/\nAuthor: the WordPress team\nAuthor URI: https://wordpress.org/\nVersion: 2.0\n*/\n")
	f.routes["/wp-cron.php"] = respond(200, "text/html", "")
	return f
}

// addExposures adds every interesting finding except multisite.
func (f *fakeWP) addExposures() *fakeWP {
	f.routes["/robots.txt"] = respond(200, "text/plain",
		"User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\nDisallow: /secret-backup/\nSitemap: {{URL}}wp-sitemap.xml\n")
	f.routes["/readme.html"] = respond(200, "text/html", `<title>WordPress &#8250; ReadMe</title><h1 id="logo"></h1><br /> Version 6.4.2`)
	f.routes["/wp-content/debug.log"] = respond(200, "text/plain",
		"[20-Oct-2026 10:00:00 UTC] PHP Notice:  Undefined index: x in /var/www/html/wp-content/plugins/a/a.php on line 3\n")
	// Modern releases exit early in rss-functions.php; template-loader.php
	// still fails when requested directly.
	f.routes["/wp-includes/rss-functions.php"] = respond(200, "text/html", "")
	f.routes["/wp-includes/template-loader.php"] = respond(500, "text/html",
		"<br />\n<b>Fatal error</b>:  Uncaught Error: Call to undefined function wp_using_themes() in /var/www/html/wp-includes/template-loader.php:7\nStack trace:\n#0 {main}\n  thrown in <b>/var/www/html/wp-includes/template-loader.php</b> on line <b>7</b><br />")
	f.routes["/wp-content/backup-db/"] = respond(403, "text/html",
		"<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>You don't have permission to access /wp-content/backup-db/ on this server.</p></body></html>")
	f.routes["/installer-log.txt"] = respond(200, "text/plain", "********************************************************************************\n* DUPLICATOR-LITE: INSTALL-LOG\n* VERSION: 1.5.7\n")
	f.routes["/wp-login.php?action=register"] = respond(200, "text/html", `<form name="registerform" id="registerform" action="wp-login.php?action=register" method="post">`)
	f.routes["/wp-content/uploads/"] = respond(200, "text/html",
		`<html><head><title>Index of /wp-content/uploads</title></head><body><h1>Index of /wp-content/uploads</h1><table><tr><th><a href="?C=N;O=D">Name</a></th></tr><tr><td><a href="/wp-content/">Parent Directory</a></td></tr><tr><td><a href="2026/">2026/</a></td></tr><tr><td><a href="dump.sql">dump.sql</a></td></tr></table></body></html>`)
	f.routes["/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip"] = respond(200, "application/zip", "PK\x03\x04\x14\x00\x00\x00"+strings.Repeat("x", 600))
	f.routes["/wp-content/uploads/dump.sql"] = respond(200, "application/sql", "-- MySQL dump 10.13  Distrib 8.0.36\n--\nCREATE TABLE `wp_users` (\n")
	f.routes["/wp-content/mu-plugins/"] = respond(403, "text/html", "<h1>Forbidden</h1>")
	f.routes["/emergency.php"] = respond(200, "text/html", "<title>WordPress Emergency PassWord Reset</title><form>")
	f.routes["/wp-includes/version.php"] = respond(200, "text/plain", "<?php\n$wp_version = '6.4.2';\n$wp_db_version = 56657;\n")
	f.routes["/fantastico_fileslist.txt"] = respond(200, "text/plain", "/var/www/html/index.php\n/var/www/html/wp-config.php\n")
	f.routes["/searchreplacedb2.php"] = respond(200, "text/html", "<title>Search and Replace DB</title> by interconnect/it")
	return f
}

func options(target string, mode cli.DetectionMode) *cli.ScanOptions {
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	return &cli.ScanOptions{
		Target: u, DetectionMode: mode, Threads: 5, Timeout: 5 * time.Second, Headers: http.Header{},
	}
}

func runScan(t *testing.T, o *cli.ScanOptions) *Result {
	t.Helper()
	c, err := httpclient.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return New(o, c).Run(context.Background(), nil)
}

func findingIDs(r *Result) []string {
	var ids []string
	for _, f := range r.InterestingFindings {
		ids = append(ids, f.ID)
	}
	return ids
}

func findingByID(r *Result, id string) *Finding {
	for i := range r.InterestingFindings {
		if r.InterestingFindings[i].ID == id {
			return &r.InterestingFindings[i]
		}
	}
	return nil
}
