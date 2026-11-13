package scan

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/wporg"
)

// quietHome is a WordPress homepage that says nothing about versions.
const quietHome = `<html><head><link rel="stylesheet" href="{{URL}}wp-content/themes/lab-child/style.css" /></head>
<body class="wp-theme-lab-child"><a href="{{URL}}wp-login.php">Log in</a>%s</body></html>`

// quietSite is the base site without anything that shows the WordPress
// version: no generator tag, no feed.
func quietSite(t *testing.T, extra string) *fakeWP {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", fmt.Sprintf(quietHome, extra))
	delete(f.routes, "/feed/")
	delete(f.routes, "/comments/feed/")
	return f
}

func TestCoreVersionSources(t *testing.T) {
	t.Run("wp-links-opml.php", func(t *testing.T) {
		f := quietSite(t, "")
		f.routes["/wp-links-opml.php"] = respond(200, "text/xml", "<?xml version=\"1.0\"?>\n<opml version=\"1.0\">\n<head>\n<title>Links for Lab</title>\n<!-- generator=\"WordPress/6.3.1\" -->\n</head><body></body></opml>")
		r := runScan(t, options(f.URL(), cli.ModeMixed))
		if r.Version.Number != "6.3.1" || !slices.Contains(methods(r.Version.Evidence), "wp-links-opml.php generator") {
			t.Errorf("version = %s (%d%%), evidence %v", r.Version.Number, r.Version.Confidence, methods(r.Version.Evidence))
		}
	})

	t.Run("install page", func(t *testing.T) {
		f := quietSite(t, "")
		f.routes["/wp-admin/install.php"] = respond(200, "text/html", `<html><head>
<link rel='stylesheet' id='dashicons-css' href='{{URL}}wp-includes/css/dashicons.min.css?ver=6.2.4' />
<link rel='stylesheet' id='buttons-css' href='{{URL}}wp-includes/css/buttons.min.css?ver=6.2.4' />
<link rel='stylesheet' id='install-css' href='{{URL}}wp-admin/css/install.min.css?ver=6.2.4' />
</head><body class="wp-core-ui"><h1>Already Installed</h1><p>You appear to have already installed WordPress.</p></body></html>`)
		r := runScan(t, options(f.URL(), cli.ModeMixed))
		if r.Version.Number != "6.2.4" || r.Version.Confidence < confInstallPage {
			t.Errorf("version = %s (%d%%), evidence %v", r.Version.Number, r.Version.Confidence, methods(r.Version.Evidence))
		}
	})

	t.Run("a soft 404 is not the install page", func(t *testing.T) {
		f := quietSite(t, "")
		f.routes["/wp-admin/install.php"] = respond(200, "text/html", `<html><head><link rel='stylesheet' href='{{URL}}wp-includes/css/dashicons.min.css?ver=9.9.9' /></head><body>Welcome</body></html>`)
		r := runScan(t, options(f.URL(), cli.ModeMixed))
		if slices.Contains(methods(r.Version.Evidence), "?ver= on the stylesheets of wp-admin/install.php") {
			t.Errorf("a page without install.css was taken for the install page: %+v", r.Version)
		}
	})

	t.Run("emoji settings", func(t *testing.T) {
		f := quietSite(t, "")
		f.routes["/"] = func(w http.ResponseWriter, r *http.Request) {
			escaped := strings.ReplaceAll("http://"+r.Host+"/", "/", `\/`)
			fmt.Fprintf(w, `<html><head><link rel="stylesheet" href="http://%s/wp-content/themes/lab-child/style.css" />
<script>window._wpemojiSettings = {"baseUrl":"https:\/\/s.w.org\/images\/core\/emoji\/14.0.0\/72x72\/","source":{"concatemoji":"%swp-includes\/js\/wp-emoji-release.min.js?ver=6.1.7"}};</script>
</head><body class="wp-theme-lab-child"></body></html>`, r.Host, escaped)
		}
		r := runScan(t, options(f.URL(), cli.ModePassive))
		if r.Version.Number != "6.1.7" || r.Version.Confidence != confLoadStyles || r.Version.Evidence[0].Method != "?ver= on the emoji script" {
			t.Errorf("version = %+v", r.Version)
		}
	})

	t.Run("stops at the first source that settles it", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite() // the meta tag and the feed say 6.4.2
		runScan(t, options(f.URL(), cli.ModeMixed))
		for _, req := range f.requested() {
			if strings.Contains(req, "wp-links-opml.php") || strings.Contains(req, "install.php") || strings.Contains(req, "feed/atom") {
				t.Errorf("%s requested although the version was settled", req)
			}
		}
	})
}

func TestPluginVersionFromScriptData(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", `<html><head><meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="{{URL}}wp-content/themes/lab-child/style.css" /></head><body>
<script id="acme-frontend-js-before">
var acmeFrontendConfig = {"environmentMode":{"edit":false},"i18n":{"close":"Close"},"version":"3.18.3","urls":{"assets":"x"}};
</script>
<script src="{{URL}}wp-content/plugins/acme/assets/js/frontend.min.js?ver=3.18.3" id="acme-frontend-js"></script>
<script id="other-js-extra">var otherData = {"version":"9.9.9"};</script>
<script src="{{URL}}wp-includes/js/other.js" id="other-js"></script>
<script id="wpver-js-extra">var wpverData = {"version":"6.4.2"};</script>
<script src="{{URL}}wp-content/plugins/wpver/a.js" id="wpver-js"></script>
</body></html>`)
	r := runScan(t, options(f.URL(), cli.ModePassive))
	acme := pluginBySlug(r, "acme")
	if acme == nil || acme.Version.Number != "3.18.3" || !slices.Contains(methods(acme.Version.Evidence), "Version in the data of the plugin's script") {
		t.Fatalf("acme = %+v", acme)
	}
	// The script data (60%) and the asset's ?ver= (40%) agree.
	if acme.Version.Confidence != 76 {
		t.Errorf("confidence = %d, want 76", acme.Version.Confidence)
	}
	// A "version" equal to WordPress's is not the plugin's.
	if p := pluginBySlug(r, "wpver"); p == nil || p.Version.Number != "" {
		t.Errorf("wpver = %+v", p)
	}

	for js, want := range map[string]string{
		`var a = {"version":"1.2.3"};`:                              "1.2.3",
		`var a = {"x":{"version":"9.9"}}; var b = {"ver":"2.0.1"};`: "2.0.1",
		`foo({"plugin_version":"4.5"});`:                            "4.5",
		`var a = {"version":"abc"};`:                                "",
		`if (x) { y(); } var a = {"version": 3};`:                   "",
		`var a = {"version":"12"};`:                                 "",
		`var broken = {"version":"1.0.0"`:                           "",
	} {
		if got := dataVersion(js); got != want {
			t.Errorf("dataVersion(%s) = %q, want %q", js, got, want)
		}
	}
}

func TestPluginVersionFromOtherFiles(t *testing.T) {
	home := `<html><head><meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="{{URL}}wp-content/themes/lab-child/style.css" />
<link rel="stylesheet" href="{{URL}}wp-content/plugins/acme-pro/public/main.css" />
<link rel="stylesheet" href="{{URL}}wp-content/plugins/locked/public/main.css" /></head><body></body></html>`
	site := func(t *testing.T) *fakeWP {
		f := newFakeWP(t).addBaseSite()
		f.routes["/"] = respond(200, "text/html", home)
		f.routes["/wp-content/plugins/acme-pro/public/main.css"] = respond(200, "text/css", "body{}")
		f.routes["/wp-content/plugins/acme-pro/languages/acme-pro.pot"] = respond(200, "text/plain",
			"# Copyright (C) 2026 Acme\nmsgid \"\"\nmsgstr \"\"\n\"Project-Id-Version: Acme Pro 2.7.1\\n\"\n\"Report-Msgid-Bugs-To: https://example.com\\n\"\n\nmsgid \"Hello\"\nmsgstr \"\"\n")
		f.routes["/wp-content/plugins/acme-pro/package.json"] = respond(200, "application/json", `{"name":"acme-pro","version":"2.7.2","scripts":{}}`)
		f.routes["/wp-content/plugins/locked/public/main.css"] = respond(200, "text/css", "body{}")
		f.routes["/wp-content/plugins/locked/readme.txt"] = respond(403, "text/html", "<h1>Forbidden</h1>")
		f.routes["/wp-content/plugins/locked/changelog.txt"] = respond(403, "text/html", "<h1>Forbidden</h1>")
		return f
	}

	f := site(t)
	r := runScan(t, options(f.URL(), cli.ModeMixed))
	acme := pluginBySlug(r, "acme-pro")
	if acme == nil || acme.Version.Number != "2.7.1" || acme.Version.Confidence != confVersionPot {
		t.Fatalf("acme-pro = %+v", acme)
	}
	if !strings.HasPrefix(acme.Version.Evidence[0].Method, "Translation template") {
		t.Errorf("evidence = %v", methods(acme.Version.Evidence))
	}
	reqs := f.requested()
	if slices.Contains(reqs, "GET /wp-content/plugins/acme-pro/package.json") || slices.Contains(reqs, "GET /wp-content/plugins/acme-pro/README.txt") {
		t.Errorf("a default scan should not try the rarer files: %v", reqs)
	}
	// readme.txt answered 403: the server refuses text files there, so
	// changelog.txt is not worth a request.
	if slices.Contains(reqs, "GET /wp-content/plugins/locked/changelog.txt") {
		t.Error("changelog.txt was requested after readme.txt answered 403")
	}
	if pluginBySlug(r, "locked") == nil {
		t.Error("the plugin whose text files are refused is still installed")
	}

	// --aggressive tries every way and every name.
	f = site(t)
	o := options(f.URL(), cli.ModeMixed)
	o.Thorough = true
	r = runScan(t, o)
	acme = pluginBySlug(r, "acme-pro")
	if acme == nil || !slices.Contains(methods(acme.Version.Evidence), "package.json") || len(acme.Version.Candidates) != 2 {
		t.Fatalf("--aggressive acme-pro = %+v", acme)
	}
	reqs = f.requested()
	for _, want := range []string{"GET /wp-content/plugins/acme-pro/README.txt", "GET /wp-content/plugins/acme-pro/CHANGELOG.md", "GET /wp-content/plugins/locked/changelog.txt"} {
		if !slices.Contains(reqs, want) {
			t.Errorf("--aggressive did not request %s", want)
		}
	}
}

// fakeOrg is WordPress.org's plugin information and checksums.
type fakeOrg struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []string
	// plugins maps a slug to its releases, each a map of file to content.
	plugins map[string]map[string]map[string]string
}

func md5Of(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newFakeOrg(t *testing.T) *fakeOrg {
	o := &fakeOrg{plugins: map[string]map[string]map[string]string{}}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.requests = append(o.requests, r.URL.Path)
		o.mu.Unlock()
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case len(parts) == 2 && parts[0] == "info":
			releases, ok := o.plugins[strings.TrimSuffix(parts[1], ".json")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":"Plugin not found."}`)
				return
			}
			versions := map[string]string{"trunk": "https://downloads.wordpress.org/plugin/x.zip"}
			for v := range releases {
				versions[v] = "https://downloads.wordpress.org/plugin/x." + v + ".zip"
			}
			json.NewEncoder(w).Encode(map[string]any{"slug": parts[1], "versions": versions})
		case len(parts) == 3 && parts[0] == "sums":
			files, ok := o.plugins[parts[1]][strings.TrimSuffix(parts[2], ".json")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			out := map[string]map[string]any{}
			for path, content := range files {
				out[path] = map[string]any{"md5": md5Of(content), "sha256": "x"}
			}
			out["plugin.php"] = map[string]any{"md5": []string{md5Of("php"), md5Of("php2")}}
			json.NewEncoder(w).Encode(map[string]any{"plugin": parts[1], "files": out})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *fakeOrg) client(t *testing.T) *wporg.Client {
	c := wporg.New(t.TempDir(), nil, "cmsrecon/test")
	c.InfoURL = o.srv.URL + "/info/%s.json"
	c.ChecksumsURL = o.srv.URL + "/sums/%s/%s.json"
	return c
}

func (o *fakeOrg) asked() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.requests)
}

// runScanOrg runs a scan that asks org instead of WordPress.org.
func runScanOrg(t *testing.T, o *cli.ScanOptions, org *wporg.Client) *Result {
	t.Helper()
	o.Offline = false
	c, err := httpclient.New(o)
	if err != nil {
		t.Fatal(err)
	}
	s := New(o, c)
	s.Org = org
	return s.Run(context.Background(), nil)
}

// hashSite is a site with one plugin, hashme, whose readme is hidden and
// whose pages load assets/app.js. files are what the site serves.
func hashSite(t *testing.T, ver string, files map[string]string) *fakeWP {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", `<html><head><meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="{{URL}}wp-content/themes/lab-child/style.css" /></head><body>
<script src="{{URL}}wp-content/plugins/hashme/assets/app.js`+ver+`"></script></body></html>`)
	for path, content := range files {
		f.routes["/wp-content/plugins/hashme/"+path] = respond(200, "application/javascript", content)
	}
	return f
}

func TestPluginVersionFromChecksums(t *testing.T) {
	// app.js is the same in 1.1 and 1.2; style.css tells them apart.
	releases := map[string]map[string]string{
		"1.0": {"assets/app.js": "app-a", "assets/style.css": "style-a", "readme.txt": "r1.0"},
		"1.1": {"assets/app.js": "app-b", "assets/style.css": "style-a", "readme.txt": "r1.1"},
		"1.2": {"assets/app.js": "app-b", "assets/style.css": "style-b", "readme.txt": "r1.2"},
		"1.3": {"assets/app.js": "app-c", "assets/style.css": "style-b", "readme.txt": "r1.3"},
	}

	t.Run("one release matches", func(t *testing.T) {
		org := newFakeOrg(t)
		org.plugins["hashme"] = releases
		f := hashSite(t, "", map[string]string{"assets/app.js": "app-b", "assets/style.css": "style-b"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		p := pluginBySlug(r, "hashme")
		if p == nil || p.Version.Number != "1.2" || p.Version.Confidence != confHashRelease {
			t.Fatalf("hashme = %+v", p)
		}
		if p.Version.Evidence[0].Method != "File hashes (WordPress.org checksums)" {
			t.Errorf("evidence = %v", methods(p.Version.Evidence))
		}
		// One file the page loads, one more to tell 1.1 from 1.2.
		var files []string
		for _, req := range f.requested() {
			if strings.Contains(req, "/plugins/hashme/assets/") {
				files = append(files, req)
			}
		}
		if len(files) > 3 {
			t.Errorf("too many of the plugin's files requested: %v", files)
		}
		if len(r.Notices) != 1 { // only the missing vulnerability data
			t.Errorf("notices = %q", r.Notices)
		}
	})

	t.Run("several releases match and another signal picks one", func(t *testing.T) {
		org := newFakeOrg(t)
		org.plugins["hashme"] = releases
		// style.css cannot be read: 1.1 and 1.2 both match; ?ver= says 1.1.
		f := hashSite(t, "?ver=1.1", map[string]string{"assets/app.js": "app-b"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		p := pluginBySlug(r, "hashme")
		if p == nil || p.Version.Number != "1.1" || p.Version.Confidence < confHashAgrees {
			t.Fatalf("hashme = %+v", p)
		}
		if !strings.Contains(strings.Join(methods(p.Version.Evidence), "; "), "one of 1.1, 1.2") {
			t.Errorf("evidence = %v", methods(p.Version.Evidence))
		}
	})

	t.Run("several releases match and nothing picks one", func(t *testing.T) {
		org := newFakeOrg(t)
		org.plugins["hashme"] = releases
		f := hashSite(t, "", map[string]string{"assets/app.js": "app-b"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		p := pluginBySlug(r, "hashme")
		if p == nil || len(p.Version.Candidates) != 2 || p.Version.Confidence != confHashReleases {
			t.Fatalf("hashme = %+v", p)
		}
	})

	t.Run("a wrong ?ver= is corrected", func(t *testing.T) {
		org := newFakeOrg(t)
		org.plugins["hashme"] = releases
		f := hashSite(t, "?ver=1.0", map[string]string{"assets/app.js": "app-c", "assets/style.css": "style-b"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		p := pluginBySlug(r, "hashme")
		if p == nil || p.Version.Number != "1.3" || p.Version.Confidence != confHashRelease {
			t.Fatalf("hashme = %+v", p)
		}
	})

	t.Run("a modified file matches nothing", func(t *testing.T) {
		org := newFakeOrg(t)
		org.plugins["hashme"] = releases
		f := hashSite(t, "", map[string]string{"assets/app.js": "minified by a cache plugin"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		if p := pluginBySlug(r, "hashme"); p == nil || p.Version.Number != "" {
			t.Fatalf("hashme = %+v", p)
		}
	})

	t.Run("an old release far from the newest", func(t *testing.T) {
		org := newFakeOrg(t)
		many := map[string]map[string]string{}
		for i := range 30 {
			many[fmt.Sprintf("2.%d", i)] = map[string]string{"assets/app.js": fmt.Sprintf("app-%d", i)}
		}
		org.plugins["hashme"] = many
		f := hashSite(t, "", map[string]string{"assets/app.js": "app-3"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		p := pluginBySlug(r, "hashme")
		if p == nil || p.Version.Number != "2.3" || p.Version.Confidence != confHashRelease {
			t.Fatalf("hashme = %+v", p)
		}
		if n := len(org.asked()); n > maxChecksumReleases+1 {
			t.Errorf("%d requests to WordPress.org, want at most %d", n, maxChecksumReleases+1)
		}
	})

	t.Run("a plugin WordPress.org does not host", func(t *testing.T) {
		org := newFakeOrg(t)
		f := hashSite(t, "", map[string]string{"assets/app.js": "app-b"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		if p := pluginBySlug(r, "hashme"); p == nil || p.Version.Number != "" {
			t.Fatalf("hashme = %+v", p)
		}
		if len(r.Notices) != 1 {
			t.Errorf("a premium plugin is no reason for a notice: %q", r.Notices)
		}
	})

	t.Run("WordPress.org cannot be reached", func(t *testing.T) {
		org := newFakeOrg(t)
		client := org.client(t)
		org.srv.Close()
		f := hashSite(t, "", map[string]string{"assets/app.js": "app-b"})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), client)
		if r.Status != StatusCompleted || pluginBySlug(r, "hashme") == nil {
			t.Fatalf("the scan must go on without WordPress.org: %s", r.Status)
		}
		n := 0
		for _, notice := range r.Notices {
			if strings.Contains(notice, "WordPress.org could not be asked") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("want one notice about WordPress.org, got %d: %q", n, r.Notices)
		}
	})

	t.Run("--offline and passive mode ask nothing", func(t *testing.T) {
		org := newFakeOrg(t)
		org.plugins["hashme"] = releases
		f := hashSite(t, "", map[string]string{"assets/app.js": "app-b", "assets/style.css": "style-b"})
		o := options(f.URL(), cli.ModeMixed)
		c, _ := httpclient.New(o)
		s := New(o, c) // options() sets Offline
		s.Org = org.client(t)
		s.Run(context.Background(), nil)
		o = options(f.URL(), cli.ModePassive)
		runScanOrg(t, o, org.client(t))
		if asked := org.asked(); len(asked) != 0 {
			t.Errorf("WordPress.org was asked: %v", asked)
		}
	})

	t.Run("a settled version needs no checksum", func(t *testing.T) {
		org := newFakeOrg(t)
		org.plugins["hashme"] = releases
		f := hashSite(t, "", map[string]string{"assets/app.js": "app-b", "readme.txt": readme("Hash Me", "1.2", "1.2", "1.1")})
		r := runScanOrg(t, options(f.URL(), cli.ModeMixed), org.client(t))
		if p := pluginBySlug(r, "hashme"); p == nil || p.Version.Number != "1.2" {
			t.Fatalf("hashme = %+v", p)
		}
		if asked := org.asked(); len(asked) != 0 {
			t.Errorf("the readme gave the version; WordPress.org was asked anyway: %v", asked)
		}
	})
}
