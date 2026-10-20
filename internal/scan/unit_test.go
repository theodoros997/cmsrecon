package scan

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

func ev(method, value string, confidence int) Evidence {
	return Evidence{Method: method, Mode: modePassive, Value: value, Confidence: confidence}
}

func TestCombineVersions(t *testing.T) {
	tests := []struct {
		name     string
		evidence []Evidence
		want     string
		wantConf int
	}{
		{"no evidence is unknown", nil, "", 0},
		{"meta generator alone", []Evidence{ev("Meta generator", "6.4.2", 60)}, "6.4.2", 60},
		{"one core asset is below the threshold", []Evidence{ev("?ver= on core assets", "6.4.2", 30)}, "", 0},
		{"exactly the threshold", []Evidence{ev("?ver= on core assets", "6.4.2", 40)}, "6.4.2", 40},
		{"agreeing signals add up", []Evidence{ev("Meta generator", "6.4.2", 60), ev("RSS feed generator", "6.4.2", 80)}, "6.4.2", 92},
		{"the same method counts once", []Evidence{ev("RSS feed generator", "6.4.2", 80), ev("RSS feed generator", "6.4.2", 80)}, "6.4.2", 80},
		{"the strongest candidate wins", []Evidence{ev("Meta generator", "6.4.1", 60), ev("RSS feed generator", "6.4.2", 80)}, "6.4.2", 80},
		{"a tie goes to the higher version", []Evidence{ev("Meta generator", "6.4.10", 60), ev("readme.html", "6.4.9", 60)}, "6.4.10", 60},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := combineVersions(tt.evidence)
			if v.Number != tt.want || v.Confidence != tt.wantConf {
				t.Errorf("got %q at %d%%, want %q at %d%% (candidates %+v)", v.Number, v.Confidence, tt.want, tt.wantConf, v.Candidates)
			}
			if len(v.Evidence) != len(tt.evidence) {
				t.Errorf("evidence was dropped: %+v", v.Evidence)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"6.4.2", "6.4.2", 0},
		{"6.4.10", "6.4.9", 1},
		{"6.4", "6.4.0", 0},
		{"6.5-RC1", "6.5", -1},
		{"5.9", "6.0", -1},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSimilarity(t *testing.T) {
	home := []byte("<html>\n<head><title>Lab</title></head>\n<body>\n<input value=\"a1b2c3d4e5\">\n<p>Posted 2026-10-20 10:00:00</p>\n</body></html>")
	same := []byte("<html>\n<head><title>Lab</title></head>\n<body>\n<input value=\"ffee99aa01\">\n<p>Posted 2026-10-21 11:30:59</p>\n</body></html>")
	other := []byte("<html><body><h1>Index of /wp-content/uploads</h1><a href=\"2026/\">2026/</a></body></html>")
	if s := similarity(tokenize(home), tokenize(same)); s < similarThreshold {
		t.Errorf("pages differing only by nonce and time: similarity %.2f", s)
	}
	if s := similarity(tokenize(home), tokenize(other)); s >= similarThreshold {
		t.Errorf("different pages: similarity %.2f", s)
	}
	echo1 := []byte("<p>Nothing at /emergency.php</p>")
	echo2 := []byte("<p>Nothing at /0123456789abcdef.php</p>")
	if s := similarity(tokenize(echo1, "emergency.php"), tokenize(echo2, "0123456789abcdef.php")); s < similarThreshold {
		t.Errorf("pages echoing the requested path: similarity %.2f", s)
	}
	if similarity(bag{}, bag{}) != 1 {
		t.Error("two empty bodies are the same page")
	}
}

func TestBaselineKey(t *testing.T) {
	tests := []struct{ path, dir, suffix string }{
		{"/wp-content/backup-db/", "/wp-content/", "/"},
		{"/wp-content/debug.log", "/wp-content/", ".log"},
		{"/blog/emergency.php", "/blog/", ".php"},
		{"/x/", "/", "/"},
		{"/robots.txt", "/", ".txt"},
	}
	for _, tt := range tests {
		if dir, suffix := baselineKey(tt.path); dir != tt.dir || suffix != tt.suffix {
			t.Errorf("baselineKey(%s) = %s, %s; want %s, %s", tt.path, dir, suffix, tt.dir, tt.suffix)
		}
	}
}

func testPage(t *testing.T, rawURL, body string, header ...string) *page {
	t.Helper()
	u, _ := url.Parse(rawURL)
	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Set(header[i], header[i+1])
	}
	return parsePage(&httpclient.Response{URL: u, StatusCode: 200, Header: h, Body: []byte(body)})
}

func TestParsePage(t *testing.T) {
	p := testPage(t, "https://example.com/blog/", `<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel="Stylesheet" href="/blog/wp-content/themes/x/style.css">
<script>var s = {"src":"https:\/\/example.com\/blog\/wp-includes\/js\/a.js?ver=6.4.2"}; // //comment</script>
<style>@font-face{src:url('wp-content/themes/x/font.woff2')}</style>
<img srcset="//cdn.example.com/a.jpg 1x, /b.jpg 2x" src="data:image/png;base64,AA">
</head><body class="home wp-theme-x"></body></html>`)

	var urls []string
	for _, u := range p.urls {
		urls = append(urls, u.String())
	}
	for _, want := range []string{
		"https://example.com/blog/wp-content/themes/x/style.css",
		"https://example.com/blog/wp-includes/js/a.js?ver=6.4.2",
		"https://example.com/blog/wp-content/themes/x/font.woff2",
		"https://cdn.example.com/a.jpg",
		"https://example.com/b.jpg",
	} {
		if !slices.Contains(urls, want) {
			t.Errorf("missing %s in %v", want, urls)
		}
	}
	for _, u := range urls {
		if strings.Contains(u, "comment") || strings.HasPrefix(u, "data:") {
			t.Errorf("unexpected URL %s", u)
		}
	}
	if !slices.Equal(p.generators, []string{"WordPress 6.4.2"}) {
		t.Errorf("generators = %v", p.generators)
	}
	if len(p.linksTo("stylesheet")) != 1 {
		t.Errorf("stylesheet links = %v", p.links)
	}
	if !slices.Contains(p.bodyClasses, "wp-theme-x") {
		t.Errorf("body classes = %v", p.bodyClasses)
	}
}

func TestCoreAssetVersionsIgnoreBundledLibraries(t *testing.T) {
	s := testScanner(t, `
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>
<script src="/wp-includes/js/underscore.min.js?ver=1.13.4"></script>
<script src="/wp-includes/js/dist/hooks.min.js?ver=c6aec9a8d4e5a5d543a1"></script>
<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2">
<script src="/wp-includes/js/comment-reply.min.js?ver=6.4.2"></script>`)
	got := s.coreAssetVersions()
	if len(got) != 1 || got[0].Value != "6.4.2" || got[0].Confidence != 40 {
		t.Errorf("evidence = %+v, want 6.4.2 from two assets at 40%%", got)
	}
}

// testScanner is a scanner whose homepage is body, served from
// https://example.com/, without a network.
func testScanner(t *testing.T, body string, header ...string) *Scanner {
	t.Helper()
	o := options("https://example.com/", cli.ModeMixed)
	c, err := httpclient.New(o)
	if err != nil {
		t.Fatal(err)
	}
	s := New(o, c)
	s.res = &Result{}
	s.home = testPage(t, "https://example.com/", body, header...)
	s.content, _ = s.detectContentDir()
	return s
}

func TestMainThemeSignals(t *testing.T) {
	tests := []struct {
		name, body, want, parent string
	}{
		{"block theme with only font URLs",
			`<style>@font-face{src:url('/wp-content/themes/twentytwentyfour/assets/fonts/inter.woff2')}</style>`,
			"twentytwentyfour", ""},
		{"child theme body class",
			`<body class="wp-theme-parentone wp-child-theme-kid"><link rel="stylesheet" href="/wp-content/themes/parentone/style.css">`,
			"kid", "parentone"},
		{"style.css beats asset count",
			`<link rel="stylesheet" href="/wp-content/themes/kid/style.css">
<script src="/wp-content/themes/base/a.js"></script><script src="/wp-content/themes/base/b.js"></script>`,
			"kid", ""},
		{"WooFramework generator",
			`<meta name="generator" content="Canvas 5.9.3"><meta name="generator" content="WooFramework 6.2.0">`,
			"canvas", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testScanner(t, tt.body)
			s.opts.DetectionMode = cli.ModePassive
			th := s.detectMainTheme(t.Context())
			if th == nil || th.Slug != tt.want {
				t.Fatalf("main theme = %+v, want %s", th, tt.want)
			}
			if th.Location != "https://example.com/wp-content/themes/"+tt.want+"/" {
				t.Errorf("location = %s", th.Location)
			}
			gotParent := ""
			if th.Parent != nil {
				gotParent = th.Parent.Slug
			}
			if gotParent != tt.parent {
				t.Errorf("parent = %q, want %q", gotParent, tt.parent)
			}
		})
	}
	s := testScanner(t, `<meta name="generator" content="Canvas 5.9.3"><meta name="generator" content="WooFramework 6.2.0">`)
	s.opts.DetectionMode = cli.ModePassive
	if th := s.detectMainTheme(t.Context()); th.Version.Number != "5.9.3" {
		t.Errorf("WooFramework theme version = %+v", th.Version)
	}
}

func TestContentDirDetection(t *testing.T) {
	tests := []struct{ body, want string }{
		{`<script src="/blog/wp-content/plugins/a/a.js"></script>`, "https://example.com/blog/wp-content/"},
		{`<script src="/app/plugins/a/a.js"></script><link href="/app/themes/t/style.css">`, "https://example.com/app/"},
		{`<p>nothing</p>`, "https://example.com/wp-content/"},
	}
	for _, tt := range tests {
		if s := testScanner(t, tt.body); s.content.String() != tt.want {
			t.Errorf("content dir for %s = %s, want %s", tt.body, s.content, tt.want)
		}
	}
}

func TestStyleHeader(t *testing.T) {
	css := []byte("/*\n * Theme Name: Lab Child\n * Version: 1.0.3 */\nTemplate:twentytwentyone\n")
	for field, want := range map[string]string{"Theme Name": "Lab Child", "Version": "1.0.3", "Template": "twentytwentyone", "Author": ""} {
		if got := styleHeader(css, field); got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
}

func TestDirListing(t *testing.T) {
	tests := []struct {
		server, body string
		want         []string
	}{
		{"nginx", `<html><head><title>Index of /wp-content/uploads/</title></head><body><h1>Index of /wp-content/uploads/</h1><hr><pre><a href="../">../</a>
<a href="2026/">2026/</a>  20-Oct-2026 10:00  -
<a href="backup.zip">backup.zip</a></pre><hr></body></html>`, []string{"2026/", "backup.zip"}},
		{"iis", `<html><head><title>example.com - /wp-content/uploads/</title></head><body><H1>example.com - /wp-content/uploads/</H1><hr>
<pre><A HREF="/wp-content/">[To Parent Directory]</A><br><br> 10/20/2026 10:00 AM &lt;dir&gt; <A HREF="/wp-content/uploads/2026/">2026</A><br></pre></body></html>`, []string{"2026"}},
	}
	for _, tt := range tests {
		s := &Scanner{server: tt.server}
		res := &httpclient.Response{StatusCode: 200, Body: []byte(tt.body)}
		got, ok := s.dirListing(res)
		if !ok || !slices.Equal(got, tt.want) {
			t.Errorf("%s listing = %v, %v; want %v", tt.server, got, ok, tt.want)
		}
	}
	s := &Scanner{server: "apache"}
	if _, ok := s.dirListing(&httpclient.Response{StatusCode: 200, Body: []byte("<html><title>Uploads</title></html>")}); ok {
		t.Error("a normal page was taken for a listing")
	}
}

func TestParseMethodResponse(t *testing.T) {
	mr, err := parseMethodResponse([]byte(listMethodsResponse))
	if err != nil || len(mr.Values) != 4 || mr.Values[2].str() != "pingback.ping" {
		t.Errorf("methods = %+v, %v", mr, err)
	}
	fault := `<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>405</int></value></member>
<member><name>faultString</name><value><string>XML-RPC services are disabled on this site.</string></value></member>
</struct></value></fault></methodResponse>`
	mr, err = parseMethodResponse([]byte(fault))
	if err != nil || mr.Fault == nil || mr.Fault.Members[1].Value.str() != "XML-RPC services are disabled on this site." {
		t.Errorf("fault = %+v, %v", mr, err)
	}
}

func TestNormalizeBase(t *testing.T) {
	tests := map[string]string{
		"https://example.com":                "https://example.com/",
		"https://example.com/blog?x=1#top":   "https://example.com/blog/",
		"https://example.com/blog/index.php": "https://example.com/blog/",
	}
	for in, want := range tests {
		u, _ := url.Parse(in)
		if got := normalizeBase(u).String(); got != want {
			t.Errorf("normalizeBase(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestFeedVersion(t *testing.T) {
	feeds := map[string]string{
		"/feed/":      rssFeed,
		"/feed/atom/": `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><generator uri="https://wordpress.org/" version="6.4.2">WordPress</generator></feed>`,
		"/feed/rdf/":  `<?xml version="1.0"?><rdf:RDF xmlns:admin="http://webns.net/mvcb/"><channel><admin:generatorAgent rdf:resource="https://wordpress.org/?v=6.4.2" /></channel></rdf:RDF>`,
	}
	f := newFakeWP(t)
	for p, body := range feeds {
		f.routes[p] = respond(200, "application/xml", body)
	}
	s := testScanner(t, "")
	s.client.AddScope("127.0.0.1")
	for p, kind := range map[string]string{"/feed/": "RSS", "/feed/atom/": "Atom", "/feed/rdf/": "RDF"} {
		got := s.feedVersion(t.Context(), f.srv.URL+p, modeAggressive)
		if len(got) != 1 || got[0].Value != "6.4.2" || got[0].Method != kind+" feed generator" {
			t.Errorf("%s: %+v", p, got)
		}
	}
}
