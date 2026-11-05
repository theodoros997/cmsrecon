package scan

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

func fakeSlugs(n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("made-up-plugin-%d", i))
	}
	return out
}

func pluginSlugs(r *Result) []string {
	var out []string
	for _, p := range r.Plugins {
		out = append(out, p.Slug)
	}
	return out
}

func TestRateLimitedProbesAreNotFound(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	limited := respond(429, "text/html", "Too many requests", "Retry-After", "0")
	fallback := f.fallback
	f.fallback = func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/made-up-plugin-") {
			limited(w, r)
			return
		}
		fallback(w, r)
	}
	o := options(f.URL(), cli.ModeMixed)
	o.PluginsList = fakeSlugs(10)
	r := runScan(t, o)
	for _, p := range r.Plugins {
		if strings.HasPrefix(p.Slug, "made-up-plugin-") {
			t.Errorf("a rate-limited path was reported as a plugin: %s (%v)", p.Slug, methods(p.Evidence))
		}
	}
	if r.Stats.Blocked == 0 || !slices.ContainsFunc(r.Notices, func(n string) bool { return strings.Contains(n, "rate limit") }) {
		t.Errorf("blocked = %d, notices = %q", r.Stats.Blocked, r.Notices)
	}
}

func TestFailingTargetStopsTheScan(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	var n atomic.Int32
	inner := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fine for pre-flight, then down for good.
		if n.Add(1) > 12 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	})
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = fullEnumeration()
	rec := &recorder{ended: map[string]string{}}
	r := runScanWith(t, o, rec)
	if r.Status != StatusBlocked {
		t.Fatalf("status = %q, want blocked", r.Status)
	}
	if !slices.ContainsFunc(r.Notices, func(n string) bool {
		return strings.Contains(n, "kept failing or refusing") && strings.Contains(n, "--throttle")
	}) {
		t.Errorf("notices = %q", r.Notices)
	}
	for _, step := range []string{stepPlugins, stepUsers} {
		if res := rec.ended[step]; !strings.Contains(res, "cut short") {
			t.Errorf("%s ended with %q, want cut short", step, res)
		}
	}
	if reqs := n.Load(); reqs > 200 {
		t.Errorf("%d requests to a dead site; the breaker should stop much sooner", reqs)
	}
}

func TestHeadAndGetDisagree(t *testing.T) {
	// A firewall that answers HEAD with 403 everywhere, while GET gets
	// the usual 404 page.
	f := newFakeWP(t).addComponentSite()
	fallback := f.fallback
	f.fallback = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/wp-content/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fallback(w, r)
	}
	o := options(f.URL(), cli.ModeMixed)
	o.PluginsList = fakeSlugs(10)
	r := runScan(t, o)
	for _, p := range r.Plugins {
		if strings.HasPrefix(p.Slug, "made-up-plugin-") {
			t.Fatalf("plugins = %v: a HEAD 403 that every path gets is not a hit", pluginSlugs(r))
		}
	}
}

func TestBlockedHomepage(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"rate limit": respond(429, "text/html", "slow down", "Retry-After", "0"),
		"cloudflare": respond(403, "text/html", "<title>Just a moment...</title>", "Cf-Mitigated", "challenge"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeWP(t)
			f.routes["/"] = h
			r := runScan(t, options(f.URL(), cli.ModeMixed))
			if r.Stop == nil || r.Stop.Code != StopBlocked || r.Stop.Hint == "" {
				t.Fatalf("stop = %+v, want blocked with a hint", r.Stop)
			}
			if strings.Contains(r.Stop.Message, "does not look like WordPress") {
				t.Errorf("a refusal is not a reason to call the site something else: %q", r.Stop.Message)
			}
		})
	}
}

func TestCatchAllBruteForceIsDropped(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	fallback := f.fallback
	var n atomic.Int32
	f.fallback = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/wp-content/plugins/") && strings.HasSuffix(r.URL.Path, "/") {
			// A different page every time, so no baseline matches. Letters,
			// not digits: the comparison ignores numbers.
			var b strings.Builder
			for i := n.Add(1); i > 0; i /= 20 {
				b.WriteByte(byte('g' + i%20))
			}
			respond(200, "text/html", "<html><body>"+strings.Repeat(b.String()+"\n", 40)+"</body></html>")(w, r)
			return
		}
		fallback(w, r)
	}
	o := options(f.URL(), cli.ModeMixed)
	o.PluginsList = fakeSlugs(40)
	r := runScan(t, o)
	for _, p := range r.Plugins {
		if strings.HasPrefix(p.Slug, "made-up-plugin-") {
			t.Fatalf("plugins = %v", pluginSlugs(r))
		}
	}
	if !slices.ContainsFunc(r.Notices, func(n string) bool { return strings.Contains(n, "no real site has") }) {
		t.Errorf("notices = %q", r.Notices)
	}
}

func TestFalsePositives(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	home := strings.Replace(pluginHomepage, "</head>", `<link rel="alternate" type="application/rss+xml" title="Lab &raquo; Comments Feed" href="{{URL}}comments/feed/" />
<script>var wpforms_settings = {"val": 1};</script>
</head>`, 1)
	home = strings.Replace(home, `<a href="{{URL}}author/alice/">Alice Author</a>`, `<a href="{{URL}}author/alice/">Alice Author</a> <a href="{{URL}}author/carol/">carol</a>`, 1)
	f.routes["/"] = respond(200, "text/html; charset=UTF-8", home, "Link", `<{{URL}}wp-json/>; rel="https://api.w.org/"`)
	f.routes["/comments/feed/"] = respond(200, "application/rss+xml", `<?xml version="1.0"?><rss xmlns:dc="http://purl.org/dc/elements/1.1/"><channel>
<item><dc:creator><![CDATA[A WordPress Commenter]]></dc:creator></item></channel></rss>`)
	f.routes["/feed/"] = respond(200, "application/rss+xml", `<?xml version="1.0"?><rss xmlns:dc="http://purl.org/dc/elements/1.1/"><channel>
<item><dc:creator><![CDATA[Alice Author]]></dc:creator></item><item><dc:creator><![CDATA[carol]]></dc:creator></item></channel></rss>`)
	// "404 to homepage": every attachment ID redirects home.
	for id := 1; id <= 5; id++ {
		f.routes[fmt.Sprintf("/?attachment_id=%d", id)] = redirect(301, strings.TrimSuffix("{{URL}}", "/"))
	}
	f.routes["/?attachment_id=2147483646"] = redirect(301, strings.TrimSuffix("{{URL}}", "/"))
	f.routes["/wp-json/wp/v2/media"] = respond(401, "application/json", `{"code":"rest_forbidden"}`)
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = cli.Enumeration{Users: &cli.IDRange{From: 1, To: 2}, Media: &cli.IDRange{From: 1, To: 5}}
	r := runScan(t, o)

	for _, u := range r.Users {
		if u.DisplayName == "A WordPress Commenter" {
			t.Errorf("a comment author was reported as a user: %+v", u)
		}
	}
	carols := 0
	for _, u := range r.Users {
		if strings.EqualFold(u.Username, "carol") || strings.EqualFold(u.DisplayName, "carol") {
			carols++
		}
	}
	if carols != 1 {
		t.Errorf("carol appears %d times: the feed's display name is the same user", carols)
	}
	if len(r.Media) != 0 {
		t.Errorf("redirects home are not media: %+v", r.Media)
	}
	if pluginBySlug(r, "wpforms-lite") != nil {
		t.Errorf("a weak signature whose folder is missing was reported: %v", pluginSlugs(r))
	}
}

func TestWeakSignatureKeptWhenFolderExists(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	home := strings.Replace(pluginHomepage, "</head>", `<script>var wpforms_settings = {"val": 1};</script></head>`, 1)
	f.routes["/"] = respond(200, "text/html; charset=UTF-8", home, "Link", `<{{URL}}wp-json/>; rel="https://api.w.org/"`)
	f.routes["/wp-content/plugins/wpforms-lite/"] = respond(403, "text/html", "<h1>Forbidden</h1>")
	r := runScan(t, options(f.URL(), cli.ModeMixed))
	if pluginBySlug(r, "wpforms-lite") == nil {
		t.Errorf("plugins = %v: a weak signature whose folder answers stays", pluginSlugs(r))
	}
}
