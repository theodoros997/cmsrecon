package scan

import (
	"slices"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

// page builds a minimal WordPress page from head markup.
func wpPage(head string) string {
	return `<!DOCTYPE html><html><head><title>Lab</title>` + head + `</head><body class="home blog"></body></html>`
}

func TestBedrockCoreRoot(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", wpPage(`<link rel='stylesheet' href='{{URL}}app/themes/lab/style.css?ver=1.0' />
<script src='{{URL}}wp/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>
<script src='{{URL}}wp/wp-includes/js/wp-embed.min.js?ver=6.4.2'></script>`))
	f.routes["/wp/wp-includes/version.php"] = respond(200, "text/plain", "<?php\n$wp_version = '6.4.2';\n")
	f.routes["/wp/readme.html"] = respond(200, "text/html", `<title>WordPress &#8250; ReadMe</title><h1 id="logo"></h1>`)
	r := runScan(t, options(f.URL(), cli.ModeMixed))
	if r.Version == nil || r.Version.Number != "6.4.2" || !slices.Contains(methods(r.Version.Evidence), "wp-includes/version.php source") {
		t.Errorf("version = %+v (%v)", r.Version, methods(r.Version.Evidence))
	}
	if findingByID(r, idReadme) == nil {
		t.Errorf("readme under /wp/ not found: %v", findingIDs(r))
	}
}

func TestCDNAndJetpackURLs(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", wpPage(`<link rel='stylesheet' href='https://site1234.b-cdn.net/wp-content/themes/astra/style.css?ver=4.6.1' />
<script src='https://site1234.b-cdn.net/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.0'></script>
<script src='https://c0.wp.com/c/6.4.2/wp-includes/js/dist/hooks.min.js'></script>
<script src='https://c0.wp.com/p/woocommerce/8.2.1/assets/js/frontend/woocommerce.min.js'></script>
<meta name="generator" content="WordPress 6.4.2" />`))
	f.routes["/wp-content/themes/astra/style.css"] = respond(200, "text/css", "/*\nTheme Name: Astra\nVersion: 4.6.1\n*/")
	r := runScan(t, options(f.URL(), cli.ModePassive))
	if r.MainTheme == nil || r.MainTheme.Slug != "astra" {
		t.Errorf("main theme from a CDN = %+v", r.MainTheme)
	}
	if p := pluginBySlug(r, "elementor"); p == nil || p.Version.Number != "3.18.0" {
		t.Errorf("elementor from a CDN = %+v", p)
	}
	if p := pluginBySlug(r, "woocommerce"); p == nil || p.Version.Number != "8.2.1" {
		t.Errorf("woocommerce from Jetpack's CDN = %+v", p)
	}
	if !slices.ContainsFunc(r.Version.Evidence, func(e Evidence) bool { return e.Value == "6.4.2" && strings.Contains(e.Method, "core assets") }) {
		t.Errorf("core ?ver= from Jetpack's /c/6.4.2/ = %v", r.Version.Evidence)
	}
}

func TestJSLibraryCopies(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", wpPage(`<script src='{{URL}}wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>
<script src='{{URL}}wp-includes/js/jquery/jquery.js?ver=3.7.1'></script>
<script src='{{URL}}wp-content/plugins/old-slider/js/jquery-1.8.3.min.js'></script>`))
	r := runScan(t, options(f.URL(), cli.ModePassive))
	var jq []string
	for _, l := range r.JSLibraries {
		if l.Name == "jquery" {
			jq = append(jq, l.Version.Number)
			if l.Version.Number == "3.7.1" && !l.Bundled {
				t.Errorf("core's jQuery is not marked as bundled: %+v", l)
			}
		}
	}
	if !slices.Equal(jq, []string{"1.8.3", "3.7.1"}) {
		t.Errorf("jquery copies = %v, want each version once", jq)
	}
}

func TestUsersBehindBlockedREST(t *testing.T) {
	t.Run("rest_route", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		f.routes["/wp-json/wp/v2/users"] = respond(403, "application/json", `{"code":"rest_forbidden"}`)
		f.routes["/?rest_route=%2Fwp%2Fv2%2Fusers&per_page=100&page=1"] = respond(200, "application/json", `[{"id":7,"name":"Dana","slug":"dana"}]`, "X-WP-TotalPages", "1")
		o := options(f.URL(), cli.ModeMixed)
		o.Enumerate = cli.Enumeration{Users: &cli.IDRange{From: 1, To: 1}}
		r := runScan(t, o)
		if len(r.Users) != 1 || r.Users[0].Username != "dana" {
			t.Errorf("users = %+v", r.Users)
		}
	})
	t.Run("posts", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		f.routes["/wp-json/wp/v2/users"] = respond(403, "application/json", `{"code":"rest_forbidden"}`)
		f.routes["/wp-json/wp/v2/posts"] = respond(200, "application/json", `[{"author":9,"_embedded":{"author":[{"id":9,"name":"Erin E.","slug":"erin"}]}}]`)
		o := options(f.URL(), cli.ModeMixed)
		o.Enumerate = cli.Enumeration{Users: &cli.IDRange{From: 1, To: 1}}
		r := runScan(t, o)
		if len(r.Users) != 1 || r.Users[0].Username != "erin" || r.Users[0].ID != 9 {
			t.Errorf("users = %+v", r.Users)
		}
	})
}

func TestCoreVersionFromLoginPage(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", wpPage(`<link rel='stylesheet' href='{{URL}}wp-content/themes/lab-child/style.css' />`))
	f.routes["/feed/"] = respond(404, "text/html", "nope")
	f.routes["/wp-login.php"] = respond(200, "text/html", `<link rel='stylesheet' href='{{URL}}wp-admin/load-styles.php?c=0&amp;dir=ltr&amp;load%5Bchunk_0%5D=dashicons,buttons,forms,l10n,login&amp;ver=6.4.2' />
<form name="loginform" id="loginform" action="wp-login.php" method="post">`)
	r := runScan(t, options(f.URL(), cli.ModeMixed))
	if r.Version == nil || r.Version.Number != "6.4.2" {
		t.Errorf("version = %+v", r.Version)
	}
}

func TestSharedVerIsNotAPluginVersion(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", wpPage(`<link rel='stylesheet' href='{{URL}}wp-content/plugins/one/a.css?ver=6.4.2' />
<link rel='stylesheet' href='{{URL}}wp-content/plugins/two/b.css?ver=6.4.2' />
<link rel='stylesheet' href='{{URL}}wp-content/plugins/three/c.css?ver=6.4.2' />
<link rel='stylesheet' href='{{URL}}wp-content/plugins/four/d.css?ver=2.1.0' />`))
	r := runScan(t, options(f.URL(), cli.ModePassive))
	for _, slug := range []string{"one", "two", "three"} {
		if p := pluginBySlug(r, slug); p == nil || p.Version.Number != "" {
			t.Errorf("%s = %+v: a ?ver= three plugins share is not theirs", slug, p)
		}
	}
	if p := pluginBySlug(r, "four"); p == nil || p.Version.Number != "2.1.0" {
		t.Errorf("four = %+v", p)
	}
}

func TestCombinedCSS(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", wpPage(`<link rel='stylesheet' href='{{URL}}wp-content/cache/autoptimize/css/autoptimize_0a1b2c.css' />`))
	f.routes["/wp-content/cache/autoptimize/css/autoptimize_0a1b2c.css"] = respond(200, "text/css",
		`.wpcf7{background:url(/wp-content/plugins/contact-form-7/images/ajax-loader.gif)}`+
			`.x{background:url("\/wp-content\/plugins\/wpforms-lite\/assets\/x.png")}.t{src:url(/wp-content/themes/astra/fonts/a.woff)}`)
	r := runScan(t, options(f.URL(), cli.ModeMixed))
	for _, slug := range []string{"contact-form-7", "wpforms-lite"} {
		if p := pluginBySlug(r, slug); p == nil || !slices.Contains(methods(p.Evidence), "Paths in a combined CSS or JS file") {
			t.Errorf("%s from the combined CSS = %+v", slug, p)
		}
	}
	if themeBySlug(r.Themes, "astra") == nil {
		t.Errorf("astra from the combined CSS: themes %+v", r.Themes)
	}
}

func TestChangelogFormats(t *testing.T) {
	for text, want := range map[string]string{
		"= 5.3.1 =\n* Fix\n= 5.3 =":                      "5.3.1",
		"**2.3.1**\n* Fix\n**2.3.0**":                    "2.3.1",
		"2023-11-02 - version 5.6.0\n2023-10-01 - 5.5.9": "5.6.0",
		"## [1.4.2] - 2024-01-01\n## [1.4.1]":            "1.4.2",
		"#### 3.0 (2024-01-01)\n#### 2.9":                "3.0",
	} {
		if got := newestVersion(text); got != want {
			t.Errorf("newestVersion(%q) = %q, want %q", text, got, want)
		}
	}
}
