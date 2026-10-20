package scan

import (
	"slices"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

// Tests of the features that follow WPScan: named plugin and theme lists,
// custom folders, per-item checks and version banners.

func TestNamedLists(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	o := options(f.URL(), cli.ModeMixed)
	o.DataDir = writeData(t)
	// The named list replaces -e ap, even with brute force on.
	o.Enumerate = cli.Enumeration{Plugins: cli.ItemsAll, Themes: cli.ItemsAll}
	o.PluginsDetection, o.ThemesDetection = cli.ModeMixed, cli.ModeMixed
	o.PluginsList = []string{"duplicator", "not-there"}
	o.ThemesList = []string{"twentynineteen"}
	r := runScan(t, o)

	if dup := pluginBySlug(r, "duplicator"); dup == nil || dup.Version.Number != "1.3.26" {
		t.Errorf("duplicator (named) = %+v", dup)
	}
	if pluginBySlug(r, "not-there") != nil {
		t.Error("a named plugin that is not installed was reported")
	}
	if themeBySlug(r.Themes, "twentynineteen") == nil {
		t.Errorf("twentynineteen (named) not found: %+v", r.Themes)
	}
	var folders []string
	for _, req := range f.requested() {
		if strings.HasPrefix(req, "HEAD ") && strings.HasSuffix(req, "/") {
			folders = append(folders, strings.TrimPrefix(req, "HEAD "))
		}
	}
	slices.Sort(folders)
	want := []string{"/wp-content/plugins/duplicator/", "/wp-content/plugins/not-there/", "/wp-content/themes/twentynineteen/"}
	if !slices.Equal(folders, want) {
		t.Errorf("folders probed = %v, want only the named ones %v", folders, want)
	}
}

func TestCustomPluginsDir(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/lib/ext/hidden-plugin/"] = respond(200, "text/html", "")
	f.routes["/lib/ext/hidden-plugin/readme.txt"] = respond(200, "text/plain", readme("Hidden Plugin", "2.0.1"))
	f.routes["/wp-content/plugins/hidden-plugin/"] = respond(200, "text/html", "")
	o := options(f.URL(), cli.ModeMixed)
	o.PluginsDir = "lib/ext"
	o.PluginsList = []string{"hidden-plugin"}
	r := runScan(t, o)

	hp := pluginBySlug(r, "hidden-plugin")
	if hp == nil || hp.Location != f.URL()+"lib/ext/hidden-plugin/" || hp.Version.Number != "2.0.1" {
		t.Fatalf("hidden-plugin = %+v", hp)
	}
	for _, req := range f.requested() {
		if strings.Contains(req, "/wp-content/plugins/hidden-plugin") {
			t.Errorf("checked the default folder despite --wp-plugins-dir: %s", req)
		}
	}
}

func TestItemChecks(t *testing.T) {
	site := func(t *testing.T) *fakeWP {
		f := newFakeWP(t).addComponentSite()
		f.routes["/wp-content/plugins/contact-form-7/"] = respond(200, "text/html",
			`<html><head><title>Index of /wp-content/plugins/contact-form-7</title></head><body><h1>Index of /wp-content/plugins/contact-form-7</h1><a href="/wp-content/plugins/">Parent Directory</a><a href="includes/">includes/</a><a href="readme.txt">readme.txt</a></body></html>`)
		f.routes["/wp-content/plugins/contact-form-7/error_log"] = respond(200, "text/plain",
			"[20-Oct-2026 10:00:00 UTC] PHP Warning:  Undefined variable $x in /home/lab/public_html/wp-content/plugins/contact-form-7/includes/a.php on line 9\n")
		// A soft 200 for error_log is not a log.
		f.routes["/wp-content/themes/twentytwenty/error_log"] = respond(200, "text/html", "<html><body>Home</body></html>")
		return f
	}

	t.Run("mixed", func(t *testing.T) {
		f := site(t)
		o := options(f.URL(), cli.ModeMixed)
		o.DataDir = writeData(t)
		r := runScan(t, o)
		cf7 := pluginBySlug(r, "contact-form-7")
		if cf7 == nil {
			t.Fatal("contact-form-7 not found")
		}
		if cf7.LastUpdated != "2026-09-30" {
			t.Errorf("last updated = %q", cf7.LastUpdated)
		}
		joined := strings.Join(cf7.Warnings, "\n")
		for _, want := range []string{
			"Directory listing is enabled: " + f.URL() + "wp-content/plugins/contact-form-7/ (2 entries)",
			"A PHP error log is exposed: " + f.URL() + "wp-content/plugins/contact-form-7/error_log",
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("warnings miss %q: %q", want, cf7.Warnings)
			}
		}
		if ys := pluginBySlug(r, "wordpress-seo"); ys == nil || !slices.Contains(ys.Warnings, "Not updated on WordPress.org since 2020-05-01: it may be abandoned") {
			t.Errorf("wordpress-seo (last updated 2020) = %+v", ys)
		}
		if r.MainTheme == nil || len(r.MainTheme.Warnings) != 0 {
			t.Errorf("main theme warnings = %+v", r.MainTheme)
		}
	})

	t.Run("passive sends nothing more", func(t *testing.T) {
		f := site(t)
		o := options(f.URL(), cli.ModePassive)
		o.DataDir = writeData(t)
		r := runScan(t, o)
		for _, req := range f.requested() {
			if strings.Contains(req, "error_log") || strings.HasSuffix(req, "/contact-form-7/") {
				t.Errorf("passive mode requested %s", req)
			}
		}
		if cf7 := pluginBySlug(r, "contact-form-7"); cf7 == nil || cf7.LastUpdated != "2026-09-30" || len(cf7.Warnings) != 0 {
			t.Errorf("contact-form-7 = %+v", cf7)
		}
	})
}

func TestBannerVersion(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	home := strings.Replace(pluginHomepage, "</head>", `<script src='{{URL}}wp-content/plugins/elementor/assets/js/frontend.min.js'></script>
<script src='{{URL}}wp-content/plugins/fancy-gallery/js/bundle.js'></script>
<link rel='stylesheet' href='{{URL}}wp-content/plugins/old-slider/css/slider.css' />
</head>`, 1)
	f.routes["/"] = respond(200, "text/html; charset=UTF-8", home, "Link", `<{{URL}}wp-json/>; rel="https://api.w.org/"`)
	f.routes["/wp-content/plugins/elementor/assets/js/frontend.min.js"] = respond(200, "application/javascript",
		"/*! elementor - v3.5.0 - 10-01-2022 */\n!function(){}();")
	// The banner of a bundled library is not the plugin's version.
	f.routes["/wp-content/plugins/fancy-gallery/js/bundle.js"] = respond(200, "application/javascript",
		"/*! jQuery Migrate v3.3.2 | (c) OpenJS Foundation */\n!function(){}();")
	// A banner further down the file is not the file's banner.
	f.routes["/wp-content/plugins/old-slider/css/slider.css"] = respond(200, "text/css",
		".a{}\n"+strings.Repeat(".b{color:red}\n", 30)+"/* old-slider v9.9 */")
	o := options(f.URL(), cli.ModeMixed)
	r := runScan(t, o)

	el := pluginBySlug(r, "elementor")
	if el == nil || el.Version.Number != "3.5.0" || !slices.Contains(methods(el.Version.Evidence), "Version banner in the plugin's file") {
		t.Errorf("elementor = %+v", el)
	}
	if fg := pluginBySlug(r, "fancy-gallery"); fg == nil || fg.Version.Number != "" {
		t.Errorf("fancy-gallery must have no version: %+v", fg)
	}
	if os := pluginBySlug(r, "old-slider"); os == nil || os.Version.Number != "" {
		t.Errorf("old-slider must have no version: %+v", os)
	}
}
