package wordlists

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuiltin(t *testing.T) {
	l := Builtin()
	if len(l.PopularPlugins) < 500 || len(l.PopularThemes) < 150 {
		t.Errorf("built-in lists are too short: %d plugins, %d themes", len(l.PopularPlugins), len(l.PopularThemes))
	}
	for _, s := range []string{"contact-form-7", "wordpress-seo", "duplicator", "akismet", "LayerSlider", "revslider"} {
		if !slices.Contains(l.PopularPlugins, s) {
			t.Errorf("popular plugins lack %s", s)
		}
	}
	for _, s := range []string{"twentytwenty", "astra", "Divi"} {
		if !slices.Contains(l.PopularThemes, s) {
			t.Errorf("popular themes lack %s", s)
		}
	}
	for _, list := range [][]string{l.PopularPlugins, l.PopularThemes} {
		seen := map[string]bool{}
		for _, s := range list {
			if strings.ContainsAny(s, " /\t") {
				t.Errorf("bad slug %q", s)
			}
			if k := strings.ToLower(s); seen[k] {
				t.Errorf("duplicate slug %q", s)
			} else {
				seen[k] = true
			}
		}
	}
	if !l.Known(Plugins, "layerslider") || l.Known(Plugins, "no-such-plugin-xyz") {
		t.Error("Known is wrong")
	}
	if l.Latest(Plugins, "contact-form-7") != "" {
		t.Error("the built-in lists have no versions")
	}
}

func TestLoadPrefersDownloadedData(t *testing.T) {
	dir := t.TempDir()
	if l, err := Load(dir); err != nil || l.AllPlugins != nil || !l.UpdatedAt.IsZero() {
		t.Fatalf("empty dir: %v %+v", err, l)
	}
	w := &WPOrg{
		UpdatedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		Plugins:   []Item{{Slug: "new-popular", Version: "2.0"}, {Slug: "contact-form-7", Version: "6.1"}},
		Themes:    []Item{{Slug: "astra", Version: "4.8"}},
	}
	if err := WriteWPOrg(filepath.Join(dir, WPOrgFile), w); err != nil {
		t.Fatal(err)
	}
	if err := WriteSlugs(filepath.Join(dir, AllPluginsFile), []string{"a", "b", "obscure-plugin"}); err != nil {
		t.Fatal(err)
	}
	l, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l.PopularPlugins[0] != "new-popular" || l.PopularPlugins[1] != "contact-form-7" {
		t.Errorf("popular plugins = %v", l.PopularPlugins[:3])
	}
	if !slices.Contains(l.PopularPlugins, "LayerSlider") {
		t.Error("premium plugins must stay in the popular list")
	}
	if l.Latest(Plugins, "contact-form-7") != "6.1" || l.Latest(Themes, "astra") != "4.8" {
		t.Error("latest versions not loaded")
	}
	if !slices.Equal(l.AllPlugins, []string{"a", "b", "obscure-plugin"}) || !l.Known(Plugins, "obscure-plugin") || l.AllThemes != nil {
		t.Errorf("all plugins = %v, themes = %v", l.AllPlugins, l.AllThemes)
	}
	if !l.UpdatedAt.Equal(w.UpdatedAt) {
		t.Errorf("updated at = %v", l.UpdatedAt)
	}

	os.WriteFile(filepath.Join(dir, AllThemesFile), []byte("broken"), 0o644)
	if _, err := Load(dir); err == nil {
		t.Error("a broken file should be reported")
	}
}

func TestNamespacePlugin(t *testing.T) {
	tests := []struct {
		ns, slug string
		known    bool
		prefix   string
	}{
		{"yoast/v1", "wordpress-seo", true, ""},
		{"contact-form-7/v1", "contact-form-7", true, ""},
		{"wc/store/v1", "woocommerce", true, ""},
		{"tribe/tickets/v1", "event-tickets", true, ""},
		{"tribe/events/v1", "the-events-calendar", true, ""},
		{"wp/v2", "", false, ""},
		{"oembed/1.0", "", false, ""},
		{"some-plugin/v2", "", false, "some-plugin"},
	}
	for _, tt := range tests {
		slug, known, prefix := NamespacePlugin(tt.ns)
		if slug != tt.slug || known != tt.known || prefix != tt.prefix {
			t.Errorf("NamespacePlugin(%q) = %q, %v, %q", tt.ns, slug, known, prefix)
		}
	}
}

func TestSignatures(t *testing.T) {
	tests := []struct {
		slug, kind, input, version string
	}{
		{"wordpress-seo", SigHTML, `<!-- This site is optimized with the Yoast SEO plugin v15.0 - https://yoast.com/wordpress/plugins/seo/ -->`, "15.0"},
		{"all-in-one-seo-pack", SigHTML, `<!-- All in One SEO 4.1.5.3 - aioseo.com -->`, "4.1.5.3"},
		{"all-in-one-seo-pack", SigHTML, `<!-- All in One SEO Pack 3.2.10 by Michael Torbert -->`, "3.2.10"},
		{"elementor", SigGenerator, `Elementor 3.5.0; features: e_dom_optimization; settings: css_print_method-external`, "3.5.0"},
		{"elementor", SigHTML, `var elementorFrontendConfig = {"environmentMode":{"edit":false},"is_rtl":false,"version":"3.18.2","is_static":false};`, "3.18.2"},
		{"woocommerce", SigGenerator, `WooCommerce 8.2.1`, "8.2.1"},
		{"revslider", SigGenerator, `Powered by Slider Revolution 6.5.11 - responsive, Mobile-Friendly Slider Plugin for WordPress with comfortable drag and drop interface.`, "6.5.11"},
		{"litespeed-cache", SigHTML, `<!-- Page cached by LiteSpeed Cache 4.4.1 on 2021-12-08 14:18:48 -->`, "4.4.1"},
		{"w3-total-cache", SigHeader, `W3 Total Cache/0.9.7.5`, "0.9.7.5"},
		{"autoptimize", SigPath, `cache/autoptimize/css/autoptimize_abc.css`, ""},
		{"sitepress-multilingual-cms", SigGenerator, `WPML ver:4.4.12 stt:1,4;`, "4.4.12"},
		{"nextgen-gallery", SigHTML, `<!-- <meta name="NextGEN" version="3.5.0" /> -->`, "3.5.0"},
	}
	for _, tt := range tests {
		found := false
		for _, s := range PluginSignatures {
			if s.Slug != tt.slug || s.Kind != tt.kind {
				continue
			}
			m := s.Re.FindStringSubmatch(tt.input)
			if m == nil {
				continue
			}
			found = true
			got := ""
			if len(m) > 1 {
				got = m[1]
			}
			if got != tt.version {
				t.Errorf("%s: version %q, want %q", tt.slug, got, tt.version)
			}
			break
		}
		if !found {
			t.Errorf("%s: no %s signature matched %q", tt.slug, tt.kind, tt.input)
		}
	}
	for _, s := range PluginSignatures {
		if s.Slug == "" || s.Method == "" || s.Confidence <= 0 || s.Confidence > 100 || (s.Kind == SigHeader && s.Header == "") {
			t.Errorf("incomplete signature %+v", s)
		}
	}
}
