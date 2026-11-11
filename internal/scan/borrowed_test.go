package scan

import (
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

// TestVersionFromAnotherPluginsFolder is TheGem on a real site: its
// plugin loads a file from its inc/elementor/ folder with Elementor's
// version (ELEMENTOR_VERSION) and another with no version, so WordPress
// adds its own. Neither is TheGem Elements' version.
func TestVersionFromAnotherPluginsFolder(t *testing.T) {
	for _, pro := range []string{"4.3.3", "4.3.5"} { // as on the site; then the same as Elementor's, as often
		f := newFakeWP(t).addBaseSite()
		f.routes["/"] = respond(200, "text/html", `<html><head>
<meta name="generator" content="WordPress 6.4.2" />
<meta name="generator" content="Elementor 4.3.5; features: e_font_icon_svg; settings: css_print_method-external" />
<link rel="stylesheet" href="{{URL}}wp-content/plugins/elementor/assets/css/frontend.min.css?ver=4.3.5" />
<link rel="stylesheet" href="{{URL}}wp-content/plugins/elementor-pro/assets/css/frontend.min.css?ver=`+pro+`" />
<link rel="stylesheet" href="{{URL}}wp-content/plugins/thegem-elements-elementor/inc/heading-animation/assets/css/main.css?ver=6.4.2" />
<link rel="stylesheet" href="{{URL}}wp-content/plugins/thegem-elements-elementor/inc/elementor/assets/css/frontend-legacy.min.css?ver=4.3.5" />
<link rel="stylesheet" href="{{URL}}wp-content/themes/thegem-elementor/style.css?ver=5.13.1" />
</head><body></body></html>`)
		r := runScan(t, options(f.URL(), cli.ModePassive))

		gem := pluginBySlug(r, "thegem-elements-elementor")
		if gem == nil {
			t.Fatalf("Elementor Pro %s: thegem-elements-elementor not found: %+v", pro, r.Plugins)
		}
		if gem.Version != nil && gem.Version.Number != "" {
			t.Errorf("Elementor Pro %s: thegem-elements-elementor version = %s; the ?ver= of its inc/elementor/ file is Elementor's", pro, gem.Version.Number)
		}
		if el := pluginBySlug(r, "elementor"); el == nil || el.Version.Number != "4.3.5" {
			t.Errorf("Elementor Pro %s: elementor = %+v", pro, el)
		}
		if p := pluginBySlug(r, "elementor-pro"); p == nil || p.Version.Number != pro {
			t.Errorf("Elementor Pro %s: elementor-pro version = %+v", pro, p.Version)
		}
	}
}

func TestInOtherPluginsFolder(t *testing.T) {
	others := map[string]bool{"elementor": true, "woocommerce": true, "thegem-elements-elementor": true, "elementor-pro": true}
	for _, tc := range []struct {
		path, slug string
		want       bool
	}{
		{"/wp-content/plugins/thegem-elements-elementor/inc/elementor/assets/css/frontend-legacy.min.css", "thegem-elements-elementor", true},
		{"/wp-content/plugins/thegem-elements-elementor/inc/heading-animation/assets/css/main.css", "thegem-elements-elementor", false},
		{"/wp-content/plugins/elementor-pro/modules/woocommerce/assets/x.js", "elementor-pro", true},
		{"/wp-content/plugins/elementor-pro/assets/css/frontend.min.css", "elementor-pro", false},
		{"/wp-content/plugins/elementor/assets/css/elementor.css", "elementor", false}, // a file named like a plugin is not a folder
		{"/wp-content/plugins/elementor/elementor/x.css", "elementor", false},          // its own name
		{"/wp-content/plugins/Elementor-Pro/modules/WooCommerce/x.js", "elementor-pro", true},
	} {
		if got := inOtherPluginsFolder(tc.path, tc.slug, others); got != tc.want {
			t.Errorf("inOtherPluginsFolder(%s, %s) = %v, want %v", tc.path, tc.slug, got, tc.want)
		}
	}
}
