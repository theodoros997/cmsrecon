package wordlists

import "strings"

// restNamespaces maps REST API namespaces (the part before the version,
// e.g. "yoast" in "yoast/v1") to the plugin that registers them. A few
// plugins register a namespace with two segments, such as "tribe/events".
var restNamespaces = map[string]string{
	"akismet":                 "akismet",
	"aioseo":                  "all-in-one-seo-pack",
	"amp":                     "amp",
	"borlabs-cookie":          "borlabs-cookie",
	"buddypress":              "buddypress",
	"burst":                   "burst-statistics",
	"cocart":                  "cart-rest-api-for-woocommerce",
	"code-snippets":           "code-snippets",
	"complianz":               "complianz-gdpr",
	"contact-form-7":          "contact-form-7",
	"dokan":                   "dokan-lite",
	"duplicate-post":          "duplicate-post",
	"elementor":               "elementor",
	"elementor-pro":           "elementor-pro",
	"elementskit":             "elementskit-lite",
	"fluent-crm":              "fluent-crm",
	"fluentform":              "fluentform",
	"forminator":              "forminator",
	"frm":                     "formidable",
	"generateblocks":          "generateblocks",
	"gf":                      "gravityforms",
	"give-api":                "give",
	"google-site-kit":         "google-site-kit",
	"ithemes-security":        "better-wp-security",
	"jetpack":                 "jetpack",
	"jetpack-boost":           "jetpack-boost",
	"jwt-auth":                "jwt-authentication-for-wp-rest-api",
	"kadence-blocks":          "kadence-blocks",
	"koko-analytics":          "koko-analytics",
	"learnpress":              "learnpress",
	"litespeed":               "litespeed-cache",
	"llms":                    "lifterlms",
	"mailpoet":                "mailpoet",
	"matomo":                  "matomo",
	"mc4wp":                   "mailchimp-for-wp",
	"metform":                 "metform",
	"monsterinsights":         "google-analytics-for-wordpress",
	"my-jetpack":              "jetpack",
	"newsletter":              "newsletter",
	"nf-submissions":          "ninja-forms",
	"ninja-forms-submissions": "ninja-forms",
	"otter":                   "otter-blocks",
	"pll":                     "polylang",
	"pmpro":                   "paid-memberships-pro",
	"post-views-counter":      "post-views-counter",
	"pum":                     "popup-maker",
	"rankmath":                "seo-by-rank-math",
	"real-cookie-banner":      "real-cookie-banner",
	"redirection":             "redirection",
	"regenerate-thumbnails":   "regenerate-thumbnails",
	"seopress":                "wp-seopress",
	"simple-jwt-login":        "simple-jwt-login",
	"siteground-optimizer":    "sg-cachepress",
	"smush":                   "wp-smushit",
	"stackable":               "stackable-ultimate-gutenberg-blocks",
	"tribe/event-aggregator":  "the-events-calendar",
	"tribe/events":            "the-events-calendar",
	"tribe/tickets":           "event-tickets",
	"tutor":                   "tutor",
	"two-factor":              "two-factor",
	"user-registration":       "user-registration",
	"wc":                      "woocommerce",
	"wc-admin":                "woocommerce",
	"wc-analytics":            "woocommerce",
	"wc-telemetry":            "woocommerce",
	"wccom-site":              "woocommerce",
	"wcfmmp":                  "wc-multivendor-marketplace",
	"wordfence":               "wordfence",
	"wordpress-popular-posts": "wordpress-popular-posts",
	"wp-mail-smtp":            "wp-mail-smtp",
	"wp-recipe-maker":         "wp-recipe-maker",
	"wp-rocket":               "wp-rocket",
	"wp-statistics":           "wp-statistics",
	"wp-super-cache":          "wp-super-cache",
	"wpcom":                   "jetpack",
	"wpforms":                 "wpforms-lite",
	"wpgmza":                  "wp-google-maps",
	"wpml":                    "sitepress-multilingual-cms",
	"wpuf":                    "wp-user-frontend",
	"yoast":                   "wordpress-seo",
}

// coreNamespaces are registered by WordPress itself.
var coreNamespaces = map[string]bool{
	"wp": true, "oembed": true, "wp-site-health": true, "wp-block-editor": true,
	"batch": true, "wp-abilities": true, "wp-abilities-api": true,
}

// NamespacePlugin returns the plugin that registers a REST namespace such
// as "yoast/v1". known reports whether it is a mapped namespace; when it is
// not, the namespace's first segment is returned as a guess (prefix), which
// callers should only trust when it is a known slug. Core namespaces give
// nothing.
func NamespacePlugin(ns string) (slug string, known bool, prefix string) {
	ns = strings.Trim(strings.ToLower(ns), "/")
	parts := strings.Split(ns, "/")
	if len(parts) == 0 || parts[0] == "" || coreNamespaces[parts[0]] {
		return "", false, ""
	}
	if len(parts) >= 2 {
		if s, ok := restNamespaces[parts[0]+"/"+parts[1]]; ok {
			return s, true, ""
		}
	}
	if s, ok := restNamespaces[parts[0]]; ok {
		return s, true, ""
	}
	return "", false, parts[0]
}
