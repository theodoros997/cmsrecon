package wordlists

// postTypePlugins maps public post types and taxonomies that only one
// plugin registers to that plugin. Sitemaps list them, so they reveal
// plugins whose pages the crawl did not visit. Generic names such as
// "event", "course" or "portfolio", which many plugins and themes use,
// are left out.
var postTypePlugins = map[string]string{
	"product":            "woocommerce",
	"product_cat":        "woocommerce",
	"product_tag":        "woocommerce",
	"product_brand":      "woocommerce",
	"download":           "easy-digital-downloads",
	"download_category":  "easy-digital-downloads",
	"dlm_download":       "download-monitor",
	"wpdmpro":            "download-manager",
	"tribe_events":       "the-events-calendar",
	"tribe_venue":        "the-events-calendar",
	"tribe_organizer":    "the-events-calendar",
	"tribe_events_cat":   "the-events-calendar",
	"mec-events":         "modern-events-calendar-lite",
	"ai1ec_event":        "all-in-one-event-calendar",
	"job_listing":        "wp-job-manager",
	"job_listing_type":   "wp-job-manager",
	"lp_course":          "learnpress",
	"sfwd-courses":       "sfwd-lms",
	"sfwd-lessons":       "sfwd-lms",
	"give_forms":         "give",
	"forum":              "bbpress",
	"topic":              "bbpress",
	"wpsl_stores":        "wp-store-locator",
	"pwb-brand":          "perfect-woocommerce-brands",
	"envira":             "envira-gallery-lite",
	"foogallery":         "foogallery",
	"wpcf7_contact_form": "contact-form-7",
}

// PostTypePlugin returns the plugin that registers a post type or
// taxonomy, or "".
func PostTypePlugin(name string) string {
	return postTypePlugins[name]
}
