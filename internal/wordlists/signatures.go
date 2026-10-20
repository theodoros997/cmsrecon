package wordlists

import "regexp"

// Where a signature looks.
const (
	SigHTML      = "html"      // the HTML of the homepage and the 404 page
	SigGenerator = "generator" // the content of a <meta name="generator"> tag
	SigHeader    = "header"    // a homepage response header
	SigPath      = "path"      // a URL path below the content directory, e.g. "cache/autoptimize/"
)

// Signature is a passive sign that a plugin is installed. When Re has a
// capture group, it is the plugin's version.
type Signature struct {
	Slug       string
	Kind       string // one of the Sig constants
	Header     string // the header name, for SigHeader
	Re         *regexp.Regexp
	Method     string // how it is described in evidence
	Confidence int    // that the plugin is installed
}

func html(slug, method string, conf int, re string) Signature {
	return Signature{Slug: slug, Kind: SigHTML, Re: regexp.MustCompile(re), Method: method, Confidence: conf}
}

func generator(slug string, re string) Signature {
	return Signature{Slug: slug, Kind: SigGenerator, Re: regexp.MustCompile(re), Method: "Meta generator", Confidence: 100}
}

func header(slug, name string, conf int, re string) Signature {
	return Signature{Slug: slug, Kind: SigHeader, Header: name, Re: regexp.MustCompile(re), Method: name + " header", Confidence: conf}
}

func contentPath(slug string, conf int, re string) Signature {
	return Signature{Slug: slug, Kind: SigPath, Re: regexp.MustCompile(re), Method: "Files it generates", Confidence: conf}
}

// ver is the version capture used in signatures.
const ver = `v?([0-9]+(?:\.[0-9]+)+)`

// PluginSignatures are the passive plugin signatures: HTML comments the
// plugins print, meta generators, JavaScript configuration objects, CSS
// classes specific enough to name one plugin, response headers, and the
// folders caching and builder plugins write their files to. They are
// cmsrecon's own; each was written from the plugin's public output.
var PluginSignatures = []Signature{
	// SEO.
	html("wordpress-seo", "Yoast SEO HTML comment", 100, `This site is optimized with the Yoast (?:WordPress )?SEO plugin `+ver),
	html("wordpress-seo-premium", "Yoast SEO Premium HTML comment", 100, `This site is optimized with the Yoast SEO Premium plugin `+ver),
	html("wordpress-seo", "Yoast schema graph", 90, `class=["']yoast-schema-graph`),
	html("all-in-one-seo-pack", "All in One SEO HTML comment", 100, `<!-- All in One SEO(?: Pack)?(?: Pro)? `+ver),
	html("seo-by-rank-math", "Rank Math HTML comment", 100, `<!-- Search Engine Optimization by Rank Math`),
	html("autodescription", "The SEO Framework HTML comment", 100, `The SEO Framework by Sybre Waaijer`),
	html("breadcrumb-navxt", "Breadcrumb NavXT HTML comment", 100, `<!-- Breadcrumb NavXT `+ver),

	// Analytics and marketing.
	html("google-analytics-for-wordpress", "MonsterInsights HTML comment", 100, `MonsterInsights plugin `+ver),
	html("google-analytics-dashboard-for-wp", "ExactMetrics HTML comment", 100, `ExactMetrics plugin `+ver),
	generator("google-site-kit", `^Site Kit by Google `+ver),
	html("google-site-kit", "Site Kit HTML comment", 100, `snippet added by Site Kit`),
	html("duracelltomi-google-tag-manager", "GTM4WP HTML comment", 100, `Google Tag Manager for WordPress by gtm4wp\.com|var gtm4wp_`),
	html("ga-google-analytics", "GA Google Analytics HTML comment", 100, `<!-- GA Google Analytics @`),
	html("pixelyoursite", "PixelYourSite JavaScript", 90, `\bpysOptions\b`),
	html("optinmonster", "OptinMonster HTML comment", 100, `converting visitors into subscribers and customers with OptinMonster`),
	html("mailchimp-for-wp", "Mailchimp for WordPress HTML comment", 100, `<!-- Mail[Cc]himp for WordPress `+ver),
	html("mailchimp-for-wp", "Mailchimp for WordPress form", 90, `class=["'][^"']*\bmc4wp-form\b`),
	html("mailpoet", "MailPoet form", 90, `class=["'][^"']*\bmailpoet_form\b`),
	html("newsletter", "Newsletter form", 80, `class=["'][^"']*\btnp-subscription\b`),
	html("email-subscribers", "Icegram Express form", 80, `class=["'][^"']*\bes_subscription_form\b`),
	html("add-to-any", "AddToAny JavaScript", 90, `\ba2a_config\b`),
	html("sassy-social-share", "Sassy Social Share JavaScript", 90, `\bheateor_sss_`),
	html("simple-social-icons", "Simple Social Icons widget", 80, `class=["'][^"']*\bsimple-social-icons\b`),
	html("social-icons-widget-by-wpzoom", "Social Icons by WPZoom widget", 80, `class=["'][^"']*\bzoom-social-icons-list\b`),
	html("ultimate-social-media-icons", "Ultimate Social Media Icons", 80, `\bsfsi_`),
	html("monarch", "Monarch", 80, `\bet_monarch\b`),
	html("instagram-feed", "Smash Balloon Instagram Feed", 100, `<!-- Instagram Feed JS -->|\bsb_instagram_js_options\b`),
	html("custom-facebook-feed", "Smash Balloon Custom Facebook Feed", 100, `<!-- Custom Facebook Feed JS -->|\bcffajaxurl\b`),
	html("youtube-embed-plus", "Embed Plus for YouTube JavaScript", 90, `\b_EPYT_\b`),
	html("wordpress-popular-posts", "WordPress Popular Posts JavaScript", 90, `\bwpp_params\b`),
	html("yet-another-related-posts-plugin", "YARPP related posts", 90, `class=["'][^"']*\byarpp-related\b`),
	html("click-to-chat-for-whatsapp", "Click to Chat button", 90, `class=["'][^"']*\bht-ctc\b`),
	html("wp-whatsapp-chat", "Joinchat button", 90, `class=["'][^"']*\bjoinchat\b`),
	html("chaty", "Chaty widget", 90, `\bchaty-widget\b`),

	// Caching and performance.
	html("w3-total-cache", "W3 Total Cache HTML comment", 100, `Performance optimized by W3 Total Cache`),
	header("w3-total-cache", "X-Powered-By", 100, `W3 Total Cache/`+ver),
	html("wp-super-cache", "WP Super Cache HTML comment", 100, `generated by WP-Super-Cache`),
	header("wp-super-cache", "WP-Super-Cache", 100, `.`),
	html("wp-fastest-cache", "WP Fastest Cache HTML comment", 100, `<!-- WP Fastest Cache file was created in`),
	html("wp-rocket", "WP Rocket HTML comment", 100, `This website is like a Rocket, isn't it\?`),
	generator("wp-rocket", `^WP Rocket `+ver),
	html("litespeed-cache", "LiteSpeed Cache HTML comment", 100, `<!-- Page (?:cached|generated) by LiteSpeed Cache `+ver),
	html("litespeed-cache", "LiteSpeed Cache HTML comment", 100, `<!-- Page optimized by LiteSpeed Cache`),
	header("litespeed-cache", "X-LiteSpeed-Tag", 90, `.`),
	html("wp-optimize", "WP-Optimize HTML comment", 100, `<!-- Cached by WP-Optimize`),
	html("hummingbird-performance", "Hummingbird HTML comment", 100, `<!-- Hummingbird cache file was created in`),
	header("hummingbird-performance", "Hummingbird-Cache", 100, `.`),
	html("breeze", "Breeze HTML comment", 100, `<!-- Cache served by breeze CACHE`),
	html("comet-cache", "Comet Cache HTML comment", 100, `Comet Cache is Fully Functional`),
	html("cache-enabler", "Cache Enabler HTML comment", 100, `<!-- Cache Enabler by KeyCDN`),
	header("nitropack", "X-Nitro-Cache", 90, `.`),
	header("wp-cloudflare-page-cache", "X-WP-CF-Super-Cache", 100, `.`),
	contentPath("autoptimize", 100, `^cache/autoptimize/`),
	contentPath("wp-fastest-cache", 100, `^cache/wpfc-minified/`),
	contentPath("w3-total-cache", 60, `^cache/minify/`),
	contentPath("litespeed-cache", 100, `^litespeed/`),
	contentPath("wp-rocket", 70, `^cache/(?:min|busting)/`),
	contentPath("wp-optimize", 100, `^cache/wpo-minify/`),
	contentPath("breeze", 100, `^cache/breeze-minification/`),
	contentPath("swift-performance-lite", 80, `^cache/swift-performance/`),
	contentPath("wp-asset-clean-up", 100, `^cache/asset-cleanup/`),
	contentPath("fast-velocity-minify", 100, `^cache/fvm/`),
	contentPath("perfmatters", 100, `^cache/perfmatters/`),
	contentPath("sg-cachepress", 100, `^uploads/(?:sites/\d+/)?siteground-optimizer-assets/`),
	contentPath("hummingbird-performance", 100, `^uploads/(?:sites/\d+/)?hummingbird-assets/`),
	contentPath("webp-express", 100, `^webp-express/`),
	contentPath("webp-converter-for-media", 100, `^uploads-webpc/`),
	contentPath("wp-smushit", 80, `^uploads/(?:sites/\d+/)?smush-webp/`),

	// Builders, blocks and sliders.
	generator("elementor", `^Elementor `+ver),
	html("elementor", "Elementor configuration", 100, `elementorFrontendConfig\s*=\s*\{[^<]*?"version":"`+`([0-9]+(?:\.[0-9]+)+)`),
	html("elementor-pro", "Elementor Pro configuration", 100, `ElementorProFrontendConfig\s*=\s*\{[^<]*?"version":"`+`([0-9]+(?:\.[0-9]+)+)`),
	contentPath("elementor", 100, `^uploads/(?:sites/\d+/)?elementor/`),
	generator("revslider", `^Powered by Slider Revolution `+ver),
	html("revslider", "Slider Revolution markup", 90, `<rs-module\b|class=["'][^"']*\brev_slider\b`),
	contentPath("revslider", 100, `^uploads/(?:sites/\d+/)?revslider/`),
	generator("js_composer", `^Powered by (?:WPBakery Page Builder|Visual Composer)`),
	contentPath("js_composer", 100, `^uploads/(?:sites/\d+/)?js_composer/`),
	generator("LayerSlider", `^Powered by LayerSlider `+ver),
	contentPath("LayerSlider", 100, `^uploads/(?:sites/\d+/)?layerslider/`),
	html("master-slider", "Master Slider HTML comment", 90, `<!-- MasterSlider -->`),
	html("smart-slider-3", "Smart Slider markup", 90, `class=["'][^"']*\bn2-section-smartslider\b`),
	html("ml-slider", "MetaSlider markup", 90, `class=["'][^"']*\bmetaslider\b`),
	contentPath("ultimate-addons-for-gutenberg", 100, `^uploads/(?:sites/\d+/)?uag-plugin/`),
	html("ultimate-addons-for-gutenberg", "Spectra blocks", 80, `class=["'][^"']*\buagb-`),
	contentPath("generateblocks", 100, `^uploads/(?:sites/\d+/)?generateblocks/`),
	contentPath("essential-addons-for-elementor-lite", 100, `^uploads/(?:sites/\d+/)?essential-addons-elementor/`),
	contentPath("so-widgets-bundle", 100, `^uploads/(?:sites/\d+/)?siteorigin-widgets/`),
	contentPath("so-css", 100, `^uploads/(?:sites/\d+/)?so-css/`),
	contentPath("custom-css-js", 100, `^uploads/(?:sites/\d+/)?custom-css-js/`),
	contentPath("astra-addon", 100, `^uploads/(?:sites/\d+/)?astra-addon/`),
	contentPath("megamenu", 100, `^uploads/(?:sites/\d+/)?maxmegamenu/`),
	contentPath("popup-maker", 100, `^uploads/(?:sites/\d+/)?pum/`),
	contentPath("host-webfonts-local", 100, `^uploads/(?:sites/\d+/)?omgf/`),
	contentPath("complianz-gdpr", 100, `^uploads/(?:sites/\d+/)?complianz/`),
	html("header-footer-elementor", "Elementor Header & Footer Builder markup", 80, `class=["'][^"']*\behf-template-`),
	html("elementskit-lite", "ElementsKit markup", 70, `class=["'][^"']*\bekit-template-content`),
	html("stackable-ultimate-gutenberg-blocks", "Stackable blocks", 90, `class=["'][^"']*\bstk-block\b`),
	html("otter-blocks", "Otter blocks", 90, `wp-block-themeisle-blocks-`),
	html("getwid", "Getwid blocks", 90, `wp-block-getwid-`),
	html("coblocks", "CoBlocks blocks", 90, `wp-block-coblocks-`),
	html("ultimate-blocks", "Ultimate Blocks blocks", 90, `wp-block-ub-`),
	generator("redux-framework", `^Redux `+ver),

	// E-commerce, forms, membership and community.
	generator("woocommerce", `^WooCommerce `+ver),
	html("woocommerce", "WooCommerce body class or script", 90, `\bwoocommerce-no-js\b|\bwc_add_to_cart_params\b|\bwoocommerce_params\b`),
	contentPath("woocommerce", 90, `^uploads/(?:sites/\d+/)?woocommerce_uploads/`),
	generator("easy-digital-downloads", `^Easy Digital Downloads `+ver),
	generator("give", `^Give `+ver),
	html("contact-form-7", "Contact Form 7 form", 90, `class=["'][^"']*\bwpcf7-form\b|\bvar wpcf7\s*=`),
	html("wpforms-lite", "WPForms JavaScript", 60, `\bwpforms_settings\b`),
	html("ninja-forms", "Ninja Forms JavaScript", 90, `\bnfForms\b`),
	html("gravityforms", "Gravity Forms markup", 90, `\bgf_global\b|class=["'][^"']*\bgform_wrapper\b`),
	contentPath("gravityforms", 100, `^uploads/(?:sites/\d+/)?gravity_forms/`),
	html("formidable", "Formidable Forms markup", 90, `class=["'][^"']*\bfrm_forms\b`),
	html("forminator", "Forminator form", 90, `class=["'][^"']*\bforminator-(?:ui|custom-form)\b`),
	html("fluentform", "Fluent Forms form", 90, `class=["'][^"']*\bfluent_form_`),
	contentPath("fluentform", 100, `^uploads/(?:sites/\d+/)?fluentform/`),
	html("everest-forms", "Everest Forms form", 90, `class=["'][^"']*\beverest-forms\b`),
	html("caldera-forms", "Caldera Forms markup", 90, `class=["'][^"']*\bcaldera-grid\b`),
	html("ultimate-member", "Ultimate Member form", 80, `class=["'][^"']*\bum-form\b`),
	html("buddypress", "BuddyPress body class", 80, `<body[^>]+class=["'][^"']*\bbuddypress\b`),
	html("bbpress", "bbPress body class", 80, `<body[^>]+class=["'][^"']*\bbbpress\b`),
	html("learnpress", "LearnPress body class", 80, `<body[^>]+class=["'][^"']*\blearnpress\b`),
	html("tutor", "Tutor LMS body class", 80, `<body[^>]+class=["'][^"']*\btutor-lms\b`),
	html("wp-job-manager", "WP Job Manager listings", 80, `class=["'][^"']*\bjob_listings\b`),
	html("the-events-calendar", "The Events Calendar meta tag", 100, `<meta name=["']tec-api-version["']`),
	html("wp-recipe-maker", "WP Recipe Maker markup", 90, `class=["'][^"']*\bwprm-recipe\b`),
	html("wpdiscuz", "wpDiscuz comments", 90, `\bwpdiscuzAjaxObj\b|id=["']wpdcom["']`),
	html("disqus-comment-system", "Disqus configuration", 60, `\bdisqus_config\b`),
	html("akismet", "Akismet comment form field", 90, `name=["']ak_js["']|id=["']ak_js_`),
	html("kk-star-ratings", "kk Star Ratings markup", 90, `class=["'][^"']*\bkk-star-ratings\b`),
	html("wp-ulike", "WP ULike markup", 90, `class=["'][^"']*\bwpulike\b`),

	// Galleries, media and content.
	html("nextgen-gallery", "NextGEN Gallery HTML comment", 100, `<meta name=["']NextGEN["'] version=["']`+`([0-9]+(?:\.[0-9]+)+)`),
	html("envira-gallery-lite", "Envira Gallery markup", 60, `class=["'][^"']*\benvira-gallery-wrap\b`),
	html("foogallery", "FooGallery markup", 90, `class=["'][^"']*\bfoogallery\b`),
	html("modula-best-grid-gallery", "Modula gallery", 90, `class=["'][^"']*\bmodula-gallery\b`),
	html("photo-gallery", "Photo Gallery JavaScript", 90, `\bbwg_objectsL10n\b`),
	html("wp-google-maps", "WP Go Maps JavaScript", 90, `\bwpgmza_`),
	html("wp-google-map-plugin", "WP Maps JavaScript", 90, `\bwpgmp_`),
	html("tablepress", "TablePress table", 90, `class=["'][^"']*\btablepress-id-`),
	html("wp-pagenavi", "WP-PageNavi markup", 90, `class=["']wp-pagenavi\b`),
	html("table-of-contents-plus", "Table of Contents Plus", 90, `id=["']toc_container["']`),
	html("easy-table-of-contents", "Easy Table of Contents", 90, `id=["']ez-toc-container["']`),
	html("luckywp-table-of-contents", "LuckyWP Table of Contents", 90, `class=["'][^"']*\blwptoc\b`),
	html("popup-maker", "Popup Maker markup", 90, `\bpum_vars\b|class=["'][^"']*\bpum-overlay\b`),
	html("jetpack", "Jetpack markup", 90, `<!-- Jetpack Open Graph Tags -->|\bWPCOM_sharing_counts\b|class=["'][^"']*\b(?:sharedaddy|jp-relatedposts)\b`),
	generator("amp", `^AMP Plugin `+ver),
	generator("seriously-simple-podcasting", `^Seriously Simple Podcasting `+ver),
	generator("sitepress-multilingual-cms", `^WPML ver:`+ver),
	html("translatepress-multilingual", "TranslatePress language switcher", 90, `\btrp-language-switcher\b|id=["']trp-floater-ls`),
	html("gtranslate", "GTranslate widget", 90, `\bgtranslateSettings\b|class=["'][^"']*\bgtranslate_wrapper\b`),
	html("weglot", "Weglot switcher", 90, `class=["'][^"']*\bweglot-`),
	html("wptouch", "WPtouch HTML comment", 100, `<!-- Powered by WPtouch(?: Pro)?: `+ver),

	// Privacy, cookies and accessibility.
	html("cookie-notice", "Cookie Notice JavaScript", 90, `\bcnArgs\b|id=["']cookie-notice["']`),
	html("cookie-law-info", "CookieYes banner", 90, `\bcli_cookiebar_settings\b|<!-- Start cookieyes banner -->`),
	html("complianz-gdpr", "Complianz banner", 90, `Consent Management powered by Complianz|\bcomplianz\s*=\s*\{`),
	html("gdpr-cookie-compliance", "GDPR Cookie Compliance", 90, `\bmoove_gdpr_`),
	html("real-cookie-banner", "Real Cookie Banner", 90, `\breal-cookie-banner\b`),
	html("borlabs-cookie", "Borlabs Cookie", 90, `\bBorlabsCookie\b|\bborlabs-cookie\b`),
	html("wp-dark-mode", "WP Dark Mode", 90, `\bwp-dark-mode\b`),
	html("pojo-accessibility", "One Click Accessibility", 90, `\bpojo-a11y\b`),
}
