package vulndb

import (
	"regexp"
	"strings"
)

// builtinLib describes how to recognize a library without the retire.js
// repository. Patterns use retire.js's §§version§§ placeholder. Names match
// the retire.js names, so its vulnerabilities attach when it is loaded.
type builtinLib struct {
	name     string
	uri      []string
	filename []string
	content  []string
	verPath  []string // case-insensitive, matched against the URL path
}

// builtinLibs are the libraries WordPress sites load most often: the ones
// WordPress bundles (whose ?ver= is the library version under
// wp-includes), and the ones themes and plugins bundle.
var builtinLibs = []builtinLib{
	{name: "jquery",
		uri:      []string{`/(§§version§§)/jquery(\.slim)?(\.min)?\.js`, `/jquery@(§§version§§)/`, `code\.jquery\.com/jquery-(§§version§§)(\.slim)?(\.min)?\.js`},
		filename: []string{`^jquery-(§§version§§)(\.slim)?(\.min)?\.js$`},
		content:  []string{`/\*!? jQuery v(§§version§§)`, `\* jQuery JavaScript Library v(§§version§§)`},
		verPath:  []string{`/jquery(\.slim)?(\.min)?\.js$`}},
	{name: "jquery-migrate",
		uri:      []string{`/jquery-migrate@(§§version§§)/`, `/(§§version§§)/jquery-migrate(\.min)?\.js`, `jquery-migrate-(§§version§§)(\.min)?\.js`},
		filename: []string{`^jquery-migrate-(§§version§§)(\.min)?\.js$`},
		content:  []string{`jQuery Migrate (?:- )?v(§§version§§)`},
		verPath:  []string{`/jquery-migrate(\.min)?\.js$`}},
	{name: "jquery-ui",
		uri:      []string{`/jqueryui/(§§version§§)/`, `/jquery-ui@(§§version§§)/`, `/jquery-ui/(§§version§§)/`, `/(§§version§§)/jquery-ui(\.min)?\.js`},
		filename: []string{`^jquery-ui-(§§version§§)(\.custom)?(\.min)?\.js$`},
		content:  []string{`jQuery UI - v(§§version§§)`, `jQuery UI (?:Core )?(§§version§§)`},
		verPath:  []string{`/wp-includes/js/jquery/ui/[a-z-]+(\.min)?\.js$`, `/jquery-ui(\.min)?\.js$`}},
	{name: "jquery-validation",
		uri:     []string{`/jquery-validation@(§§version§§)/`, `/jquery-validate/(§§version§§)/`},
		content: []string{`jQuery Validation Plugin (?:- )?v(§§version§§)`},
		verPath: []string{`/jquery\.validate(\.min)?\.js$`}},
	{name: "jquery-form", content: []string{`jQuery Form Plugin\s*\*?\s*version: (§§version§§)`}, verPath: []string{`/jquery\.form(\.min)?\.js$`}},
	{name: "jquery-blockui", content: []string{`jQuery BlockUI; v(§§version§§)`}, verPath: []string{`/jquery\.blockUI(\.min)?\.js$`}},
	{name: "jquery.prettyPhoto",
		content: []string{`Class: prettyPhoto[\s\S]{0,200}?Version: (§§version§§)`, `\.prettyPhoto\s*=\s*\{\s*version:\s*['"](§§version§§)`},
		verPath: []string{`/jquery\.prettyPhoto(\.min)?\.js$`}},
	{name: "bootstrap",
		uri:      []string{`/bootstrap@(§§version§§)/`, `/twitter-bootstrap/(§§version§§)/`, `/bootstrap/(§§version§§)/(?:js|css)/`},
		filename: []string{`^bootstrap-(§§version§§)(\.min)?\.js$`},
		content:  []string{`/\*!? Bootstrap v(§§version§§)`, `\* Bootstrap v(§§version§§)`},
		verPath:  []string{`/bootstrap(\.bundle)?(\.min)?\.js$`}},
	{name: "lodash",
		uri:     []string{`/lodash@(§§version§§)/`, `/lodash\.js/(§§version§§)/`},
		content: []string{`@license\s+Lodash[\s\S]{0,600}?VERSION\s*=\s*['"](§§version§§)`, `lodash\.com/license[\s\S]{0,600}?VERSION\s*=\s*['"](§§version§§)`},
		verPath: []string{`/lodash(\.min)?\.js$`}},
	{name: "underscore.js",
		uri:     []string{`/underscore@(§§version§§)/`, `/underscore\.js/(§§version§§)/`},
		content: []string{`//\s+Underscore\.js (§§version§§)`},
		verPath: []string{`/underscore(\.min)?\.js$`}},
	{name: "backbone.js",
		uri:     []string{`/backbone@(§§version§§)/`, `/backbone\.js/(§§version§§)/`},
		content: []string{`//\s+Backbone\.js (§§version§§)`},
		verPath: []string{`/backbone(\.min)?\.js$`}},
	{name: "moment.js",
		uri:     []string{`/moment@(§§version§§)/`, `/moment\.js/(§§version§§)/`},
		content: []string{`//! version : (§§version§§)`},
		verPath: []string{`/moment(\.min)?\.js$`}},
	{name: "handlebars",
		uri:      []string{`/handlebars@(§§version§§)/`, `/handlebars\.js/(§§version§§)/`},
		filename: []string{`^handlebars-v?(§§version§§)(\.min)?\.js$`},
		content:  []string{`handlebars v(§§version§§)`}},
	{name: "mustache.js", uri: []string{`/mustache\.js/(§§version§§)/`, `/mustache@(§§version§§)/`}, content: []string{`mustache\.version\s*=\s*["'](§§version§§)`}},
	{name: "angularjs",
		uri:      []string{`/angular\.js/(§§version§§)/`, `/angularjs/(§§version§§)/`, `/angular@(§§version§§)/`},
		filename: []string{`^angular-(§§version§§)(\.min)?\.js$`},
		content:  []string{`@license AngularJS v(§§version§§)`}},
	{name: "vue", uri: []string{`/vue@(§§version§§)/`, `/vue/(§§version§§)/`}, content: []string{`Vue\.js v(§§version§§)`}},
	{name: "react",
		uri:     []string{`/react@(§§version§§)/`, `/react/(§§version§§)/umd/`},
		content: []string{`@license React v(§§version§§)`},
		verPath: []string{`/react(\.min)?\.js$`}},
	{name: "react-dom",
		uri:     []string{`/react-dom@(§§version§§)/`, `/react-dom/(§§version§§)/umd/`},
		content: []string{`@license React(?:DOM)? v(§§version§§)[\s\S]{0,40}react-dom`},
		verPath: []string{`/react-dom(\.min)?\.js$`}},
	{name: "DOMPurify", uri: []string{`/dompurify@(§§version§§)/`, `/dompurify/(§§version§§)/`}, content: []string{`@license DOMPurify (§§version§§)`, `DOMPurify (§§version§§) \|`}},
	{name: "tinyMCE", uri: []string{`/tinymce/(§§version§§)/`, `/tinymce@(§§version§§)/`}, content: []string{`TinyMCE version (§§version§§)`}, verPath: []string{`/tinymce(\.min)?\.js$`}},
	{name: "ckeditor", uri: []string{`/ckeditor/(§§version§§)/`}, content: []string{`version:"(§§version§§)",revision:"`}},
	{name: "select2",
		uri:     []string{`/select2@(§§version§§)/`, `/select2/(§§version§§)/`},
		content: []string{`Select2 (§§version§§)`},
		verPath: []string{`/select2(\.full)?(\.min)?\.js$`}},
	{name: "swiper",
		uri:     []string{`/swiper@(§§version§§)/`, `/Swiper/(§§version§§)/`},
		content: []string{`\* Swiper (§§version§§)`},
		verPath: []string{`/swiper(-bundle)?(\.min)?\.js$`}},
	{name: "plupload", content: []string{`Plupload - multi-runtime File Uploader[\s\S]{0,20}v(§§version§§)`}, verPath: []string{`/plupload(\.full)?(\.min)?\.js$`}},
	{name: "jPlayer", content: []string{`jPlayer Plugin for jQuery[\s\S]{0,300}?Version: (§§version§§)`}, verPath: []string{`/jquery\.jplayer(\.min)?\.js$`}},
	{name: "mediaelement", content: []string{`MediaElement\.js[\s\S]{0,200}?(?:v|version )(§§version§§)`}, verPath: []string{`/mediaelement(-and-player)?(\.min)?\.js$`}},
	{name: "swfobject", content: []string{`SWFObject v(§§version§§)`}, verPath: []string{`/swfobject(\.min)?\.js$`}},
	{name: "chart.js",
		uri:     []string{`/chart\.js@(§§version§§)/`, `/Chart\.js/(§§version§§)/`},
		content: []string{`Chart\.js v(§§version§§)`},
		verPath: []string{`/chart(\.umd)?(\.bundle)?(\.min)?\.js$`}},
	{name: "jquery.datatables", uri: []string{`/datatables/(§§version§§)/`, `/datatables\.net@(§§version§§)/`}, content: []string{`DataTables (§§version§§)`}},
	{name: "d3", uri: []string{`/d3@(§§version§§)/`, `/d3/(§§version§§)/`}, content: []string{`https://d3js\.org v(§§version§§)`}},
	{name: "video.js", uri: []string{`/video\.js@(§§version§§)/`, `/video\.js/(§§version§§)/`}, content: []string{`Video\.js (§§version§§)`}},
	{name: "axios", uri: []string{`/axios@(§§version§§)/`, `/axios/(§§version§§)/`}, content: []string{`axios v(§§version§§)`}},
	{name: "highlightjs", uri: []string{`/highlight\.js/(§§version§§)/`}, content: []string{`Highlight\.js v?(§§version§§)`}},
	{name: "prototypejs", uri: []string{`/prototype/(§§version§§)/prototype`}, content: []string{`Prototype JavaScript framework, version (§§version§§)`}},
	{name: "knockout", content: []string{`Knockout JavaScript library v(§§version§§)`}},
	{name: "jquery-mobile", uri: []string{`/mobile/(§§version§§)/jquery\.mobile`}, content: []string{`jQuery Mobile (§§version§§)`}},
	{name: "highcharts", uri: []string{`/highcharts/(§§version§§)/`}, content: []string{`Highcharts JS v(§§version§§)`}},
	{name: "jszip", uri: []string{`/jszip@(§§version§§)/`, `/jszip/(§§version§§)/`}, content: []string{`JSZip v(§§version§§)`}},
	{name: "bootstrap-select", uri: []string{`/bootstrap-select@(§§version§§)/`}, content: []string{`Bootstrap-select v(§§version§§)`}},
	{name: "pdf.js", uri: []string{`/pdfjs-dist@(§§version§§)/`, `/pdf\.js/(§§version§§)/`}, content: []string{`pdfjsVersion\s*=\s*['"](§§version§§)`}},
	{name: "quill", uri: []string{`/quill@(§§version§§)/`}, content: []string{`Quill Editor v(§§version§§)`}},
	{name: "marked", uri: []string{`/marked@(§§version§§)/`}, content: []string{`marked v(§§version§§)`}},
	{name: "alpinejs", uri: []string{`/alpinejs@(§§version§§)/`}},
	{name: "threejs", uri: []string{`/three@(§§version§§)/`}},

	// Libraries retire.js has no vulnerabilities for, listed for the
	// inventory.
	{name: "slick", uri: []string{`/slick-carousel@(§§version§§)/`, `/slick-carousel/(§§version§§)/`}, content: []string{`Version: (§§version§§)\s+Author: Ken Wheeler`}, verPath: []string{`/slick(\.min)?\.js$`}},
	{name: "owl.carousel", uri: []string{`/owl\.carousel@(§§version§§)/`, `/OwlCarousel2/(§§version§§)/`}, content: []string{`Owl Carousel v(§§version§§)`}, verPath: []string{`/owl\.carousel(\.min)?\.js$`}},
	{name: "magnific-popup", uri: []string{`/magnific-popup@(§§version§§)/`, `/magnific-popup\.js/(§§version§§)/`}, content: []string{`Magnific Popup - v(§§version§§)`}, verPath: []string{`/jquery\.magnific-popup(\.min)?\.js$`}},
	{name: "isotope", uri: []string{`/isotope-layout@(§§version§§)/`}, content: []string{`Isotope (?:PACKAGED )?v(§§version§§)`}, verPath: []string{`/isotope(\.pkgd)?(\.min)?\.js$`}},
	{name: "imagesloaded", uri: []string{`/imagesloaded@(§§version§§)/`}, content: []string{`imagesLoaded (?:PACKAGED )?v(§§version§§)`}, verPath: []string{`/imagesloaded(\.pkgd)?(\.min)?\.js$`}},
	{name: "masonry", uri: []string{`/masonry-layout@(§§version§§)/`}, content: []string{`Masonry (?:PACKAGED )?v(§§version§§)`}, verPath: []string{`/masonry(\.pkgd)?(\.min)?\.js$`}},
	{name: "fancybox", uri: []string{`/@fancyapps/fancybox@(§§version§§)/`, `/fancybox/(§§version§§)/`}, content: []string{`fancyBox v(§§version§§)`}, verPath: []string{`/jquery\.fancybox(\.pack|\.min)?\.js$`}},
	{name: "flexslider", content: []string{`jQuery FlexSlider v(§§version§§)`}, verPath: []string{`/jquery\.flexslider(-min)?\.js$`}},
	{name: "font-awesome", uri: []string{`/font-awesome/(§§version§§)/css/`, `/fontawesome-free@(§§version§§)/`, `use\.fontawesome\.com/releases/v(§§version§§)/`, `/font-awesome@(§§version§§)/`}},
	{name: "popper.js", uri: []string{`/@popperjs/core@(§§version§§)/`, `/popper\.js@(§§version§§)/`, `/popper\.js/(§§version§§)/`}, content: []string{`@popperjs/core v(§§version§§)`, `Popper\.js v(§§version§§)`}},
	{name: "modernizr", content: []string{`[Mm]odernizr (?:v)?(§§version§§)`}, verPath: []string{`/modernizr([.-]custom)?(\.min)?\.js$`}},
	{name: "waypoints", content: []string{`Waypoints - (§§version§§)`}, verPath: []string{`/(jquery\.)?waypoints(\.min)?\.js$`}},
	{name: "photoswipe", content: []string{`PhotoSwipe - v(§§version§§)`}},
	{name: "lightbox2", content: []string{`Lightbox v(§§version§§)`}, verPath: []string{`/lightbox(\.min)?\.js$`}},
	{name: "js-cookie", content: []string{`JavaScript Cookie v(§§version§§)`}},
	{name: "jquery-cookie", content: []string{`jQuery Cookie Plugin v(§§version§§)`}},
	{name: "clipboard.js", content: []string{`clipboard\.js v(§§version§§)`}, verPath: []string{`/clipboard(\.min)?\.js$`}},
	{name: "gsap", uri: []string{`/gsap/(§§version§§)/`, `/gsap@(§§version§§)/`}, content: []string{`\* GSAP (§§version§§)`}},
	{name: "wow.js", content: []string{`WOW (?:wow\.js )?- v(§§version§§)`}, verPath: []string{`/wow(\.min)?\.js$`}},
	{name: "hoverintent", content: []string{`hoverIntent v(§§version§§)`}, verPath: []string{`/hoverIntent(\.min)?\.js$`}},
	{name: "colorbox", content: []string{`Colorbox v?(§§version§§)`}, verPath: []string{`/jquery\.colorbox(-min)?\.js$`}},
	{name: "lightgallery", uri: []string{`/lightgallery@(§§version§§)/`}, content: []string{`lightgallery \| (§§version§§)`}},
	{name: "lazysizes", uri: []string{`/lazysizes@(§§version§§)/`, `/lazysizes/(§§version§§)/`}},
}

func builtinJSRepo() *JSRepo {
	r := &JSRepo{byName: map[string]*jsLibrary{}}
	for _, b := range builtinLibs {
		l := r.library(b.name)
		l.uri = append(l.uri, compileRetire(b.uri)...)
		l.filename = append(l.filename, compileRetire(b.filename)...)
		l.content = append(l.content, compileRetire(b.content)...)
		for _, p := range b.verPath {
			l.verPath = append(l.verPath, regexp.MustCompile("(?i)"+p))
		}
	}
	return r
}

// Libraries lists the names of the libraries the repository can detect.
func (r *JSRepo) Libraries() []string {
	out := make([]string, 0, len(r.libs))
	for _, l := range r.libs {
		out = append(out, l.name)
	}
	return out
}

// CoreBundled reports whether a library URL is one WordPress ships in
// wp-includes, where ?ver= is the library's own version.
func CoreBundled(path string) bool {
	return strings.Contains(path, "/wp-includes/js/")
}
