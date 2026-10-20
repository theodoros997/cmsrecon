package scan

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// component collects what a scan learns about one plugin or theme.
type component struct {
	slug      string
	name      string
	readme    string
	evidence  []Evidence // that it is installed
	versions  []Evidence // what its version is
	observed  bool       // a page referenced a file in its folder
	confirmed bool       // a request showed the folder exists: a readme, a listing, a brute-force hit, an asset
	assets    []string   // in-scope URLs of its files the pages referenced, at most three
	gone      bool       // the first of those files is gone (404 or 410)
}

// Evidence methods that only suggest a plugin: a REST namespace or a meta
// generator that happens to match a slug. A plugin found only by these is
// reported once a request confirms its folder.
const (
	methodRESTGuess        = "REST API namespace named like the plugin"
	methodGenericGenerator = "Meta generator naming the plugin"
)

// weakOnly reports whether every piece of evidence is a guess.
func (c *component) weakOnly() bool {
	for _, e := range c.evidence {
		if e.Method != methodRESTGuess && e.Method != methodGenericGenerator {
			return false
		}
	}
	return true
}

// urlsOnly reports whether the only evidence is links in pages.
func (c *component) urlsOnly() bool {
	for _, e := range c.evidence {
		if !strings.HasPrefix(e.Method, "URLs in the ") && !strings.HasPrefix(e.Method, "Theme URLs in the ") {
			return false
		}
	}
	return len(c.evidence) > 0
}

// componentSet is a concurrency-safe set of components keyed by slug,
// compared without case.
type componentSet struct {
	mu    sync.Mutex
	items map[string]*component
}

func newComponentSet() *componentSet {
	return &componentSet{items: map[string]*component{}}
}

func (cs *componentSet) get(slug string) *component {
	k := strings.ToLower(slug)
	c := cs.items[k]
	if c == nil {
		c = &component{slug: slug}
		cs.items[k] = c
	}
	return c
}

// add records that slug is installed. A method already recorded for slug
// is not repeated: the first page it was seen on is evidence enough, and
// confidence counts each method once anyway.
func (cs *componentSet) add(slug string, e Evidence) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c := cs.get(slug)
	if !slices.ContainsFunc(c.evidence, func(o Evidence) bool { return o.Method == e.Method }) {
		c.evidence = append(c.evidence, e)
	}
}

// addVersion records a version signal for slug, once per method and
// version.
func (cs *componentSet) addVersion(slug string, e Evidence) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c := cs.get(slug)
	if !slices.ContainsFunc(c.versions, func(o Evidence) bool { return o.Method == e.Method && o.Value == e.Value }) {
		c.versions = append(c.versions, e)
	}
}

// observe records an in-scope URL of one of slug's files that a page
// referenced.
func (cs *componentSet) observe(slug, u string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c := cs.get(slug)
	c.observed = true
	if u != "" && len(c.assets) < 3 && !slices.Contains(c.assets, u) {
		c.assets = append(c.assets, u)
	}
}

// confirm records that a request showed slug's folder exists.
func (cs *componentSet) confirm(slug string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.get(slug).confirmed = true
}

func (cs *componentSet) has(slug string) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	_, ok := cs.items[strings.ToLower(slug)]
	return ok
}

// list returns the components sorted by slug.
func (cs *componentSet) list() []*component {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]*component, 0, len(cs.items))
	for _, c := range cs.items {
		if len(c.evidence) > 0 {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b *component) int {
		return strings.Compare(strings.ToLower(a.slug), strings.ToLower(b.slug))
	})
	return out
}

// parallel runs fn for 0..n-1 on --threads workers and stops early when ctx
// is cancelled.
func (s *Scanner) parallel(ctx context.Context, n int, fn func(i int)) {
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(max(s.opts.Threads, 1), n) {
		wg.Go(func() {
			for ctx.Err() == nil {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				fn(i)
			}
		})
	}
	wg.Wait()
}

var (
	photonHostRe = regexp.MustCompile(`(?i)^i[0-3]\.wp\.com$`)
	// First labels of hosts that serve a site's own files.
	cdnLabelRe = regexp.MustCompile(`(?i)^(?:www|cdn\d*|static\d*|assets?|media|img|images|files|content|s\d*|st)$`)
)

// sitePath returns the path of an asset URL on the scanned site: an
// in-scope URL, a CDN alias of the site such as cdn.example.com, or a
// Jetpack image CDN URL (i0.wp.com/example.com/...). Out-of-scope URLs are
// only read, never requested.
func (s *Scanner) sitePath(u *url.URL) (string, bool) {
	if s.client.InScope(u) || siteAlias(u.Hostname(), s.base.Hostname()) {
		return u.Path, true
	}
	if photonHostRe.MatchString(u.Hostname()) {
		if rest, ok := strings.CutPrefix(u.Path, "/"+s.base.Hostname()+"/"); ok {
			return "/" + rest, true
		}
	}
	return "", false
}

// siteAlias reports whether host serves the files of the site at base:
// both are under the same registrable domain and host's first label is
// a CDN or www label. Other sibling hosts may be unrelated sites on a
// shared domain.
func siteAlias(host, base string) bool {
	host, base = strings.ToLower(host), strings.ToLower(base)
	d := siteDomain(base)
	if d == "" || siteDomain(host) != d || host == base {
		return false
	}
	first, _, _ := strings.Cut(host, ".")
	return cdnLabelRe.MatchString(first)
}

// siteDomain approximates a host's registrable domain: the last two
// labels, or the last three under two-letter country domains with a short
// second level (example.co.uk). IP addresses and single labels give "".
func siteDomain(host string) string {
	if !strings.Contains(host, ".") || net.ParseIP(strings.Trim(host, "[]")) != nil {
		return ""
	}
	labels := strings.Split(host, ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && len(labels[len(labels)-2]) <= 3 {
		n = 3
	}
	if len(labels) < n {
		return host
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// slugIn returns the directory name after prefix in path, such as the slug
// in "/wp-content/plugins/<slug>/x.js" for prefix "/wp-content/plugins/".
// Files directly in the prefix directory give nothing.
func slugIn(path, prefix string) string {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		// A renamed or nested content directory: match on the prefix's
		// last two segments.
		i := strings.Index(path, prefixTail(prefix))
		if i < 0 {
			return ""
		}
		rest = path[i+len(prefixTail(prefix)):]
	}
	slug, _, isDir := strings.Cut(rest, "/")
	if !isDir || !validSlug(slug) {
		return ""
	}
	return slug
}

var slugRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// validSlug reports whether s can be a plugin or theme folder name. It
// rejects what page text contains around real paths: template
// placeholders ("${slug}", "%s", "{{name}}"), escaped and encoded
// characters, and "." and "..".
func validSlug(s string) bool {
	return slugRe.MatchString(s) && !strings.Contains(s, "..")
}

// prefixTail returns the last two segments of a directory path:
// "/wp-content/plugins/" gives "/wp-content/plugins/".
func prefixTail(prefix string) string {
	parts := strings.Split(strings.Trim(prefix, "/"), "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return "/" + strings.Join(parts, "/") + "/"
}

// assetVersions groups the ?ver= values of a component's assets. Versions
// equal to a core version candidate are dropped (WordPress adds its own
// version to assets enqueued without one), and so are bundled libraries,
// whose ?ver= is often the library's version.
func (s *Scanner) assetVersions(urls []*url.URL, core *Version) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, u := range urls {
		v := u.Query().Get("ver")
		if !vulndb.Valid(v) || !strings.Contains(v, ".") || isCoreVersion(v, core) || vendored(u.Path) {
			continue
		}
		if len(s.data.js.FromURL(u)) > 0 {
			continue
		}
		if out[v] == nil {
			out[v] = map[string]bool{}
		}
		out[v][u.Path] = true
	}
	return out
}

func isCoreVersion(v string, core *Version) bool {
	if core == nil {
		return false
	}
	for _, c := range core.Candidates {
		if c.Number == v {
			return true
		}
	}
	return false
}

var vendorDirRe = regexp.MustCompile(`(?i)/(?:vendor|vendors|node_modules|lib|libs|library|libraries|third-party|thirdparty|external|bower_components)/`)

func vendored(path string) bool { return vendorDirRe.MatchString(path) }

// pathOf returns the lower-case path of a URL.
func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Path)
}

// isLibraryURL reports whether a URL is a JavaScript library cmsrecon
// recognizes, such as a copy of Select2 bundled in a plugin.
func (s *Scanner) isLibraryURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(s.data.js.FromURL(u)) > 0
}

// assetVersionConfidence: the more assets agree, the more likely ?ver= is
// the component's version: 40% for one asset, up to 60% for three.
func assetVersionConfidence(assets int) int {
	return min(30+10*assets, 60)
}

// Readme parsing. WordPress.org readmes look like:
//
//	=== Contact Form 7 ===
//	Stable tag: 5.3.1
//	== Changelog ==
//	= 5.3.1 =
var (
	readmeNameRe      = regexp.MustCompile(`(?m)^[ \t]*===[ \t]*(.+?)[ \t]*===[ \t]*$`)
	readmeMarkerRe    = regexp.MustCompile(`(?im)^[ \t*#]*(?:stable tag|contributors|requires at least|tested up to)[ \t*]*:|^[ \t]*===[^=\n]+===`)
	stableTagRe       = regexp.MustCompile(`(?im)^[ \t*#>-]*stable tag[ \t*]*:[ \t*]*([^\s*]+)`)
	changelogStartRe  = regexp.MustCompile(`(?im)^[ \t]*(?:==+|#+)[ \t]*change[ \t]?log[ \t]*(?:==+)?[ \t]*$`)
	sectionHeadingRe  = regexp.MustCompile(`(?m)^[ \t]*(?:==[^=]|##?[^#])`)
	changelogEntryRe  = regexp.MustCompile(`(?im)^[ \t]*(?:=+|#+|\*\*)?[ \t]*\[?(?:version[ \t]+|v)?(\d+(?:\.\d+){1,3})(?:[-.]?(?:alpha|beta|rc)[0-9.]*)?\]?(?:[ \t]|=|$|:|\(|-)`)
	readmeVersionLike = regexp.MustCompile(`^\d+(?:\.\d+)+`)
)

type readmeInfo struct {
	name      string
	stableTag string
	changelog string // the newest version in the changelog
}

// parseReadme reads a plugin readme. ok is false when the body does not
// look like a readme.
func parseReadme(body []byte) (info readmeInfo, ok bool) {
	text := string(body[:min(len(body), 512<<10)])
	if !readmeMarkerRe.MatchString(text) {
		return info, false
	}
	if m := readmeNameRe.FindStringSubmatch(text); m != nil {
		info.name = strings.TrimSpace(m[1])
	}
	if m := stableTagRe.FindStringSubmatch(text); m != nil && readmeVersionLike.MatchString(vulndb.Normalize(m[1])) {
		info.stableTag = vulndb.Normalize(m[1])
	}
	if loc := changelogStartRe.FindStringIndex(text); loc != nil {
		section := text[loc[1]:]
		if next := sectionHeadingRe.FindStringIndex(section); next != nil {
			section = section[:next[0]]
		}
		info.changelog = newestVersion(section)
	}
	return info, true
}

// newestVersion returns the highest version heading in a changelog; some
// changelogs list the oldest release first.
func newestVersion(text string) string {
	best := ""
	for _, m := range changelogEntryRe.FindAllStringSubmatch(text, -1) {
		if best == "" || vulndb.Compare(m[1], best) > 0 {
			best = m[1]
		}
	}
	return best
}

// bruteList returns the slugs to brute-force for -e vp/p/ap or vt/t/at.
// The vulnerable list needs the vulnerability data, and the full list the
// WordPress.org data; without them the popular list is used, with a notice.
func (s *Scanner) bruteList(kind string, set cli.ItemSet) []string {
	lists := s.data.lists
	popular, all, what := lists.PopularPlugins, lists.AllPlugins, "plugins"
	if kind == wordlists.Themes {
		popular, all, what = lists.PopularThemes, lists.AllThemes, "themes"
	}
	switch set {
	case cli.ItemsVulnerable:
		slugs := s.data.vulns.Slugs(kind)
		if len(slugs) == 0 {
			s.notice("Without vulnerability data, the popular %s were checked instead of the vulnerable ones: run \"cmsrecon update\".", what)
			return popular
		}
		return respell(slugs, popular)
	case cli.ItemsPopular:
		return popular
	case cli.ItemsAll:
		if len(all) == 0 {
			s.notice("The list of all %s is downloaded by \"cmsrecon update\"; the popular %s were checked instead.", what, what)
			return popular
		}
		return mergeLists(popular, all)
	}
	return nil
}

// respell spells slugs the way the reference list does. Vulnerability data
// is lower case, but paths are case-sensitive on most servers
// ("LayerSlider").
func respell(slugs, reference []string) []string {
	spelling := map[string]string{}
	for _, r := range reference {
		spelling[strings.ToLower(r)] = r
	}
	out := make([]string, len(slugs))
	for i, s := range slugs {
		if r, ok := spelling[strings.ToLower(s)]; ok {
			out[i] = r
		} else {
			out[i] = s
		}
	}
	return out
}

func mergeLists(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if k := strings.ToLower(s); !seen[k] {
				seen[k] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// latest fills in the latest release and whether v is outdated.
func latest(v *Version, latestVersion string) {
	if v == nil || latestVersion == "" {
		return
	}
	v.Latest = latestVersion
	v.Outdated = v.Number != "" && vulndb.Compare(v.Number, latestVersion) < 0
}

// truncate shortens s to n runes for evidence values.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
