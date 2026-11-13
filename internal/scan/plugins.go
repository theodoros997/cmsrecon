package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// Confidence of plugin signals.
const (
	confPluginURLs         = 80  // the plugin's files are referenced by a page
	confPluginReadme       = 100 // its readme is served
	confPluginRESTKnown    = 90  // a REST namespace the plugin registers
	confPluginRESTGuess    = 60  // a REST namespace named like a known plugin
	confPluginGenerator    = 60  // a "<slug> <version>" meta generator
	confPluginPostType     = 80  // a post type only that plugin registers
	confVersionStableTag   = 80
	confVersionChangelog   = 60
	confVersionSignature   = 80
	confVersionGenericMeta = 60
	confVersionBanner      = 50 // "/*! name - v1.2.3" at the top of one of its files
	confStrongSignature    = 80 // signature evidence at least this strong is kept without its folder
)

// genericGeneratorRe matches the meta generators some plugins add with
// their slug and version, e.g. "performance-lab 3.2.0; plugins: ...".
var genericGeneratorRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]*[a-z0-9]) v?([0-9]+(?:\.[0-9]+)+)(?:[;\s]|$)`)

// pluginScan carries plugin detection across its two parts: discovery
// first, then brute force (when asked for) once the quieter checks are
// done, so that a firewall that bans the brute force does not cost the
// rest of the scan.
type pluginScan struct {
	set       *componentSet
	inventory []*Plugin           // the exact list from --wp-auth, which replaces detection
	checked   map[*component]bool // its readme was read and its folder verified
}

// discoverPlugins finds the plugins the site uses, then reads each one's
// readme for its version. Discovery (--plugins-detection passive, the
// default, or mixed) reads the URLs and signatures of the homepage, the
// 404 page and the crawled pages, the REST API namespaces, the post types
// in the sitemaps and the plugins directory listing. With --wp-auth the
// REST inventory replaces all of this. core is the detected WordPress
// version.
func (s *Scanner) discoverPlugins(ctx context.Context, core *Version) *pluginScan {
	if inv := s.restInventory(ctx); inv != nil {
		for _, p := range inv.plugins {
			latest(p.Version, s.data.lists.Latest(wordlists.Plugins, p.Slug))
		}
		return &pluginScan{inventory: inv.plugins}
	}
	ps := &pluginScan{set: newComponentSet(), checked: map[*component]bool{}}
	set := ps.set
	prefix := s.plugins.Path
	if s.opts.PluginsDetection.Discover() {
		s.steps().Update(stepPlugins, "reading pages")
		pages := s.discoveryPages(ctx)
		s.pluginsFromPages(set, pages, prefix, core)
		s.pluginsFromSignatures(set, pages)
		s.pluginsFromInlineData(set, pages, prefix, core)
		if s.passive() {
			s.pluginsFromREST(ctx, set)
		}
		if s.aggressive() {
			s.fromListing(ctx, set, s.plugins, nil)
			s.pluginsFromPostTypes(ctx, set)
			for _, f := range s.combinedFiles(ctx) {
				for _, slug := range slugsInCombined(f.body, s.plugins.Path) {
					set.add(slug, Evidence{Method: "Paths in a combined CSS or JS file", Mode: modeAggressive, URL: f.url, Value: prefixTail(s.plugins.Path) + slug + "/", Confidence: confPluginURLs})
					set.observe(slug, "")
				}
			}
		}
	}
	s.checkPlugins(ctx, ps)
	return ps
}

// wantsPluginBruteForce reports whether the options ask for brute force
// of plugins: the -e list (vp, p or ap) with --plugins-detection mixed or
// aggressive, or the plugins the user named.
func (s *Scanner) wantsPluginBruteForce() bool {
	if !s.aggressive() {
		return false
	}
	return len(s.opts.PluginsList) > 0 || s.opts.PluginsDetection.BruteForce() && s.opts.Enumerate.Plugins != cli.ItemsNone
}

// bruteForcePlugins requests the folder of every plugin of the list, then
// reads the readmes of those it found.
func (s *Scanner) bruteForcePlugins(ctx context.Context, ps *pluginScan) {
	if ps.inventory != nil {
		return
	}
	list := s.opts.Enumerate.Plugins
	switch {
	case len(s.opts.PluginsList) > 0:
		// The user named the plugins to check: exactly those, whatever
		// --plugins-detection says.
		if s.aggressive() {
			s.bruteForce(ctx, ps.set, "Plugins", s.plugins, s.opts.PluginsList)
		}
	case s.wantsPluginBruteForce():
		s.bruteForce(ctx, ps.set, "Plugins", s.plugins, s.bruteList(wordlists.Plugins, list))
	case !s.opts.PluginsDetection.BruteForce() && (list == cli.ItemsPopular || list == cli.ItemsAll):
		s.notice("-e %sp only chooses the plugins to brute-force, which --plugins-detection passive (the default) does not do: the plugins were found from what the site shows. Use --plugins-detection mixed to also check every plugin on the list.", itemCode(list))
	}
	s.checkPlugins(ctx, ps)
}

// checkPlugins reads the readme and verifies the folder of the plugins
// found since the last call.
func (s *Scanner) checkPlugins(ctx context.Context, ps *pluginScan) {
	if !s.aggressive() {
		return
	}
	var todo []*component
	for _, c := range ps.set.list() {
		if !ps.checked[c] {
			todo = append(todo, c)
		}
	}
	var read atomic.Int32
	s.parallel(ctx, len(todo), func(i int) {
		s.readReadme(ctx, ps.set, todo[i], s.plugins)
		s.verify(ctx, ps.set, todo[i], s.plugins)
		s.steps().Update(stepPlugins, fmt.Sprintf("%d/%d checked", read.Add(1), len(todo)))
	})
	if ctx.Err() == nil {
		for _, c := range todo {
			ps.checked[c] = true
		}
	}
}

// pluginList is the plugins found so far, as the report shows them.
func (s *Scanner) pluginList(ps *pluginScan) []*Plugin {
	if ps.inventory != nil {
		return ps.inventory
	}
	var out []*Plugin
	for _, c := range ps.set.list() {
		if !s.keep(c) {
			continue
		}
		p := &Plugin{
			Slug: c.slug, Name: c.name, ReadmeURL: c.readme,
			Confidence: combine(c.evidence), Evidence: slices.Clone(c.evidence), Version: combineVersions(slices.Clone(c.versions)),
		}
		if c.observed || c.confirmed {
			p.Location = under(s.plugins, c.slug+"/")
		}
		sortEvidence(p.Evidence)
		latest(p.Version, s.data.lists.Latest(wordlists.Plugins, p.Slug))
		out = append(out, p)
	}
	return out
}

// methodAssetVersion is the evidence of a version read from the ?ver= of
// a plugin's files.
const methodAssetVersion = "?ver= on the plugin's assets"

// inOtherPluginsFolder reports whether a file of plugin slug sits in a
// sub-folder named after another plugin: .../plugins/slug/inc/elementor/x.css.
func inOtherPluginsFolder(path, slug string, others map[string]bool) bool {
	lower := strings.ToLower(path)
	i := strings.Index(lower, "/"+slug+"/")
	if i < 0 {
		return false
	}
	dirs := strings.Split(lower[i+len(slug)+2:], "/")
	for _, d := range dirs[:len(dirs)-1] { // the last part is the file
		if d != slug && others[d] {
			return true
		}
	}
	return false
}

// bruteForce requests <dir><slug>/ for the slugs not found yet and adds
// the ones that exist.
func (s *Scanner) bruteForce(ctx context.Context, set *componentSet, label string, dir *url.URL, slugs []string) {
	bySlug := map[string]string{}
	var urls []string
	for _, slug := range slugs {
		if set.has(slug) {
			continue
		}
		u := under(dir, slug+"/")
		bySlug[u] = slug
		urls = append(urls, u)
	}
	hits := s.probe(ctx, label, urls)
	// A real site has a handful of the plugins on a list, never a third
	// of them: that many "hits" means the site answers made-up paths as if
	// they existed, so they prove nothing. Listings are still proof.
	if n := len(hits); n >= 20 && n*10 > len(urls)*3 {
		s.notice("%s: %d of the %d paths brute-forced look present, which no real site has: the site answers paths that do not exist as if they did, so those results were dropped (only directory listings are kept).", label, n, len(urls))
		var listed []probeHit
		for _, h := range hits {
			if h.listed {
				listed = append(listed, h)
			}
		}
		hits = listed
	}
	for _, h := range hits {
		set.add(bySlug[h.url], Evidence{Method: "Known location", Mode: modeAggressive, URL: h.url, Value: fmt.Sprintf("HTTP %d", h.status), Confidence: h.confidence()})
		set.confirm(bySlug[h.url])
	}
}

// verify makes sure a plugin found from page links or guesses exists
// before it is reported. Links can be stale (a post that links to the
// files of a plugin removed since) and guesses can be wrong. A plugin
// whose folder a request already confirmed, or that a signature names,
// needs nothing. One seen only in links is confirmed when one of the files
// the pages reference answers; one found only by a guess when its folder
// answers (the same soft-404 check brute force uses). verify marks the
// component confirmed, or not; keep then decides.
func (s *Scanner) verify(ctx context.Context, set *componentSet, c *component, dir *url.URL) {
	set.mu.Lock()
	done, urls, weak, assets := c.confirmed, c.urlsOnly(), c.weakOnly(), slices.Clone(c.assets)
	set.mu.Unlock()
	switch {
	case done:
	case urls && len(assets) > 0:
		res := s.do(ctx, httpclient.Request{Method: http.MethodHead, URL: assets[0]})
		if res != nil && res.StatusCode != http.StatusNotFound && res.StatusCode != http.StatusGone {
			set.confirm(c.slug)
		} else if res != nil {
			set.mu.Lock()
			c.gone = true
			set.mu.Unlock()
		}
	case weak:
		if _, ok := s.probeOne(ctx, under(dir, c.slug+"/")); ok {
			set.confirm(c.slug)
		}
	case s.weakSignature(set, c):
		// Found only by a signature, a REST namespace or a post type the
		// plugin shares with others (WPForms Pro uses WPForms Lite's
		// settings object): drop it when its folder is clearly missing.
		// The readme was already asked for and was not there.
		res := s.do(ctx, httpclient.Request{Method: http.MethodHead, URL: under(dir, c.slug+"/")})
		if res != nil && res.Blocked == "" && (res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone) {
			set.mu.Lock()
			c.gone = true
			set.mu.Unlock()
		}
	}
}

// weakSignature reports whether a component is known only from what its
// pages show indirectly (signatures, REST namespaces, post types), with
// less than confStrongSignature: strong signatures such as Yoast's HTML
// comment are kept even when a hardened site hides the plugin's folder.
func (s *Scanner) weakSignature(set *componentSet, c *component) bool {
	set.mu.Lock()
	defer set.mu.Unlock()
	return !c.observed && !c.confirmed && combine(c.evidence) < confStrongSignature
}

// keep decides whether a component is reported: not when it was only
// guessed and nothing confirmed it, nor when the only file the pages
// linked to no longer exists.
func (s *Scanner) keep(c *component) bool {
	switch {
	case c.confirmed:
		return true
	case c.weakOnly():
		return false
	case c.urlsOnly() && c.gone:
		return false
	case !c.observed && c.gone:
		return false
	}
	return true
}

// itemCode is the -e prefix of a list: "v", "" or "a".
func itemCode(set cli.ItemSet) string {
	switch set {
	case cli.ItemsVulnerable:
		return "v"
	case cli.ItemsAll:
		return "a"
	}
	return ""
}

// fromListing adds the plugins or themes a directory listing of dir
// (s.plugins or s.themes) shows, inactive ones included: one request
// that, on a misconfigured server, lists everything installed. Slugs in
// skip (lower case) are left out.
func (s *Scanner) fromListing(ctx context.Context, set *componentSet, dir *url.URL, skip map[string]bool) {
	u := dir.String()
	names, ok := s.listingEntries(s.get(ctx, u))
	if !ok {
		return
	}
	for _, n := range names {
		slug, isDir := strings.CutSuffix(n, "/")
		if isDir && slug != "" && slug != "." && slug != ".." && !strings.Contains(slug, "/") && !skip[strings.ToLower(slug)] {
			set.add(slug, Evidence{Method: "Directory listing", Mode: modeAggressive, URL: u, Value: n, Confidence: 100})
			set.confirm(slug)
		}
	}
}

// pluginsFromPostTypes maps the post types and taxonomies the sitemaps
// list to the plugins that register them (WooCommerce's "product", The
// Events Calendar's "tribe_events", ...).
func (s *Scanner) pluginsFromPostTypes(ctx context.Context, set *componentSet) {
	for kind, u := range s.sitePages(ctx).postTypes {
		if slug := wordlists.PostTypePlugin(kind); slug != "" {
			set.add(slug, Evidence{Method: "Post type in the sitemap", Mode: modeAggressive, URL: u, Value: kind, Confidence: confPluginPostType})
		}
	}
}

// pluginsFromPages finds plugin directories in the URLs of the pages, and
// reads ?ver= from the plugins' assets.
func (s *Scanner) pluginsFromPages(set *componentSet, pages []labelledPage, prefix string, core *Version) {
	assets := map[string][]*url.URL{}
	spelling := map[string]string{}
	passive := map[string]bool{} // the plugin's assets were seen on a passive page
	for _, p := range pages {
		seen := map[string]bool{}
		for _, orig := range p.urls {
			u, ok := s.siteURL(orig)
			if !ok {
				continue
			}
			slug := slugIn(u.Path, prefix)
			if slug == "" {
				continue
			}
			k := strings.ToLower(slug)
			if _, ok := spelling[k]; !ok {
				spelling[k] = slug
			}
			assets[k] = append(assets[k], u)
			passive[k] = passive[k] || p.mode == modePassive
			inScope := ""
			if s.client.InScope(u) {
				inScope = u.String()
			}
			set.observe(spelling[k], inScope)
			if !seen[k] {
				seen[k] = true
				set.add(spelling[k], Evidence{Method: "URLs in the " + p.label, Mode: p.mode, URL: p.resp.URL.String(), Value: u.String(), Confidence: confPluginURLs})
			}
		}
	}
	// A file in a sub-folder named after another plugin on the site
	// (thegem-elements-elementor/inc/elementor/...) belongs to the
	// integration with that plugin, and plugins load such files with the
	// other plugin's version (ELEMENTOR_VERSION): its ?ver= is not theirs.
	others := map[string]bool{}
	for k := range assets {
		others[k] = true
	}
	for _, c := range set.list() {
		others[strings.ToLower(c.slug)] = true
	}
	for k, urls := range assets {
		own := urls[:0:0]
		for _, u := range urls {
			if !inOtherPluginsFolder(u.Path, k, others) {
				own = append(own, u)
			}
		}
		assets[k] = own
	}
	// A ?ver= that the assets of three plugins or more share is the
	// WordPress version (hidden elsewhere) or a cache buster, not theirs.
	shared := map[string]int{}
	for _, urls := range assets {
		for v := range s.assetVersions(urls, core) {
			shared[v]++
		}
	}
	for k, urls := range assets {
		mode := modeAggressive
		if passive[k] {
			mode = modePassive
		}
		for v, paths := range s.assetVersions(urls, core) {
			if shared[v] >= 3 {
				continue
			}
			var example string
			for _, u := range urls {
				if u.Query().Get("ver") == v {
					example = u.String()
					break
				}
			}
			set.addVersion(spelling[k], Evidence{Method: methodAssetVersion, Mode: mode, URL: example, Value: v, Confidence: assetVersionConfidence(len(paths))})
		}
	}
}

// pluginsFromSignatures applies the passive signatures to the pages and
// the homepage headers.
func (s *Scanner) pluginsFromSignatures(set *componentSet, pages []labelledPage) {
	hit := func(sig wordlists.Signature, p labelledPage, m []string) {
		pageURL := p.resp.URL.String()
		set.add(sig.Slug, Evidence{Method: sig.Method, Mode: p.mode, URL: pageURL, Value: truncate(m[0], 120), Confidence: sig.Confidence})
		if len(m) > 1 && m[1] != "" {
			set.addVersion(sig.Slug, Evidence{Method: sig.Method, Mode: p.mode, URL: pageURL, Value: vulndb.Normalize(m[1]), Confidence: confVersionSignature})
		}
	}
	contentPrefix := s.content.Path
	for _, p := range pages {
		pageURL := p.resp.URL.String()
		var paths []string
		for _, u := range p.urls {
			if path, ok := s.sitePath(u); ok {
				if rel, ok := strings.CutPrefix(path, contentPrefix); ok {
					paths = append(paths, rel)
				}
			}
		}
		for _, sig := range wordlists.PluginSignatures {
			switch sig.Kind {
			case wordlists.SigHTML:
				if m := sig.Re.FindStringSubmatch(p.text); m != nil {
					hit(sig, p, m)
				}
			case wordlists.SigGenerator:
				for _, g := range p.generators {
					if m := sig.Re.FindStringSubmatch(g); m != nil {
						hit(sig, p, m)
					}
				}
			case wordlists.SigPath:
				for _, rel := range paths {
					if sig.Re.MatchString(rel) {
						hit(sig, p, []string{s.content.String() + rel})
						break
					}
				}
			case wordlists.SigHeader:
				if p.page != s.home {
					continue
				}
				for _, v := range p.resp.Header.Values(sig.Header) {
					if m := sig.Re.FindStringSubmatch(v); m != nil {
						m[0] = sig.Header + ": " + v
						hit(sig, p, m)
						break
					}
				}
			}
		}
		// Generators that name a plugin slug and its version.
		for _, g := range p.generators {
			m := genericGeneratorRe.FindStringSubmatch(g)
			if m == nil || !s.knownPlugin(m[1]) {
				continue
			}
			set.add(m[1], Evidence{Method: methodGenericGenerator, Mode: p.mode, URL: pageURL, Value: g, Confidence: confPluginGenerator})
			set.addVersion(m[1], Evidence{Method: methodGenericGenerator, Mode: p.mode, URL: pageURL, Value: m[2], Confidence: confVersionGenericMeta})
		}
	}
}

// knownPlugin reports whether slug is a popular or premium plugin, or one
// with known vulnerabilities. Guesses from REST namespaces and meta
// generators are limited to these: with the full WordPress.org list, almost
// any word is some plugin's slug.
func (s *Scanner) knownPlugin(slug string) bool {
	return s.data.lists.Popular(wordlists.Plugins, slug) || len(s.data.vulns.Advisories(vulndb.KindPlugin, slug)) > 0
}

// pluginsFromREST maps the namespaces of the REST API index to plugins.
func (s *Scanner) pluginsFromREST(ctx context.Context, set *componentSet) {
	api := s.rest(ctx)
	if api == nil {
		return
	}
	for _, ns := range api.namespaces {
		slug, known, prefix := wordlists.NamespacePlugin(ns)
		switch {
		case known:
			set.add(slug, Evidence{Method: "REST API namespace", Mode: modePassive, URL: api.root, Value: ns, Confidence: confPluginRESTKnown})
		case prefix != "" && validSlug(prefix) && s.knownPlugin(prefix):
			set.add(prefix, Evidence{Method: methodRESTGuess, Mode: modePassive, URL: api.root, Value: ns, Confidence: confPluginRESTGuess})
		}
	}
}

// readReadme reads a plugin's readme for its name and version, then, while
// the version is not settled, tries the other ways to read it, from the
// cheapest to the dearest:
//
//  1. readme.txt: the stable tag and the changelog;
//  2. changelog.txt;
//  3. the banner comment of the plugin's own scripts and stylesheets;
//  4. the hashes of its files against WordPress.org's checksums of every
//     release, which settles it for a plugin WordPress.org hosts;
//  5. the header of its translation template.
//
// --aggressive tries all of them, with the rarer names of each file and
// package.json. dir is the plugins directory.
func (s *Scanner) readReadme(ctx context.Context, set *componentSet, c *component, dir *url.URL) {
	base := under(dir, c.slug+"/")
	readmes, changelogs := []string{"readme.txt"}, []string{"changelog.txt"}
	if s.thorough() {
		readmes = append(readmes, "README.txt", "readme.md")
		changelogs = append(changelogs, "CHANGELOG.md", "CHANGELOG.txt")
	}
	refused := false // the server refuses text files in the plugin's folder
	for _, name := range readmes {
		u := base + name
		res := s.get(ctx, u)
		if res != nil && (res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized) {
			refused = true
		}
		if res == nil || res.StatusCode != 200 {
			continue
		}
		info, ok := parseReadme(res.Body)
		if !ok {
			continue
		}
		set.mu.Lock()
		c.readme, c.confirmed = u, true
		if info.name != "" {
			c.name = info.name
		}
		c.evidence = append(c.evidence, Evidence{Method: name, Mode: modeAggressive, URL: u, Confidence: confPluginReadme})
		if info.stableTag != "" {
			c.versions = append(c.versions, Evidence{Method: name + " Stable tag", Mode: modeAggressive, URL: u, Value: info.stableTag, Confidence: confVersionStableTag})
		}
		if info.changelog != "" {
			c.versions = append(c.versions, Evidence{Method: name + " changelog", Mode: modeAggressive, URL: u, Value: info.changelog, Confidence: confVersionChangelog})
		}
		// The readme's own version ends the search: a ?ver= seen on the
		// pages is often the WordPress version or a cache buster.
		hasVersion := info.stableTag != "" || info.changelog != ""
		set.mu.Unlock()
		if hasVersion && !s.thorough() {
			return
		}
		break
	}
	// Some plugins keep the changelog in its own file. A server that
	// answered 403 for readme.txt would do the same for it.
	if !refused || s.thorough() {
		for _, name := range changelogs {
			if s.pluginVersionSettled(set, c) {
				break
			}
			u := base + name
			res := s.get(ctx, u)
			if res == nil || res.StatusCode != 200 {
				continue
			}
			if v := newestVersion(string(res.Body[:min(len(res.Body), 256<<10)])); v != "" && !isHTML(res.Body) {
				set.addVersion(c.slug, Evidence{Method: name, Mode: modeAggressive, URL: u, Value: v, Confidence: confVersionChangelog})
				set.confirm(c.slug)
				break
			}
		}
	}
	if s.pluginVersionSettled(set, c) {
		return
	}
	// The banner of one of the plugin's own files the pages load.
	set.mu.Lock()
	assets := slices.Clone(c.assets)
	set.mu.Unlock()
	v, u, live := s.bannerVersion(ctx, c.slug, assets)
	if v != "" {
		set.addVersion(c.slug, Evidence{Method: "Version banner in the plugin's file", Mode: modeAggressive, URL: u, Value: v, Confidence: confVersionBanner})
	}
	if live {
		set.confirm(c.slug) // its files answer: verify needs no request
	}
	if s.pluginVersionSettled(set, c) {
		return
	}
	s.hashVersionOfPlugin(ctx, set, c, dir)
	if s.pluginVersionSettled(set, c) {
		return
	}
	s.potVersion(ctx, set, c, dir)
	if s.thorough() {
		s.packageVersion(ctx, set, c, dir)
	}
}

func isHTML(body []byte) bool {
	head := strings.ToLower(string(body[:min(len(body), 1024)]))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html")
}
