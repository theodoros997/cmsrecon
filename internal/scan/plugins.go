package scan

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/cli"
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
	confVersionStableTag   = 80
	confVersionChangelog   = 60
	confVersionSignature   = 80
	confVersionGenericMeta = 60
)

// genericGeneratorRe matches the meta generators some plugins add with
// their slug and version, e.g. "performance-lab 3.2.0; plugins: ...".
var genericGeneratorRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]*[a-z0-9]) v?([0-9]+(?:\.[0-9]+)+)(?:[;\s]|$)`)

// detectPlugins finds plugins: passively from page URLs, signatures and
// REST namespaces, and aggressively by brute force (-e vp, p or ap), then
// reads each plugin's readme for its version. With --wp-auth the REST
// inventory replaces all of this. core is the detected WordPress version.
func (s *Scanner) detectPlugins(ctx context.Context, core *Version) []*Plugin {
	if inv := s.restInventory(ctx); inv != nil {
		for _, p := range inv.plugins {
			latest(p.Version, s.data.lists.Latest(wordlists.Plugins, p.Slug))
		}
		return inv.plugins
	}
	set := newComponentSet()
	prefix := s.content.Path + "plugins/"
	if s.passive() {
		s.pluginsFromPages(set, prefix, core)
		s.pluginsFromSignatures(set)
		s.pluginsFromREST(ctx, set)
	}
	if s.aggressive() && s.opts.Enumerate.Plugins != cli.ItemsNone {
		s.bruteForce(ctx, set, "Plugins", "plugins/", s.bruteList(wordlists.Plugins, s.opts.Enumerate.Plugins))
	}

	comps := set.list()
	if s.aggressive() {
		s.parallel(ctx, len(comps), func(i int) { s.readReadme(ctx, set, comps[i], "plugins/") })
	}
	var out []*Plugin
	for _, c := range comps {
		p := &Plugin{
			Slug: c.slug, Name: c.name, Location: s.contentURL("plugins/" + c.slug + "/"), ReadmeURL: c.readme,
			Confidence: combine(c.evidence), Evidence: c.evidence, Version: combineVersions(c.versions),
		}
		sortEvidence(p.Evidence)
		latest(p.Version, s.data.lists.Latest(wordlists.Plugins, p.Slug))
		out = append(out, p)
	}
	return out
}

// bruteForce requests <content>/<dir><slug>/ for the slugs not found yet
// and adds the ones that exist.
func (s *Scanner) bruteForce(ctx context.Context, set *componentSet, label, dir string, slugs []string) {
	bySlug := map[string]string{}
	var urls []string
	for _, slug := range slugs {
		if set.has(slug) {
			continue
		}
		u := s.contentURL(dir + slug + "/")
		bySlug[u] = slug
		urls = append(urls, u)
	}
	for _, h := range s.probe(ctx, label, urls) {
		set.add(bySlug[h.url], Evidence{Method: "Known location", Mode: modeAggressive, URL: h.url, Value: fmt.Sprintf("HTTP %d", h.status), Confidence: h.confidence()})
	}
}

// pluginsFromPages finds plugin directories in the URLs of the homepage
// and the 404 page, and reads ?ver= from the plugins' assets.
func (s *Scanner) pluginsFromPages(set *componentSet, prefix string, core *Version) {
	assets := map[string][]*url.URL{}
	spelling := map[string]string{}
	for _, p := range s.pages() {
		seen := map[string]bool{}
		for _, u := range p.urls {
			path, ok := s.sitePath(u)
			if !ok {
				continue
			}
			slug := slugIn(path, prefix)
			if slug == "" {
				continue
			}
			k := strings.ToLower(slug)
			if _, ok := spelling[k]; !ok {
				spelling[k] = slug
			}
			assets[k] = append(assets[k], u)
			if !seen[k] {
				seen[k] = true
				set.add(spelling[k], Evidence{Method: "URLs in the " + p.label, Mode: modePassive, URL: p.resp.URL.String(), Value: u.String(), Confidence: confPluginURLs})
			}
		}
	}
	for k, urls := range assets {
		for v, paths := range s.assetVersions(urls, core) {
			var example string
			for _, u := range urls {
				if u.Query().Get("ver") == v {
					example = u.String()
					break
				}
			}
			set.addVersion(spelling[k], Evidence{Method: "?ver= on the plugin's assets", Mode: modePassive, URL: example, Value: v, Confidence: assetVersionConfidence(len(paths))})
		}
	}
}

// pluginsFromSignatures applies the passive signatures to the homepage, the
// 404 page and the homepage headers.
func (s *Scanner) pluginsFromSignatures(set *componentSet) {
	hit := func(sig wordlists.Signature, pageURL string, m []string) {
		set.add(sig.Slug, Evidence{Method: sig.Method, Mode: modePassive, URL: pageURL, Value: truncate(m[0], 120), Confidence: sig.Confidence})
		if len(m) > 1 && m[1] != "" {
			set.addVersion(sig.Slug, Evidence{Method: sig.Method, Mode: modePassive, URL: pageURL, Value: vulndb.Normalize(m[1]), Confidence: confVersionSignature})
		}
	}
	contentPrefix := s.content.Path
	for _, p := range s.pages() {
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
					hit(sig, pageURL, m)
				}
			case wordlists.SigGenerator:
				for _, g := range p.generators {
					if m := sig.Re.FindStringSubmatch(g); m != nil {
						hit(sig, pageURL, m)
					}
				}
			case wordlists.SigPath:
				for _, rel := range paths {
					if sig.Re.MatchString(rel) {
						hit(sig, pageURL, []string{s.content.String() + rel})
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
						hit(sig, pageURL, m)
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
			set.add(m[1], Evidence{Method: "Meta generator", Mode: modePassive, URL: pageURL, Value: g, Confidence: confPluginGenerator})
			set.addVersion(m[1], Evidence{Method: "Meta generator", Mode: modePassive, URL: pageURL, Value: m[2], Confidence: confVersionGenericMeta})
		}
	}
}

// knownPlugin reports whether slug is a plugin cmsrecon knows of: in a
// slug list or in the vulnerability data.
func (s *Scanner) knownPlugin(slug string) bool {
	return s.data.lists.Known(wordlists.Plugins, slug) || len(s.data.vulns.Advisories(vulndb.KindPlugin, slug)) > 0
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
		case prefix != "" && s.knownPlugin(prefix):
			set.add(prefix, Evidence{Method: "REST API namespace", Mode: modePassive, URL: api.root, Value: ns, Confidence: confPluginRESTGuess})
		}
	}
}

// readReadme reads a plugin's readme for its name and version. dir is the
// plugin's parent directory under wp-content ("plugins/").
func (s *Scanner) readReadme(ctx context.Context, set *componentSet, c *component, dir string) {
	base := s.contentURL(dir + c.slug + "/")
	for _, name := range []string{"readme.txt", "README.txt", "readme.md", "README.md"} {
		u := base + name
		res := s.get(ctx, u)
		if res == nil || res.StatusCode != 200 {
			continue
		}
		info, ok := parseReadme(res.Body)
		if !ok {
			continue
		}
		set.mu.Lock()
		c.readme = u
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
		hasVersion := len(c.versions) > 0
		set.mu.Unlock()
		if hasVersion {
			return
		}
		break
	}
	// No version yet: some plugins keep the changelog in its own file.
	for _, name := range []string{"changelog.txt", "CHANGELOG.md", "changelog.md"} {
		u := base + name
		res := s.get(ctx, u)
		if res == nil || res.StatusCode != 200 {
			continue
		}
		if v := newestVersion(string(res.Body[:min(len(res.Body), 256<<10)])); v != "" && !isHTML(res.Body) {
			set.addVersion(c.slug, Evidence{Method: name, Mode: modeAggressive, URL: u, Value: v, Confidence: confVersionChangelog})
			return
		}
	}
}

func isHTML(body []byte) bool {
	head := strings.ToLower(string(body[:min(len(body), 1024)]))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html")
}
