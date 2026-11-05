package scan

import (
	"context"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// Confidence of JavaScript library version signals.
const (
	confJSURL     = 80  // the version is in the URL path or file name
	confJSCoreVer = 80  // ?ver= on a library WordPress bundles in wp-includes
	confJSVer     = 30  // ?ver= elsewhere: often the plugin's or theme's version
	confJSContent = 100 // a version banner in the file
)

// maxScriptFetches caps how many scripts aggressive detection downloads.
const maxScriptFetches = 30

type jsCandidate struct {
	name     string
	urls     []string
	versions []Evidence
	bundled  bool // a copy WordPress core ships in wp-includes
}

// detectJSLibraries finds the JavaScript libraries (and a few CSS ones)
// the pages load: from their URLs, and aggressively from the version
// banners in the scripts themselves.
func (s *Scanner) detectJSLibraries(ctx context.Context) []*JSLibrary {
	var mu sync.Mutex
	libs := map[string]*jsCandidate{}
	// Each file is its own copy: core's jQuery 3.7.1 must not hide a
	// plugin's jquery-1.8.3.min.js.
	add := func(d vulndb.JSDetection, where string, e *Evidence) {
		mu.Lock()
		defer mu.Unlock()
		k := d.Library + "|" + copyKey(where)
		c := libs[k]
		if c == nil {
			c = &jsCandidate{name: d.Library}
			libs[k] = c
		}
		if u, err := url.Parse(where); err == nil && vulndb.CoreBundled(u.Path) {
			c.bundled = true
		}
		if where != "" && len(c.urls) < 5 && !slices.Contains(c.urls, where) {
			c.urls = append(c.urls, where)
		}
		if e != nil && !slices.ContainsFunc(c.versions, func(o Evidence) bool { return o.Method == e.Method && o.Value == e.Value }) {
			c.versions = append(c.versions, *e)
		}
	}

	for _, p := range s.discoveryPages(ctx) {
		for _, u := range p.urls {
			if isAsset(u) {
				for _, d := range s.data.js.FromURL(u) {
					add(d, u.String(), jsURLEvidence(d, u, p.mode))
				}
			}
		}
	}
	var scripts []string
	seen := map[string]bool{}
	for _, p := range append(s.pages(), s.sitePages(ctx).pages...) {
		for _, u := range p.urls {
			if isAsset(u) && s.client.InScope(u) && strings.HasSuffix(strings.ToLower(u.Path), ".js") && !seen[u.String()] {
				seen[u.String()] = true
				scripts = append(scripts, u.String())
			}
		}
	}

	if s.aggressive() {
		scripts = scripts[:min(len(scripts), maxScriptFetches)]
		s.parallel(ctx, len(scripts), func(i int) {
			res := s.get(ctx, scripts[i])
			if res == nil || res.StatusCode != 200 || isHTML(res.Body) {
				return
			}
			for _, d := range s.data.js.FromContent(res.Body) {
				add(d, scripts[i], &Evidence{Method: "Version banner in the file", Mode: modeAggressive, URL: scripts[i], Value: d.Version, Confidence: confJSContent})
			}
		})
	}

	return mergeCopies(libs)
}

// copyKey is a script's URL without its query: the same file with another
// ?ver= is the same copy.
func copyKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return strings.ToLower(u.Host) + u.Path
}

// mergeCopies turns the copies found into the report's libraries: one
// entry per library and version, the copies of the same version merged. A
// copy of unknown version is only kept when no copy of that library has a
// known one: it is most likely the same file loaded another way.
func mergeCopies(libs map[string]*jsCandidate) []*JSLibrary {
	type key struct{ name, version string }
	var order []key
	merged := map[key]*JSLibrary{}
	known := map[string]bool{}
	keys := make([]string, 0, len(libs))
	for k := range libs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		c := libs[k]
		v := combineVersions(c.versions)
		if v.Number != "" {
			known[c.name] = true
		}
		mk := key{c.name, v.Number}
		l := merged[mk]
		if l == nil {
			l = &JSLibrary{Name: c.name, Version: v}
			merged[mk] = l
			order = append(order, mk)
		} else {
			l.Version.Evidence = append(l.Version.Evidence, v.Evidence...)
			if v.Confidence > l.Version.Confidence {
				l.Version.Confidence, l.Version.Candidates = v.Confidence, v.Candidates
			}
		}
		for _, u := range c.urls {
			if len(l.URLs) < 5 && !slices.Contains(l.URLs, u) {
				l.URLs = append(l.URLs, u)
			}
		}
		l.Bundled = l.Bundled || c.bundled
	}
	out := make([]*JSLibrary, 0, len(order))
	for _, mk := range order {
		if mk.version == "" && known[mk.name] {
			continue
		}
		out = append(out, merged[mk])
	}
	slices.SortStableFunc(out, func(a, b *JSLibrary) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return vulndb.Compare(a.Version.Number, b.Version.Number)
	})
	return out
}

// isAsset reports whether a URL looks like a script or stylesheet,
// including CDN URLs such as /npm/jquery@3.6.0.
func isAsset(u *url.URL) bool {
	ext := strings.ToLower(path.Ext(u.Path))
	return ext == ".js" || ext == ".css" || strings.Contains(u.Path, "@")
}

func jsURLEvidence(d vulndb.JSDetection, u *url.URL, mode string) *Evidence {
	if d.Version == "" {
		return nil
	}
	e := &Evidence{Mode: mode, URL: u.String(), Value: d.Version}
	switch d.Method {
	case vulndb.JSMethodURL, vulndb.JSMethodFilename:
		e.Method, e.Confidence = "Version in the URL", confJSURL
	case vulndb.JSMethodVer:
		if vulndb.CoreBundled(u.Path) {
			e.Method, e.Confidence = "?ver= on the copy WordPress bundles", confJSCoreVer
		} else {
			e.Method, e.Confidence = "?ver= on the file", confJSVer
		}
	default:
		return nil
	}
	return e
}
