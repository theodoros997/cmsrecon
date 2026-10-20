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
	urls     []string
	versions []Evidence
}

// detectJSLibraries finds the JavaScript libraries (and a few CSS ones)
// the pages load: from their URLs, and aggressively from the version
// banners in the scripts themselves.
func (s *Scanner) detectJSLibraries(ctx context.Context) []*JSLibrary {
	var mu sync.Mutex
	libs := map[string]*jsCandidate{}
	add := func(d vulndb.JSDetection, where string, e *Evidence) {
		mu.Lock()
		defer mu.Unlock()
		c := libs[d.Library]
		if c == nil {
			c = &jsCandidate{}
			libs[d.Library] = c
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

	names := make([]string, 0, len(libs))
	for n := range libs {
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	out := make([]*JSLibrary, 0, len(names))
	for _, n := range names {
		c := libs[n]
		out = append(out, &JSLibrary{Name: n, URLs: c.urls, Version: combineVersions(c.versions)})
	}
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
