package scan

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// Caching and optimization plugins combine the plugins' and themes'
// stylesheets and scripts into one file, so the pages no longer link to
// their folders. The combined file still names them: url() references to
// their images and fonts, or source comments. Up to maxCombinedFiles of
// these files are read, stylesheets first.

const maxCombinedFiles = 3

var combinedAssetRe = regexp.MustCompile(`(?i)/(?:cache/autoptimize/|cache/min/|cache/wpfc-minified/|cache/minify/|cache/breeze-minification/|cache/swift-performance/|litespeed/(?:css|js|cssjs)/|siteground-optimizer-assets/|hummingbird-assets/|wphb-cache/)[^?#]*\.(?:css|js)$`)

type combinedFile struct {
	url  string
	body []byte
}

// combinedFiles fetches the combined files the discovery pages load, once
// per scan. Only aggressive scans request them.
func (s *Scanner) combinedFiles(ctx context.Context) []combinedFile {
	s.combinedOnce.Do(func() {
		if !s.aggressive() {
			return
		}
		var css, js []string
		seen := map[string]bool{}
		for _, p := range s.discoveryPages(ctx) {
			for _, u := range s.siteURLs(p.page) {
				if !combinedAssetRe.MatchString(u.Path) || seen[u.Path] {
					continue
				}
				seen[u.Path] = true
				if strings.HasSuffix(strings.ToLower(u.Path), ".css") {
					css = append(css, u.String())
				} else {
					js = append(js, u.String())
				}
			}
		}
		urls := append(css, js...)
		urls = urls[:min(len(urls), maxCombinedFiles)]
		files := make([]combinedFile, len(urls))
		s.parallel(ctx, len(urls), func(i int) {
			res := s.do(ctx, httpclient.Request{URL: urls[i], MaxBody: 4 << 20})
			if res != nil && res.StatusCode == http.StatusOK && !isHTML(res.Body) {
				files[i] = combinedFile{url: urls[i], body: res.Body}
			}
		})
		for _, f := range files {
			if f.body != nil {
				s.combined = append(s.combined, f)
			}
		}
	})
	return s.combined
}

// slugsInCombined returns the folders under dir ("/wp-content/plugins/")
// a combined file names, as written or JSON-escaped ("\/wp-content\/").
func slugsInCombined(body []byte, dir string) []string {
	var out []string
	tail := prefixTail(dir)
	for _, needle := range []string{tail, strings.ReplaceAll(tail, "/", `\/`)} {
		rest := body
		for {
			i := bytes.Index(rest, []byte(needle))
			if i < 0 {
				break
			}
			rest = rest[i+len(needle):]
			end := bytes.IndexAny(rest, `/\"')? `)
			if end <= 0 {
				continue
			}
			slug := string(rest[:end])
			if validSlug(slug) && !slices.Contains(out, slug) {
				out = append(out, slug)
			}
		}
	}
	return out
}
