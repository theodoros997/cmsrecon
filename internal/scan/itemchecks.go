package scan

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// abandonedAfter is how long without an update on WordPress.org makes a
// plugin or theme look abandoned. WordPress.org itself warns after two
// years.
const abandonedAfter = 2 * 365 * 24 * time.Hour

// itemCheck is a plugin or theme folder to look into.
type itemCheck struct {
	folder   string // its folder URL; empty when it was never seen
	kind     string // wordlists.Plugins or wordlists.Themes
	slug     string
	updated  *string   // where to store the last updated date
	warnings *[]string // where to add warnings
}

// checkItems looks into the folder of every plugin and theme found, as
// WPScan does: a directory listing, and an error_log left by PHP (cPanel
// writes one in the folder of the script that failed), which can disclose
// paths and data. It also notes when WordPress.org last saw an update.
// That is two requests per item, and only outside passive mode. It
// returns how many warnings it added.
func (s *Scanner) checkItems(ctx context.Context) int {
	r := s.res
	var items []itemCheck
	for _, p := range r.Plugins {
		items = append(items, itemCheck{p.Location, wordlists.Plugins, p.Slug, &p.LastUpdated, &p.Warnings})
	}
	themes := append([]*Theme{}, r.Themes...)
	for t := r.MainTheme; t != nil; t = t.Parent {
		themes = append(themes, t)
	}
	for _, t := range themes {
		items = append(items, itemCheck{t.Location, wordlists.Themes, t.Slug, &t.LastUpdated, &t.Warnings})
	}
	for _, it := range items {
		if d := s.data.lists.LastUpdated(it.kind, it.slug); d != "" {
			*it.updated = d
			if t, err := time.Parse("2006-01-02", d); err == nil && s.res.StartedAt.Sub(t) > abandonedAfter {
				*it.warnings = append(*it.warnings, fmt.Sprintf("Not updated on WordPress.org since %s: it may be abandoned", d))
			}
		}
	}
	if !s.aggressive() {
		return 0
	}
	var added atomic.Int32
	s.parallel(ctx, len(items), func(i int) {
		it := items[i]
		if it.folder == "" {
			return
		}
		var warn []string
		if names, ok := s.dirListing(s.get(ctx, it.folder)); ok {
			entries := fmt.Sprintf("%d entries", len(names))
			if len(names) == 1 {
				entries = "1 entry"
			}
			warn = append(warn, fmt.Sprintf("Directory listing is enabled: %s (%s)", it.folder, entries))
		}
		u := it.folder + "error_log"
		if res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 64 << 10}); res != nil && res.StatusCode == http.StatusOK && debugLogRe.Match(res.Body) {
			warn = append(warn, "A PHP error log is exposed: "+u)
		}
		s.mu.Lock()
		*it.warnings = append(*it.warnings, warn...)
		s.mu.Unlock()
		added.Add(int32(len(warn)))
	})
	return int(added.Load())
}

var (
	firstCommentRe = regexp.MustCompile(`/\*[\s\S]*?\*/`)
	bannerVerRe    = regexp.MustCompile(`(?i)(?:\bv|\bversion[:\s]+|@version\s+)(\d+\.\d+(?:\.\d+){0,2})\b`)
)

// bannerVersion reads a plugin's version from the comment at the top of
// one of its own scripts or stylesheets ("/*! elementor - v3.5.0 */"),
// for plugins whose readme gave none. The comment must name the plugin, so
// that the banner of a library bundled in the file is not taken for it.
// Only files the pages load are read: no path is guessed. live reports
// whether one of the files answered, which proves the plugin is there.
func (s *Scanner) bannerVersion(ctx context.Context, slug string, assets []string) (version, from string, live bool) {
	names := []string{strings.ToLower(slug)}
	if first, _, _ := strings.Cut(names[0], "-"); len(first) >= 4 && first != names[0] {
		names = append(names, first)
	}
	tried := 0
	for _, u := range assets {
		if tried == 2 {
			break
		}
		if vendored(u) || !(strings.HasSuffix(pathOf(u), ".js") || strings.HasSuffix(pathOf(u), ".css")) || s.isLibraryURL(u) {
			continue
		}
		tried++
		res := s.get(ctx, u)
		if res == nil || res.StatusCode != http.StatusOK || isHTML(res.Body) {
			continue
		}
		live = true
		// The banner is the file's first comment, at its top.
		head := res.Body[:min(len(res.Body), 4096)]
		loc := firstCommentRe.FindIndex(head)
		if loc == nil || loc[0] > 200 {
			continue
		}
		block := head[loc[0]:loc[1]]
		lower := strings.ToLower(string(block))
		named := false
		for _, n := range names {
			named = named || strings.Contains(lower, n) || strings.Contains(lower, strings.ReplaceAll(n, "-", " "))
		}
		if !named {
			continue
		}
		if m := bannerVerRe.FindSubmatch(block); m != nil && vulndb.Valid(string(m[1])) {
			return string(m[1]), u, true
		}
	}
	return "", "", live
}
