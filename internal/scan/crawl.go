package scan

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// The crawl reads a few more pages than the homepage and the 404 page,
// because different templates load different plugins: a shop page loads
// the cart and payment plugins, a contact page the form plugin, a post
// the comment and sharing plugins, the login page the security and
// captcha plugins. It picks one page per kind of page, from the sitemaps
// and from the homepage's links, so a handful of requests that look like
// a visitor's covers most of what the site uses. Only links are followed;
// no path is guessed.

// maxSitemaps caps how many of the sitemap index's sitemaps are read for
// pages to crawl.
const maxSitemaps = 3

type crawlResult struct {
	pages     []labelledPage
	postTypes map[string]string // post type or taxonomy listed in a sitemap -> that sitemap's URL
}

var (
	coreSitemapRe    = regexp.MustCompile(`wp-sitemap-(posts|taxonomies|users)-([a-z0-9_-]+?)-\d+\.xml$`)
	pluginSitemapRe  = regexp.MustCompile(`/([a-z0-9_-]+?)-sitemap\d*\.xml$`)
	robotsSitemapRe  = regexp.MustCompile(`(?im)^\s*sitemap\s*:\s*(\S+)`)
	sitemapTaxonomy  = map[string]bool{"category": true, "post_tag": true, "tag": true, "product_cat": true, "product_tag": true, "author": true, "users": true, "local": true, "news": true, "video": true, "image": true}
	crawlSkipPathRes = regexp.MustCompile(`(?i)/(?:wp-admin|wp-content|wp-includes|wp-json|feed|comments|trackback|embed)(?:/|$)|/(?:xmlrpc|wp-login|wp-signup|wp-cron|wp-trackback|wp-comments-post|wp-activate)\.php$`)
)

// sitePages crawls once per scan and returns what it found.
func (s *Scanner) sitePages(ctx context.Context) *crawlResult {
	s.crawlOnce.Do(func() { s.crawled = s.crawl(ctx) })
	return s.crawled
}

func (s *Scanner) crawl(ctx context.Context) *crawlResult {
	r := &crawlResult{postTypes: map[string]string{}}
	if !s.aggressive() || s.opts.CrawlPages <= 0 {
		return r
	}
	st := s.steps()
	st.Start(stepPages)
	st.Update(stepPages, "sitemaps")
	defer func() {
		read := 0
		for _, p := range r.pages {
			if p.label != "sitemap" {
				read++
			}
		}
		st.Done(stepPages, countSummary(read, "pages read for plugins and themes", "no extra page read"))
	}()
	var candidates []string
	if idx := s.sitemapIndex(ctx); idx != nil {
		r.pages = append(r.pages, labelledPage{"sitemap", modeAggressive, idx})
		candidates = append(candidates, s.sitemapPages(ctx, idx, r.postTypes)...)
	}
	candidates = append(candidates, s.homeLinks()...)

	seen := map[string]bool{s.base.String(): true}
	if s.notFound != nil && s.notFound.resp != nil {
		seen[s.notFound.resp.URL.String()] = true
	}
	var urls []string
	for _, c := range candidates {
		if !seen[c] && len(urls) < s.opts.CrawlPages {
			seen[c] = true
			urls = append(urls, c)
		}
	}
	// The login page loads security, captcha and social login plugins.
	login := s.url("wp-login.php")
	urls = append(urls, login)

	st.Update(stepPages, fmt.Sprintf("%d pages", len(urls)))
	pages := make([]*page, len(urls))
	s.parallel(ctx, len(urls), func(i int) {
		res := s.get(ctx, urls[i])
		if res == nil || res.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "html") {
			return
		}
		if urls[i] == login && !loginFormRe.Match(res.Body) {
			return
		}
		pages[i] = parsePage(res)
	})
	for i, p := range pages {
		if p == nil {
			continue
		}
		label := "site pages"
		if urls[i] == login {
			label = "login page"
		}
		r.pages = append(r.pages, labelledPage{label, modeAggressive, p})
	}
	return r
}

// sitemapIndex finds the sitemap index: from robots.txt, then WordPress's
// own /wp-sitemap.xml, then /sitemap_index.xml (Yoast SEO, Rank Math).
func (s *Scanner) sitemapIndex(ctx context.Context) *page {
	var cands []string
	robots := s.base.ResolveReference(&url.URL{Path: "/robots.txt"}).String()
	if res := s.get(ctx, robots); res != nil && res.StatusCode == http.StatusOK {
		for _, m := range robotsSitemapRe.FindAllSubmatch(res.Body, 5) {
			if u, err := s.base.Parse(string(m[1])); err == nil && s.client.InScope(u) {
				cands = append(cands, u.String())
			}
		}
	}
	cands = append(cands, s.url("wp-sitemap.xml"), s.url("sitemap_index.xml"))
	for _, u := range uniqueStrings(cands) {
		res := s.get(ctx, u)
		// SEO plugins redirect WordPress's sitemap to their own.
		if res != nil && res.IsRedirect() {
			if loc, err := res.Location(); err == nil && s.client.InScope(loc) {
				res = s.get(ctx, loc.String())
			}
		}
		if res == nil || res.StatusCode != http.StatusOK {
			continue
		}
		head := strings.ToLower(string(res.Body[:min(len(res.Body), 4096)]))
		if strings.Contains(head, "<sitemapindex") || strings.Contains(head, "<urlset") {
			return parsePage(res)
		}
	}
	return nil
}

// sitemapPages records the post types the sitemap index lists and returns
// one page of each of the first few, most common kinds first.
func (s *Scanner) sitemapPages(ctx context.Context, idx *page, postTypes map[string]string) []string {
	locs := sitemapLocs(idx.resp.Body, 500)
	head := strings.ToLower(string(idx.resp.Body[:min(len(idx.resp.Body), 4096)]))
	if !strings.Contains(head, "<sitemapindex") {
		// A plain sitemap (a urlset) lists pages directly.
		return firstLinks(s, locs, maxSitemaps)
	}
	type sitemap struct{ kind, url string }
	var sitemaps []sitemap
	for _, u := range locs {
		if !s.client.InScope(u) {
			continue
		}
		kind, crawlable := "", false
		if cm := coreSitemapRe.FindStringSubmatch(u.Path); cm != nil {
			kind, crawlable = cm[2], cm[1] == "posts"
		} else if pm := pluginSitemapRe.FindStringSubmatch(u.Path); pm != nil {
			kind = pm[1]
			crawlable = !sitemapTaxonomy[kind]
		}
		if kind == "" {
			continue
		}
		if _, ok := postTypes[kind]; !ok {
			postTypes[kind] = u.String()
		}
		if crawlable {
			sitemaps = append(sitemaps, sitemap{kind, u.String()})
		}
	}
	rank := func(kind string) int {
		switch kind {
		case "page":
			return 0
		case "post":
			return 1
		case "product":
			return 2
		}
		return 3
	}
	// A stable sort keeps the index's order within a rank.
	slices.SortStableFunc(sitemaps, func(a, b sitemap) int { return rank(a.kind) - rank(b.kind) })
	if len(sitemaps) > maxSitemaps {
		sitemaps = sitemaps[:maxSitemaps]
	}

	out := make([]string, len(sitemaps))
	var mu sync.Mutex
	s.parallel(ctx, len(sitemaps), func(i int) {
		res := s.get(ctx, sitemaps[i].url)
		if res == nil || res.StatusCode != http.StatusOK {
			return
		}
		if links := firstLinks(s, sitemapLocs(res.Body, 20), 1); len(links) > 0 {
			mu.Lock()
			out[i] = links[0]
			mu.Unlock()
		}
	})
	var links []string
	for _, l := range out {
		if l != "" {
			links = append(links, l)
		}
	}
	return links
}

// sitemapLocs returns the first n <loc> URLs of a sitemap.
func sitemapLocs(body []byte, n int) []*url.URL {
	var out []*url.URL
	for _, m := range sitemapLocRe.FindAllSubmatch(body, n) {
		if u, err := url.Parse(html.UnescapeString(string(m[1]))); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// homeLinks returns the homepage's links to other pages of the site, one
// per first path segment ("/shop/...", "/contact/", "/2026/..."), in page
// order, so the navigation's pages come first and each kind of page is
// read once.
func (s *Scanner) homeLinks() []string {
	return firstLinks(s, s.home.anchors, -1)
}

// firstLinks filters links down to crawlable pages of the site, keeping
// the first link of each first path segment. n caps the result; -1 keeps
// them all.
func firstLinks(s *Scanner, links []*url.URL, n int) []string {
	var out []string
	groups := map[string]bool{}
	for _, u := range links {
		if n >= 0 && len(out) >= n {
			break
		}
		if !s.crawlable(u) {
			continue
		}
		rel := strings.TrimPrefix(u.Path, s.base.Path)
		group, _, _ := strings.Cut(strings.Trim(rel, "/"), "/")
		group += "?" + u.RawQuery
		if groups[group] || u.String() == s.base.String() {
			continue
		}
		groups[group] = true
		out = append(out, u.String())
	}
	return out
}

// crawlable reports whether u is a page of the site worth reading: in
// scope, under the scanned path, not an admin, API, feed or file URL, and
// without a query string other than WordPress's plain permalinks (?p=1,
// ?page_id=2), so that no link with side effects (add to cart, log out)
// is followed.
func (s *Scanner) crawlable(u *url.URL) bool {
	if !s.client.InScope(u) || !strings.HasPrefix(u.Path, s.base.Path) || crawlSkipPathRes.MatchString(u.Path) {
		return false
	}
	switch strings.ToLower(path.Ext(u.Path)) {
	case "", ".html", ".htm", ".php":
	default:
		return false
	}
	for k := range u.Query() {
		if k != "p" && k != "page_id" {
			return false
		}
	}
	return true
}
