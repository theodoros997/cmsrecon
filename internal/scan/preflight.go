package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

const maxRedirects = 10

// preflight fetches the homepage and decides whether the scan goes on. It
// returns false after recording a Stop in the result.
func (s *Scanner) preflight(ctx context.Context) bool {
	home, ok := s.fetchHomepage(ctx)
	if !ok {
		return false
	}
	s.home = parsePage(home)
	s.res.WebServer = detectServer(home.Header)
	s.server = s.res.WebServer.Family

	// The 404 page is the baseline for random directories next to the
	// homepage and a second page for passive detection.
	if b := s.baselineFor(ctx, s.base.ResolveReference(&url.URL{Path: "x/"})); b != nil {
		s.notFound = parsePage(b.resp)
	}

	content, contentFound := s.detectContentDir()
	if s.opts.ContentDir != "" {
		content, contentFound = s.dirOption(s.opts.ContentDir), true
	}
	s.content = content
	s.plugins = s.content.ResolveReference(&url.URL{Path: "plugins/"})
	if s.opts.PluginsDir != "" {
		s.plugins = s.dirOption(s.opts.PluginsDir)
	}
	s.themes = s.content.ResolveReference(&url.URL{Path: "themes/"})

	if s.wordPressCom(contentFound) {
		s.stop(StopWordPressCom, "The site is hosted on WordPress.com.",
			"WordPress.com, not the site owner, runs the infrastructure, so the site owner cannot authorize scanning it.")
		return false
	}

	wp := s.detectWordPress(ctx)
	if contentFound {
		wp.ContentURL = content.String()
	}
	s.res.WordPress = wp
	if !wp.Detected && !s.opts.Force {
		s.stop(StopNotWordPress, "The site does not look like WordPress.", "Use --force to scan it anyway.")
		return false
	}
	return true
}

// dirOption resolves --wp-content-dir or --wp-plugins-dir, a path
// relative to the scanned URL or an absolute URL, to a directory URL. A
// host outside the scope joins it: the user named it.
func (s *Scanner) dirOption(v string) *url.URL {
	u, err := s.base.Parse(strings.TrimSpace(v))
	if err != nil {
		u = s.base.ResolveReference(&url.URL{Path: v})
	}
	u.RawQuery, u.Fragment = "", ""
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	s.client.AddScope(u.Hostname())
	return u
}

func (s *Scanner) stop(code, msg, hint string) {
	s.res.Status = StatusStopped
	s.res.Stop = &Stop{Code: code, Message: msg, Hint: hint}
}

// fetchHomepage requests the homepage, following http<->https redirects on
// the same host, and other redirects only with --follow-redirect.
func (s *Scanner) fetchHomepage(ctx context.Context) (*httpclient.Response, bool) {
	u := s.base
	seen := map[string]bool{u.String(): true}
	for {
		res, err := s.client.Get(ctx, u.String())
		if err != nil {
			s.stop(StopConnectionFailed, fmt.Sprintf("Could not connect to %s: %v", u, err), "")
			return nil, false
		}
		switch res.StatusCode {
		case http.StatusUnauthorized:
			hint := "Use --http-auth USER:PASS."
			if s.opts.HTTPAuth != nil {
				hint = "The --http-auth credentials were rejected."
			}
			s.stop(StopHTTPAuthRequired, fmt.Sprintf("%s requires HTTP authentication (%s).", u, res.Header.Get("WWW-Authenticate")), hint)
			return nil, false
		case http.StatusProxyAuthRequired:
			s.stop(StopProxyAuthRequired, "The proxy requires authentication.", "Put the credentials in the proxy URL, e.g. --proxy http://user:pass@host:8080.")
			return nil, false
		case http.StatusForbidden:
			if !s.opts.Force {
				s.stop(StopForbidden, fmt.Sprintf("%s answered 403 Forbidden.", u), "A WAF or an IP allowlist may be blocking the scan. Use --force to scan anyway.")
				return nil, false
			}
		}
		if !res.IsRedirect() {
			s.base = u
			s.client.AddScope(u.Hostname())
			return res, true
		}

		loc, err := res.Location()
		if err != nil {
			s.base = u
			return res, true
		}
		if installPage(loc) {
			s.unfinishedInstall(loc)
			return nil, false
		}
		// As in WPScan, a redirect within the scope (the target host or a
		// --scope domain) is followed; others only with --follow-redirect.
		next := normalizeBase(loc)
		red := Redirect{From: u.String(), To: loc.String(), Status: res.StatusCode}
		switch {
		case s.client.InScope(next):
			red.Followed, red.Reason = true, RedirectInScope
		case s.opts.FollowRedirect:
			red.Followed, red.Reason = true, RedirectFollowFlag
			s.client.AddScope(next.Hostname())
		default:
			red.Reason = RedirectOutOfScope
		}
		s.res.Target.Redirects = append(s.res.Target.Redirects, red)
		if !red.Followed {
			s.stop(StopRedirect, fmt.Sprintf("The homepage redirects to %s, which is out of scope.", loc),
				fmt.Sprintf("Use --follow-redirect, or --scope %s, to scan it.", next.Hostname()))
			return nil, false
		}
		if seen[next.String()] || len(s.res.Target.Redirects) >= maxRedirects {
			s.stop(StopRedirect, fmt.Sprintf("The homepage keeps redirecting (last: %s).", loc),
				"The site may require a login or redirect every request; try the final URL with -u.")
			return nil, false
		}
		seen[next.String()] = true
		u = next
	}
}

// installPage reports whether u is the installer or the setup screen that
// WordPress redirects to until it is configured.
func installPage(u *url.URL) bool {
	return strings.HasSuffix(u.Path, "/wp-admin/install.php") || strings.HasSuffix(u.Path, "/wp-admin/setup-config.php")
}

func (s *Scanner) unfinishedInstall(loc *url.URL) {
	f := Finding{
		ID:         idUnfinishedInstall,
		Severity:   SeverityCritical,
		URL:        loc.String(),
		Confidence: 100,
		Evidence: []Evidence{{
			Method: "Homepage redirect", Mode: modePassive, URL: s.base.String(), Value: loc.String(), Confidence: 100,
		}},
	}
	if strings.HasSuffix(loc.Path, "setup-config.php") {
		f.Title = "WordPress is not configured (no wp-config.php)"
		f.Entries = []string{"Anyone can open the setup page, point the site at their own database and take it over."}
	} else {
		f.Title = "WordPress installation is not finished"
		f.Entries = []string{"Anyone can open the installer and create the administrator account."}
	}
	s.res.InterestingFindings = append(s.res.InterestingFindings, f)
	s.stop(StopUnfinishedInstall, "The site is in install mode; the other checks were skipped.", "")
}

// scriptExtRe matches the file names a redirect may point at, such as
// index.php; they are dropped to get the directory.
var scriptExtRe = regexp.MustCompile(`(?i)\.(?:php|html?|aspx?|jsp)$`)

// normalizeBase turns a redirect target into a base URL: no query or
// fragment, and a path that ends in "/".
func normalizeBase(u *url.URL) *url.URL {
	n := *u
	n.RawQuery, n.Fragment, n.RawPath = "", "", ""
	if scriptExtRe.MatchString(n.Path) {
		n.Path = path.Dir(n.Path)
	}
	if !strings.HasSuffix(n.Path, "/") {
		n.Path += "/"
	}
	return &n
}

func detectServer(h http.Header) *WebServer {
	v := h.Get("Server")
	l := strings.ToLower(v)
	family := "unknown"
	switch {
	case strings.Contains(l, "apache"):
		family = "apache"
	case strings.Contains(l, "nginx"), strings.Contains(l, "openresty"), strings.Contains(l, "tengine"):
		family = "nginx"
	case strings.Contains(l, "iis"):
		family = "iis"
	}
	return &WebServer{Header: v, Family: family}
}

// customContentRe finds a renamed content directory (e.g. Bedrock's /app/)
// from theme and plugin URLs.
var customContentRe = regexp.MustCompile(`^(.*/)?([^/]+)/(?:themes|plugins)/[^/]+/`)

// detectContentDir finds the wp-content directory from in-scope page URLs.
// It falls back to <base>wp-content/ and reports whether it found one.
func (s *Scanner) detectContentDir() (*url.URL, bool) {
	counts := map[string]int{}
	custom := map[string]int{}
	for _, p := range s.pages() {
		for _, u := range s.scopedURLs(p.page) {
			if i := strings.Index(u.Path, "/wp-content/"); i >= 0 {
				counts[u.Path[:i+len("/wp-content/")]]++
			} else if m := customContentRe.FindStringSubmatch(u.Path); m != nil && strings.EqualFold(u.Hostname(), s.base.Hostname()) {
				custom[m[1]+m[2]+"/"]++
			}
		}
	}
	if len(counts) == 0 {
		counts = custom
	}
	best, n := "", 0
	for p, c := range counts {
		if c > n || (c == n && p < best) {
			best, n = p, c
		}
	}
	if best == "" {
		return s.base.ResolveReference(&url.URL{Path: "wp-content/"}), false
	}
	return s.base.ResolveReference(&url.URL{Path: best}), true
}

var wpcomAssetRe = regexp.MustCompile(`(?i)^(?:s\d+\.wp\.com|[a-z0-9-]+\.files\.wordpress\.com)$`)

// wordPressCom reports whether the site runs on WordPress.com: a
// *.wordpress.com host, the WordPress.com generator, or, when the site
// serves no wp-content of its own, assets from WordPress.com's CDN. Jetpack
// sites also load from wp.com but have their own wp-content.
func (s *Scanner) wordPressCom(contentFound bool) bool {
	if strings.HasSuffix(strings.ToLower(s.base.Hostname()), ".wordpress.com") {
		return true
	}
	for _, g := range s.home.generators {
		if strings.EqualFold(g, "WordPress.com") {
			return true
		}
	}
	if contentFound {
		return false
	}
	for _, u := range s.home.urls {
		if wpcomAssetRe.MatchString(u.Hostname()) {
			return true
		}
	}
	return false
}

var loginFormRe = regexp.MustCompile(`(?i)<form[^>]+(?:id|name)=["']loginform["']`)

// detectWordPress looks for WordPress in the pages fetched so far and, unless
// the mode is passive, in the login page.
func (s *Scanner) detectWordPress(ctx context.Context) *WordPress {
	wp := &WordPress{}
	for _, p := range s.pages() {
		for _, u := range s.scopedURLs(p.page) {
			if strings.Contains(u.Path, "/wp-content/") || strings.Contains(u.Path, "/wp-includes/") {
				wp.Evidence = append(wp.Evidence, Evidence{
					Method: "wp-content or wp-includes URLs in the " + p.label, Mode: modePassive,
					URL: p.resp.URL.String(), Value: u.String(), Confidence: 100,
				})
				break
			}
		}
	}
	for _, g := range s.home.generators {
		if strings.HasPrefix(strings.ToLower(g), "wordpress") {
			wp.Evidence = append(wp.Evidence, Evidence{
				Method: "Meta generator", Mode: modePassive, URL: s.base.String(), Value: g, Confidence: 100,
			})
			break
		}
	}
	for _, l := range s.home.resp.Header.Values("Link") {
		if strings.Contains(l, "api.w.org") {
			wp.Evidence = append(wp.Evidence, Evidence{
				Method: "REST API Link header", Mode: modePassive, URL: s.base.String(), Value: l, Confidence: 100,
			})
			break
		}
	}
	if xp := s.home.resp.Header.Get("X-Pingback"); strings.HasSuffix(xp, "xmlrpc.php") {
		wp.Evidence = append(wp.Evidence, Evidence{
			Method: "X-Pingback header", Mode: modePassive, URL: s.base.String(), Value: xp, Confidence: 80,
		})
	}
	if len(wp.Evidence) == 0 && s.aggressive() {
		u := s.url("wp-login.php")
		if res := s.get(ctx, u); res != nil && res.StatusCode == 200 && loginFormRe.Match(res.Body) {
			wp.Evidence = append(wp.Evidence, Evidence{
				Method: "Login page", Mode: modeAggressive, URL: u, Confidence: 90,
			})
		}
	}
	wp.Detected = len(wp.Evidence) > 0
	return wp
}
