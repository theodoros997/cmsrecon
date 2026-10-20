package scan

import (
	"bytes"
	"context"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Confidence of each main theme signal.
const (
	confThemeBodyClass    = 100
	confThemeStyleLink    = 70
	confThemeURLs         = 40
	confThemeOtherURLs    = 10
	confThemeWooFramework = 80
	confThemeStyleVersion = 80
	confThemeStyleVer     = 50
)

type themeCandidate struct {
	location string
	evidence []Evidence
}

// detectMainTheme finds the active theme from the homepage and the 404 page.
// All its signals are passive; in aggressive or mixed mode the theme's
// style.css is then read for its name, version and parent theme. core is
// the detected WordPress version (may be nil): WordPress puts its own
// version in ?ver= when a theme enqueues its stylesheet without one.
func (s *Scanner) detectMainTheme(ctx context.Context, core *Version) *Theme {
	if !s.passive() {
		return nil
	}
	themeURLRe := regexp.MustCompile(`^(.*/` + regexp.QuoteMeta(path.Base(s.content.Path)) + `/themes/)([^/]+)/`)
	slugOf := func(u *url.URL) (slug, location string) {
		m := themeURLRe.FindStringSubmatch(u.Path)
		if m == nil || m[2] == "." || m[2] == ".." {
			return "", ""
		}
		loc := url.URL{Scheme: u.Scheme, Host: u.Host, Path: m[1] + m[2] + "/"}
		return m[2], loc.String()
	}

	cands := map[string]*themeCandidate{}
	add := func(slug, location string, e Evidence) {
		c := cands[slug]
		if c == nil {
			c = &themeCandidate{}
			cands[slug] = c
		}
		if c.location == "" {
			c.location = location
		}
		c.evidence = append(c.evidence, e)
	}

	var parentHint string
	styleVer := map[string]Evidence{} // ?ver= on each theme's style.css link
	for _, p := range s.pages() {
		pageURL := p.resp.URL.String()
		var child, parent string
		for _, c := range p.bodyClasses {
			if v, ok := strings.CutPrefix(c, "wp-child-theme-"); ok {
				child = v
			} else if v, ok := strings.CutPrefix(c, "wp-theme-"); ok {
				parent = v
			}
		}
		switch {
		case child != "":
			add(child, "", Evidence{Method: "wp-child-theme body class", Mode: modePassive, URL: pageURL, Value: child, Confidence: confThemeBodyClass})
			parentHint = parent
		case parent != "":
			add(parent, "", Evidence{Method: "wp-theme body class", Mode: modePassive, URL: pageURL, Value: parent, Confidence: confThemeBodyClass})
		}

		// A child theme's style.css is enqueued after its parent's, so only
		// the last theme style.css on the page counts as the main theme's.
		var lastStyle *url.URL
		for _, href := range p.linksTo("stylesheet") {
			slug, _ := slugOf(href)
			if slug == "" || !s.client.InScope(href) || path.Base(href.Path) != "style.css" {
				continue
			}
			lastStyle = href
			if _, seen := styleVer[slug]; !seen {
				styleVer[slug] = Evidence{Method: "?ver= on the theme's style.css", Mode: modePassive, URL: href.String(),
					Value: href.Query().Get("ver"), Confidence: confThemeStyleVer}
			}
		}
		if lastStyle != nil {
			slug, loc := slugOf(lastStyle)
			add(slug, loc, Evidence{Method: "style.css link in the " + p.label, Mode: modePassive, URL: pageURL, Value: lastStyle.String(), Confidence: confThemeStyleLink})
		}

		counts := map[string]int{}
		locs := map[string]string{}
		for _, u := range s.scopedURLs(p.page) {
			if slug, loc := slugOf(u); slug != "" {
				counts[slug]++
				locs[slug] = loc
			}
		}
		// The theme with the most URLs is a decent guess; the others stay
		// candidates (a child theme often has fewer assets than its parent).
		best := mostCommon(counts)
		for slug, loc := range locs {
			c := confThemeOtherURLs
			if slug == best {
				c = confThemeURLs
			}
			add(slug, loc, Evidence{Method: "Theme URLs in the " + p.label, Mode: modePassive, URL: pageURL, Value: slug, Confidence: c})
		}
	}
	wooVersions := s.wooFrameworkTheme(add)

	ranked := make([]string, 0, len(cands))
	conf := map[string]int{}
	for slug, c := range cands {
		ranked = append(ranked, slug)
		conf[slug] = combine(c.evidence)
	}
	if len(ranked) == 0 {
		return nil
	}
	sort.Slice(ranked, func(i, j int) bool {
		if conf[ranked[i]] != conf[ranked[j]] {
			return conf[ranked[i]] > conf[ranked[j]]
		}
		return ranked[i] < ranked[j]
	})
	themeFor := func(slug string) *Theme {
		t := s.newTheme(slug, cands[slug].location)
		t.Confidence = conf[slug]
		t.Evidence = cands[slug].evidence
		sortEvidence(t.Evidence)
		return t
	}

	t := themeFor(ranked[0])
	versionEv := wooVersions[t.Slug]
	parentSlug := parentHint
	parentEv := Evidence{Method: "wp-theme body class", Mode: modePassive, URL: s.base.String(), Value: parentHint, Confidence: 100}
	if s.aggressive() {
		ev, template := s.readStyle(ctx, t)
		if template == "" && !fromBodyClass(t.Evidence) {
			// The leader may be the parent of the active theme: a runner-up
			// whose Template header names it is the child, and the main theme.
			for _, slug := range ranked[1:min(len(ranked), 3)] {
				child := themeFor(slug)
				cev, ctemplate := s.readStyle(ctx, child)
				if ctemplate == t.Slug {
					child.Evidence = append(child.Evidence, Evidence{
						Method: "Child of " + t.Slug + " (style.css Template header)", Mode: modeAggressive,
						URL: child.StyleURL, Value: t.Slug, Confidence: 100,
					})
					child.Confidence = combine(child.Evidence)
					sortEvidence(child.Evidence)
					t, ev, template = child, cev, ctemplate
					versionEv = wooVersions[t.Slug]
					break
				}
			}
		}
		versionEv = append(versionEv, ev...)
		if template != "" {
			parentSlug = template
			parentEv = Evidence{Method: "Template header of the main theme", Mode: modeAggressive, URL: t.StyleURL, Value: template, Confidence: 100}
		}
	}
	t.Version = combineVersions(append(versionEv, themeStyleVer(styleVer, t.Slug, core)...))

	if parentSlug != "" && parentSlug != t.Slug {
		parent := s.newTheme(parentSlug, strings.TrimSuffix(t.Location, t.Slug+"/")+parentSlug+"/")
		parent.Confidence = 100
		parent.Evidence = []Evidence{parentEv}
		var pv []Evidence
		if s.aggressive() {
			pv, _ = s.readStyle(ctx, parent)
		}
		parent.Version = combineVersions(append(pv, themeStyleVer(styleVer, parentSlug, core)...))
		t.Parent = parent
	}
	return t
}

func (s *Scanner) newTheme(slug, location string) *Theme {
	if location == "" {
		location = s.contentURL("themes/" + slug + "/")
	}
	return &Theme{Slug: slug, Location: location, StyleURL: location + "style.css", Evidence: []Evidence{}}
}

func fromBodyClass(ev []Evidence) bool {
	for _, e := range ev {
		if strings.HasSuffix(e.Method, "body class") {
			return true
		}
	}
	return false
}

func mostCommon(counts map[string]int) string {
	best, n := "", 0
	for k, c := range counts {
		if c > n || (c == n && k < best) {
			best, n = k, c
		}
	}
	return best
}

// wooFrameworkTheme reads the theme from the meta generators WooFramework
// themes add: "WooFramework 5.5.5" next to "<Theme Name> <version>". It
// returns the version evidence by theme slug.
func (s *Scanner) wooFrameworkTheme(add func(slug, location string, e Evidence)) map[string][]Evidence {
	woo := false
	for _, g := range s.home.generators {
		woo = woo || strings.HasPrefix(g, "WooFramework")
	}
	if !woo {
		return nil
	}
	ev := map[string][]Evidence{}
	for _, g := range s.home.generators {
		i := strings.LastIndexByte(g, ' ')
		if i <= 0 || strings.HasPrefix(g, "WooFramework") || strings.HasPrefix(strings.ToLower(g), "wordpress") || strings.HasPrefix(g, "WooCommerce") {
			continue
		}
		name, ver := g[:i], g[i+1:]
		slug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", "-"))
		add(slug, "", Evidence{Method: "WooFramework meta generator", Mode: modePassive, URL: s.base.String(), Value: g, Confidence: confThemeWooFramework})
		if validVersion(ver) {
			ev[slug] = append(ev[slug], Evidence{Method: "WooFramework meta generator", Mode: modePassive, URL: s.base.String(), Value: ver, Confidence: confThemeWooFramework})
		}
	}
	return ev
}

// styleHeader returns the value of a theme header such as "Version" from the
// comment at the top of style.css.
func styleHeader(css []byte, field string) string {
	re := regexp.MustCompile(`(?mi)^[ \t/*#@]*` + regexp.QuoteMeta(field) + `:(.*)$`)
	m := re.FindSubmatch(css)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(string(m[1])), "*/"))
}

// readStyle fills in the theme's headers from its style.css and returns the
// version evidence and the parent theme (Template header).
func (s *Scanner) readStyle(ctx context.Context, t *Theme) ([]Evidence, string) {
	res := s.get(ctx, t.StyleURL)
	if res == nil || res.StatusCode != 200 {
		return nil, ""
	}
	header := styleHeaderBlock(res.Body)
	name := styleHeader(header, "Theme Name")
	if name == "" {
		return nil, ""
	}
	t.Name = name
	t.ThemeURI = styleHeader(header, "Theme URI")
	t.Author = styleHeader(header, "Author")
	t.AuthorURI = styleHeader(header, "Author URI")
	var ev []Evidence
	if v := styleHeader(header, "Version"); v != "" {
		ev = append(ev, Evidence{Method: "style.css Version header", Mode: modeAggressive, URL: t.StyleURL, Value: v, Confidence: confThemeStyleVersion})
	}
	return ev, styleHeader(header, "Template")
}

// styleHeaderBlock returns the comment at the top of a stylesheet, where the
// theme headers are (WordPress reads them from the first 8 KB). Later
// comments can contain lines such as "Template: Cover" that are not headers.
func styleHeaderBlock(css []byte) []byte {
	css = css[:min(len(css), 8<<10)]
	if i := bytes.Index(css, []byte("*/")); i >= 0 {
		return css[:i]
	}
	return css
}

// themeStyleVer returns the ?ver= evidence of a theme's style.css link, unless
// it is not a version or equals a WordPress core version candidate.
func themeStyleVer(styleVer map[string]Evidence, slug string, core *Version) []Evidence {
	e, ok := styleVer[slug]
	if !ok || !validVersion(e.Value) {
		return nil
	}
	if core != nil {
		for _, c := range core.Candidates {
			if c.Number == e.Value {
				return nil
			}
		}
	}
	return []Evidence{e}
}
