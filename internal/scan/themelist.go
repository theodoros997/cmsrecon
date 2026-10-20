package scan

import (
	"context"
	"path"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// Confidence of the signals for themes other than the main one.
const (
	confThemeOtherPageURLs = 80  // a page references the theme's files
	confThemeStyleHeader   = 100 // its style.css has a Theme Name header
)

// enumerateThemes finds the installed themes other than the main theme and
// its parent: passively from page URLs, aggressively by brute force (-e vt,
// t or at). Each theme's style.css gives its name and version.
func (s *Scanner) enumerateThemes(ctx context.Context, core *Version, main *Theme) []*Theme {
	exclude := map[string]bool{}
	for t := main; t != nil; t = t.Parent {
		exclude[strings.ToLower(t.Slug)] = true
	}
	set := newComponentSet()
	prefix := s.content.Path + "themes/"
	if s.passive() {
		for _, p := range s.pages() {
			seen := map[string]bool{}
			for _, u := range p.urls {
				sp, ok := s.sitePath(u)
				if !ok {
					continue
				}
				slug := slugIn(sp, prefix)
				k := strings.ToLower(slug)
				if slug == "" || exclude[k] {
					continue
				}
				if !seen[k] {
					seen[k] = true
					set.add(slug, Evidence{Method: "Theme URLs in the " + p.label, Mode: modePassive, URL: p.resp.URL.String(), Value: u.String(), Confidence: confThemeOtherPageURLs})
				}
				if v := u.Query().Get("ver"); path.Base(sp) == "style.css" && vulndb.Valid(v) && !isCoreVersion(v, core) {
					set.addVersion(slug, Evidence{Method: "?ver= on the theme's style.css", Mode: modePassive, URL: u.String(), Value: v, Confidence: confThemeStyleVer})
				}
			}
		}
	}
	if s.aggressive() && s.opts.Enumerate.Themes != cli.ItemsNone {
		var slugs []string
		for _, slug := range s.bruteList(wordlists.Themes, s.opts.Enumerate.Themes) {
			if !exclude[strings.ToLower(slug)] {
				slugs = append(slugs, slug)
			}
		}
		s.bruteForce(ctx, set, "Themes", "themes/", slugs)
	}

	comps := set.list()
	out := make([]*Theme, len(comps))
	for i, c := range comps {
		out[i] = s.newTheme(c.slug, "")
	}
	if s.aggressive() {
		s.parallel(ctx, len(comps), func(i int) {
			t := out[i]
			ev, _ := s.readStyle(ctx, t)
			if t.Name != "" {
				set.add(comps[i].slug, Evidence{Method: "style.css Theme Name header", Mode: modeAggressive, URL: t.StyleURL, Value: t.Name, Confidence: confThemeStyleHeader})
			}
			for _, e := range ev {
				set.addVersion(comps[i].slug, e)
			}
		})
	}
	for i, c := range comps {
		t := out[i]
		t.Evidence = c.evidence
		sortEvidence(t.Evidence)
		t.Confidence = combine(c.evidence)
		t.Version = combineVersions(c.versions)
		latest(t.Version, s.data.lists.Latest(wordlists.Themes, t.Slug))
	}
	return out
}

// themesFromInventory splits the --wp-auth theme list into the main theme
// (with its parent) and the others.
func (s *Scanner) themesFromInventory(inv *inventory) (*Theme, []*Theme) {
	if len(inv.themes) == 0 || inv.themes[0].Evidence[0].Value != "active" {
		return nil, inv.themes
	}
	main := inv.themes[0]
	var others []*Theme
	for _, t := range inv.themes[1:] {
		if main.Parent != nil && t.Slug == main.Parent.Slug {
			main.Parent = t
			continue
		}
		others = append(others, t)
	}
	if main.Parent != nil && main.Parent.Location == "" {
		main.Parent = s.newTheme(main.Parent.Slug, "")
	}
	for _, t := range append([]*Theme{main, main.Parent}, others...) {
		if t != nil {
			latest(t.Version, s.data.lists.Latest(wordlists.Themes, t.Slug))
		}
	}
	return main, others
}
