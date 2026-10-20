package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// restAPI is the site's REST API root and its index.
type restAPI struct {
	root       string // e.g. https://example.com/wp-json/ or https://example.com/?rest_route=/
	query      bool   // routes go in ?rest_route= (no pretty permalinks)
	namespaces []string
}

// route returns the URL of a REST route such as "wp/v2/users", with an
// optional raw query.
func (r *restAPI) route(route, rawQuery string) string {
	if r.query {
		u, _ := url.Parse(r.root)
		q := "rest_route=" + url.QueryEscape("/"+route)
		if rawQuery != "" {
			q += "&" + rawQuery
		}
		u.RawQuery = q
		return u.String()
	}
	u := r.root + route
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	return u
}

var linkAPIRe = regexp.MustCompile(`<([^>]+)>;\s*rel="https://api\.w\.org/"`)

// rest finds the REST API and reads its index, once per scan: the root
// the homepage's Link header advertises, then, unless the mode is passive,
// /wp-json/ and ?rest_route=/. It returns nil when the API does not
// answer.
func (s *Scanner) rest(ctx context.Context) *restAPI {
	s.restOnce.Do(func() {
		var roots []string
		for _, l := range s.home.resp.Header.Values("Link") {
			if m := linkAPIRe.FindStringSubmatch(l); m != nil {
				if u, err := s.base.Parse(m[1]); err == nil && s.client.InScope(u) {
					roots = append(roots, u.String())
				}
			}
		}
		if s.aggressive() {
			roots = append(roots, s.url("wp-json/"), s.urlWithQuery("", "rest_route=/"))
		}
		for _, root := range uniqueStrings(roots) {
			res := s.get(ctx, root)
			if res == nil || res.StatusCode != http.StatusOK {
				continue
			}
			var idx struct {
				Namespaces []string `json:"namespaces"`
			}
			if json.Unmarshal(res.Body, &idx) != nil || len(idx.Namespaces) == 0 {
				continue
			}
			api := &restAPI{root: root, namespaces: idx.Namespaces}
			if u, _ := url.Parse(root); u != nil && u.Query().Has("rest_route") {
				u.RawQuery = ""
				api.root, api.query = u.String(), true
			} else if !strings.HasSuffix(api.root, "/") {
				api.root += "/"
			}
			s.restAPI = api
			return
		}
	})
	return s.restAPI
}

// inventory is the exact plugin and theme list read with --wp-auth.
type inventory struct {
	plugins []*Plugin
	themes  []*Theme // the active theme first
}

const methodInventory = "REST API inventory (--wp-auth)"

// restInventory reads /wp/v2/plugins (WordPress 5.5+) and /wp/v2/themes
// (5.7+) with an Application Password, once per scan. It returns nil and a
// notice when that fails, and the scan enumerates instead.
func (s *Scanner) restInventory(ctx context.Context) *inventory {
	if s.opts.WPAuth == nil {
		return nil
	}
	s.invOnce.Do(func() {
		api := s.rest(ctx)
		if api == nil {
			s.notice("--wp-auth: the REST API does not answer, so plugins and themes were enumerated instead.")
			return
		}
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.opts.WPAuth.Username+":"+s.opts.WPAuth.Password))
		fetch := func(route string, v any) (string, error) {
			u := api.route(route, "per_page=100")
			res := s.do(ctx, httpclient.Request{URL: u, Header: http.Header{"Authorization": {auth}}})
			switch {
			case res == nil:
				return u, fmt.Errorf("%s failed", u)
			case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
				return u, fmt.Errorf("the credentials were rejected or lack the rights (HTTP %d on %s)", res.StatusCode, route)
			case res.StatusCode != http.StatusOK:
				return u, fmt.Errorf("HTTP %d on %s (plugins need WordPress 5.5, themes 5.7)", res.StatusCode, route)
			}
			if err := json.Unmarshal(res.Body, v); err != nil {
				return u, fmt.Errorf("%s did not return a list: %v", route, err)
			}
			return u, nil
		}

		var plugins []struct {
			Plugin  string `json:"plugin"`
			Status  string `json:"status"`
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		pu, err := fetch("wp/v2/plugins", &plugins)
		if err != nil {
			s.notice("--wp-auth: %v; plugins and themes were enumerated instead.", err)
			return
		}
		inv := &inventory{}
		for _, p := range plugins {
			slug, _, _ := strings.Cut(p.Plugin, "/")
			slug = strings.TrimSuffix(slug, ".php")
			if slug == "" {
				continue
			}
			ev := Evidence{Method: methodInventory, Mode: modeAggressive, URL: pu, Value: p.Status, Confidence: 100}
			pl := &Plugin{Slug: slug, Name: p.Name, Location: under(s.plugins, slug+"/"), Confidence: 100, Evidence: []Evidence{ev}}
			pl.Version = combineVersions(versionEvidence(pu, p.Version))
			inv.plugins = append(inv.plugins, pl)
		}

		var themes []struct {
			Stylesheet string `json:"stylesheet"`
			Template   string `json:"template"`
			Status     string `json:"status"`
			Version    string `json:"version"`
			Name       struct {
				Raw      string `json:"raw"`
				Rendered string `json:"rendered"`
			} `json:"name"`
		}
		tu, err := fetch("wp/v2/themes", &themes)
		if err != nil {
			s.notice("--wp-auth: %v; themes were detected without it.", err)
		}
		for _, t := range themes {
			if t.Stylesheet == "" {
				continue
			}
			th := s.newTheme(t.Stylesheet, "")
			th.Name = t.Name.Raw
			if th.Name == "" {
				th.Name = t.Name.Rendered
			}
			th.Confidence = 100
			th.Evidence = []Evidence{{Method: methodInventory, Mode: modeAggressive, URL: tu, Value: t.Status, Confidence: 100}}
			th.Version = combineVersions(versionEvidence(tu, t.Version))
			if t.Template != "" && t.Template != t.Stylesheet {
				th.Parent = &Theme{Slug: t.Template} // resolved against the list below
			}
			if t.Status == "active" {
				inv.themes = append([]*Theme{th}, inv.themes...)
			} else {
				inv.themes = append(inv.themes, th)
			}
		}
		s.inv = inv
	})
	return s.inv
}

func versionEvidence(u, v string) []Evidence {
	if v == "" {
		return nil
	}
	return []Evidence{{Method: methodInventory, Mode: modeAggressive, URL: u, Value: v, Confidence: 100}}
}
