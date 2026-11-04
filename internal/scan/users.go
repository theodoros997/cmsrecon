package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// Confidence of user signals.
const (
	confUserAuthorLink = 80  // an author archive link on a page
	confUserFeed       = 60  // a dc:creator in a feed: a display name only
	confUserDirect     = 100 // REST API, oEmbed, sitemaps, author ID redirects
	confUserArchive    = 90  // an author archive page's body class
)

var (
	authorPathRe   = regexp.MustCompile(`/author/([^/?#]+)/?$`)
	dcCreatorRe    = regexp.MustCompile(`(?s)<dc:creator>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</dc:creator>`)
	sitemapLocRe   = regexp.MustCompile(`<loc>\s*([^<\s]+)\s*</loc>`)
	authorClassRe  = regexp.MustCompile(`<body[^>]+class=["'][^"']*\bauthor-([a-z0-9_.@-]+)\b[^"']*\bauthor-(\d+)\b`)
	titleRe        = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	titleAuthorRes = []*regexp.Regexp{
		regexp.MustCompile(`^(.+?), Author at `),
		regexp.MustCompile(`^(.+?)(?:, Autor| – | - | \| | — | :: )`),
	}
)

// userSet merges users seen by different finders. Two sightings are the
// same user when they share an ID or a username, or when one has only a
// display name that the other has too.
type userSet struct {
	mu    sync.Mutex
	users []*User
}

func (us *userSet) add(id int, username, display string, e Evidence) {
	us.mu.Lock()
	defer us.mu.Unlock()
	username, display = strings.TrimSpace(username), strings.TrimSpace(html.UnescapeString(display))
	// An ID or a username identifies a user; a display name only matches
	// an entry that lacks the other's username.
	i := slices.IndexFunc(us.users, func(c *User) bool {
		return (id != 0 && c.ID == id) || (username != "" && strings.EqualFold(c.Username, username))
	})
	if i < 0 && display != "" {
		i = slices.IndexFunc(us.users, func(c *User) bool {
			return c.DisplayName == display && (username == "" || c.Username == "") && (id == 0 || c.ID == 0)
		})
	}
	u := &User{}
	if i >= 0 {
		u = us.users[i]
	} else {
		us.users = append(us.users, u)
	}
	merge(u, &User{ID: id, Username: username, DisplayName: display, Evidence: []Evidence{e}})
}

// commentsFeed reports whether a feed URL is a comments feed: the site's
// (/comments/feed/, ?feed=comments-rss2) or a post's (/2026/10/post/feed/).
func commentsFeed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if strings.HasPrefix(u.Query().Get("feed"), "comments") {
		return true
	}
	p := strings.TrimSuffix(strings.ToLower(u.Path), "/")
	if strings.Contains(p, "/comments/feed") {
		return true
	}
	// A post's feed: /<post>/feed, but not the site's /feed, nor the
	// category, tag and author feeds, which list posts.
	before, ok := strings.CutSuffix(p, "/feed")
	if !ok {
		before, ok = strings.CutSuffix(strings.TrimSuffix(p, "/atom"), "/feed")
	}
	if !ok || before == "" {
		return false
	}
	for _, listing := range []string{"/category/", "/tag/", "/author/", "/type/"} {
		if strings.Contains(before+"/", listing) {
			return false
		}
	}
	return true
}

// merge copies what u lacks from o and adds o's evidence.
func merge(u, o *User) {
	if u.ID == 0 {
		u.ID = o.ID
	}
	if u.Username == "" {
		u.Username = o.Username
	}
	if u.DisplayName == "" {
		u.DisplayName = o.DisplayName
	}
	u.Evidence = append(u.Evidence, o.Evidence...)
}

// list merges entries that turned out to be the same user (sightings can
// arrive in any order), and sorts by ID, then name.
func (us *userSet) list() []*User {
	var out []*User
	for _, u := range us.users {
		i := slices.IndexFunc(out, func(o *User) bool {
			switch {
			case u.ID != 0 && o.ID != 0:
				return u.ID == o.ID
			case u.Username != "" && o.Username != "":
				return strings.EqualFold(u.Username, o.Username)
			}
			return u.DisplayName != "" && u.DisplayName == o.DisplayName
		})
		if i >= 0 {
			merge(out[i], u)
			continue
		}
		out = append(out, u)
	}
	// A display name that is another entry's username, with no other
	// display name, is that user seen in a feed.
	var merged []*User
	for _, u := range out {
		if u.ID == 0 && u.Username == "" && u.DisplayName != "" {
			j := slices.IndexFunc(out, func(o *User) bool {
				return o != u && o.Username != "" && strings.EqualFold(o.Username, u.DisplayName) && (o.DisplayName == "" || o.DisplayName == u.DisplayName)
			})
			if j >= 0 {
				merge(out[j], u)
				continue
			}
		}
		merged = append(merged, u)
	}
	out = merged
	for _, u := range out {
		u.Confidence = combine(u.Evidence)
		sortEvidence(u.Evidence)
	}
	slices.SortStableFunc(out, func(a, b *User) int {
		switch {
		case a.ID != 0 && b.ID != 0:
			return a.ID - b.ID
		case a.ID != 0:
			return -1
		case b.ID != 0:
			return 1
		}
		return strings.Compare(a.Username+a.DisplayName, b.Username+b.DisplayName)
	})
	return out
}

// enumerateUsers finds user accounts (-e u). It never submits a login.
func (s *Scanner) enumerateUsers(ctx context.Context) []*User {
	ids := s.opts.Enumerate.Users
	if ids == nil {
		return nil
	}
	us := &userSet{}
	for _, p := range s.discoveryPages(ctx) {
		for _, u := range s.scopedURLs(p.page) {
			if m := authorPathRe.FindStringSubmatch(u.Path); m != nil {
				slug, _ := url.PathUnescape(m[1])
				us.add(0, slug, "", Evidence{Method: "Author links in the " + p.label, Mode: p.mode, URL: p.resp.URL.String(), Value: u.String(), Confidence: confUserAuthorLink})
			}
		}
	}
	if s.passive() {
		for _, f := range s.linkedFeeds() {
			// A comments feed names the people who commented, who
			// are not users of the site.
			if !commentsFeed(f) {
				s.usersFromFeed(ctx, us, f, modePassive)
			}
		}
	}
	if s.aggressive() {
		var wg sync.WaitGroup
		wg.Go(func() { s.usersFromFeed(ctx, us, s.url("feed/"), modeAggressive) })
		wg.Go(func() { s.usersFromREST(ctx, us) })
		wg.Go(func() { s.usersFromOEmbed(ctx, us) })
		wg.Go(func() {
			// The author sitemaps the sitemap index lists, then the
			// usual names (the index can be missing or unlinked).
			sitemaps := map[string]string{s.url("wp-sitemap-users-1.xml"): "WordPress users sitemap", s.url("author-sitemap.xml"): "Yoast author sitemap"}
			for kind, u := range s.sitePages(ctx).postTypes {
				if kind == "users" || kind == "author" {
					sitemaps[u] = "Author sitemap in the sitemap index"
				}
			}
			for _, u := range slices.Sorted(maps.Keys(sitemaps)) {
				s.usersFromSitemap(ctx, us, u, sitemaps[u])
			}
		})
		wg.Go(func() { s.usersFromAuthorIDs(ctx, us, ids.From, ids.To) })
		wg.Wait()
	}
	return us.list()
}

// usersFromPosts reads the authors WordPress embeds in the REST API's
// posts (?_embed=author), which stays open on many sites that close the
// users route.
func (s *Scanner) usersFromPosts(ctx context.Context, us *userSet, api *restAPI) {
	q := "per_page=100&_embed=author&_fields=author,_links,_embedded"
	u := s.urlWithQuery("wp-json/wp/v2/posts", q)
	if api != nil {
		u = api.route("wp/v2/posts", q)
	}
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != http.StatusOK {
		return
	}
	var posts []struct {
		Embedded struct {
			Author []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
				Slug string `json:"slug"`
			} `json:"author"`
		} `json:"_embedded"`
	}
	if json.Unmarshal(res.Body, &posts) != nil {
		return
	}
	for _, p := range posts {
		for _, a := range p.Embedded.Author {
			if a.ID > 0 && a.Slug != "" {
				us.add(a.ID, a.Slug, a.Name, Evidence{Method: "Post authors in the REST API", Mode: modeAggressive, URL: u, Value: a.Slug, Confidence: confUserDirect})
			}
		}
	}
}

func (s *Scanner) usersFromFeed(ctx context.Context, us *userSet, u, mode string) {
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != http.StatusOK {
		return
	}
	seen := map[string]bool{}
	for _, m := range dcCreatorRe.FindAllSubmatch(res.Body, -1) {
		name := strings.TrimSpace(string(m[1]))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		us.add(0, "", name, Evidence{Method: "Feed author (display name)", Mode: mode, URL: u, Value: name, Confidence: confUserFeed})
	}
}

// usersFromREST pages through /wp/v2/users, which lists the authors of
// published posts unless a plugin restricts it. A firewall rule often
// blocks only the /wp-json/ path, so ?rest_route= is tried when it fails,
// and when the users route is closed, the authors embedded in the posts.
func (s *Scanner) usersFromREST(ctx context.Context, us *userSet) {
	api := s.rest(ctx)
	var routes []func(page int) string
	if api != nil {
		routes = append(routes, func(page int) string { return api.route("wp/v2/users", fmt.Sprintf("per_page=100&page=%d", page)) })
	}
	if api == nil || !api.query {
		routes = append(routes, func(page int) string {
			return s.urlWithQuery("", "rest_route="+url.QueryEscape("/wp/v2/users")+fmt.Sprintf("&per_page=100&page=%d", page))
		})
	}
	if api == nil {
		routes = append([]func(int) string{func(page int) string {
			return s.urlWithQuery("wp-json/wp/v2/users", fmt.Sprintf("per_page=100&page=%d", page))
		}}, routes...)
	}
	anyFound := false
	defer func() {
		if !anyFound {
			s.usersFromPosts(ctx, us, api)
		}
	}()
	for _, route := range routes {
		found := false
		for page := 1; page <= 10; page++ {
			u := route(page)
			res := s.get(ctx, u)
			if res == nil || res.StatusCode != http.StatusOK {
				break
			}
			var users []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
				Slug string `json:"slug"`
			}
			if json.Unmarshal(res.Body, &users) != nil || len(users) == 0 {
				break
			}
			found = true
			for _, x := range users {
				us.add(x.ID, x.Slug, x.Name, Evidence{Method: "REST API", Mode: modeAggressive, URL: u, Value: x.Slug, Confidence: confUserDirect})
			}
			total, _ := strconv.Atoi(res.Header.Get("X-WP-TotalPages"))
			if page >= total {
				break
			}
		}
		if found {
			anyFound = true
			return
		}
	}
}

// usersFromOEmbed reads the author of the homepage from its oEmbed data,
// which exists when the homepage is a post or a page.
func (s *Scanner) usersFromOEmbed(ctx context.Context, us *userSet) {
	q := "url=" + url.QueryEscape(s.base.String())
	var u string
	if api := s.rest(ctx); api != nil {
		u = api.route("oembed/1.0/embed", q)
	} else {
		u = s.urlWithQuery("wp-json/oembed/1.0/embed", q)
	}
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != http.StatusOK {
		return
	}
	var o struct {
		AuthorName string `json:"author_name"`
		AuthorURL  string `json:"author_url"`
	}
	if json.Unmarshal(res.Body, &o) != nil || (o.AuthorName == "" && o.AuthorURL == "") {
		return
	}
	slug := ""
	if au, err := url.Parse(o.AuthorURL); err == nil {
		if m := authorPathRe.FindStringSubmatch(au.Path); m != nil {
			slug, _ = url.PathUnescape(m[1])
		}
	}
	us.add(0, slug, o.AuthorName, Evidence{Method: "oEmbed author", Mode: modeAggressive, URL: u, Value: o.AuthorURL, Confidence: confUserDirect})
}

func (s *Scanner) usersFromSitemap(ctx context.Context, us *userSet, u, method string) {
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != http.StatusOK || !strings.Contains(string(res.Body[:min(len(res.Body), 2048)]), "<urlset") {
		return
	}
	for _, m := range sitemapLocRe.FindAllSubmatch(res.Body, -1) {
		loc, err := url.Parse(html.UnescapeString(string(m[1])))
		if err != nil {
			continue
		}
		if am := authorPathRe.FindStringSubmatch(loc.Path); am != nil {
			slug, _ := url.PathUnescape(am[1])
			us.add(0, slug, "", Evidence{Method: method, Mode: modeAggressive, URL: u, Value: loc.String(), Confidence: confUserDirect})
		}
	}
}

// usersFromAuthorIDs requests /?author=N: WordPress redirects it to the
// author's archive, whose URL contains the username, or serves the archive
// with an author-<username> body class.
func (s *Scanner) usersFromAuthorIDs(ctx context.Context, us *userSet, from, to int) {
	ids := make([]int, 0, to-from+1)
	for id := from; id <= to; id++ {
		ids = append(ids, id)
	}
	s.parallel(ctx, len(ids), func(i int) {
		id := ids[i]
		u := s.urlWithQuery("", "author="+strconv.Itoa(id))
		// Not cached: a range of IDs would otherwise keep every page.
		res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 512 << 10})
		if res == nil {
			return
		}
		if res.IsRedirect() {
			loc, err := res.Location()
			if err != nil {
				return
			}
			if m := authorPathRe.FindStringSubmatch(loc.Path); m != nil {
				slug, _ := url.PathUnescape(m[1])
				us.add(id, slug, "", Evidence{Method: "Author ID redirect", Mode: modeAggressive, URL: u, Value: loc.String(), Confidence: confUserDirect})
			}
			return
		}
		if res.StatusCode != http.StatusOK {
			return
		}
		m := authorClassRe.FindSubmatch(res.Body)
		if m == nil || string(m[2]) != strconv.Itoa(id) {
			return
		}
		display := ""
		if t := titleRe.FindSubmatch(res.Body); t != nil {
			title := strings.TrimSpace(html.UnescapeString(string(t[1])))
			for _, re := range titleAuthorRes {
				if tm := re.FindStringSubmatch(title); tm != nil {
					display = tm[1]
					break
				}
			}
		}
		us.add(id, string(m[1]), display, Evidence{Method: "Author archive", Mode: modeAggressive, URL: u, Value: string(m[1]), Confidence: confUserArchive})
	})
}
