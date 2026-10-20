// Package update downloads the data cmsrecon matches against into the data
// directory: the Wordfence Intelligence feed, the CVE List, WordPress.org
// plugin and theme metadata, and the retire.js repository. Each source is
// stored in its own file and replaced atomically, so a failed source keeps
// its previous data and does not affect the others.
package update

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/fsutil"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// Source names accepted by --sources.
const (
	SourceWordfence = "wordfence"
	SourceCVE       = "cve"
	SourceWPOrg     = "wporg"
	SourceRetire    = "retirejs"
)

// AllSources is the default --sources list, in the order they run.
var AllSources = []string{SourceWordfence, SourceCVE, SourceWPOrg, SourceRetire}

// Label is the name of a source for people.
func Label(source string) string {
	switch source {
	case SourceWordfence:
		return "Wordfence Intelligence"
	case SourceCVE:
		return "CVE List"
	case SourceWPOrg:
		return "WordPress.org"
	case SourceRetire:
		return "retire.js"
	}
	return source
}

// Endpoints are the URLs the sources are downloaded from. Tests replace
// them with local servers.
type Endpoints struct {
	Wordfence      string
	CVERelease     string // GitHub API URL of the latest CVE List release
	CoreAPI        string // WordPress.org core version check
	PluginsAPI     string // WordPress.org plugins API, query_plugins
	ThemesAPI      string // WordPress.org themes API, query_themes
	PluginsSVN     string // directory listing of every plugin slug
	ThemesSVN      string
	RetireJS       string
	PopularPlugins int // how many popular plugins to fetch
	PopularThemes  int
}

// DefaultEndpoints are the real data sources.
var DefaultEndpoints = Endpoints{
	Wordfence:      vulndb.WordfenceURL,
	CVERelease:     "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest",
	CoreAPI:        "https://api.wordpress.org/core/version-check/1.7/",
	PluginsAPI:     "https://api.wordpress.org/plugins/info/1.2/",
	ThemesAPI:      "https://api.wordpress.org/themes/info/1.2/",
	PluginsSVN:     "https://plugins.svn.wordpress.org/",
	ThemesSVN:      "https://themes.svn.wordpress.org/",
	RetireJS:       vulndb.RetireURL,
	PopularPlugins: 2000,
	PopularThemes:  500,
}

// Options configures an update.
type Options struct {
	DataDir      string
	Sources      []string
	WordfenceKey string
	GitHubToken  string        // optional, raises GitHub's API rate limit
	Proxy        *url.URL      // nil: the environment's proxy settings
	Timeout      time.Duration // time to wait for a server to start answering
	Endpoints    Endpoints
	Log          io.Writer // progress and results, for people
}

// Result says what happened to each source.
type Result struct {
	Source  string
	Skipped bool   // not attempted, e.g. no Wordfence API key
	Summary string // what was stored, or why it was skipped
	Err     error
}

type updater struct {
	o  Options
	hc *http.Client
}

// Run updates the selected sources one after another and returns what
// happened to each. It returns an error when any attempted source failed;
// the sources that succeeded are stored anyway.
func Run(ctx context.Context, o Options) ([]Result, error) {
	if o.DataDir == "" {
		return nil, errors.New("no data directory: use --data-dir")
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.Endpoints == (Endpoints{}) {
		o.Endpoints = DefaultEndpoints
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	if err := os.MkdirAll(o.DataDir, 0o755); err != nil {
		return nil, err
	}
	u := &updater{o: o, hc: newClient(o)}

	var results []Result
	var failed []string
	for _, src := range o.Sources {
		if ctx.Err() != nil {
			break
		}
		var r Result
		switch src {
		case SourceWordfence:
			r = u.wordfence(ctx)
		case SourceCVE:
			r = u.cve(ctx)
		case SourceWPOrg:
			r = u.wporg(ctx)
		case SourceRetire:
			r = u.retire(ctx)
		default:
			r = Result{Err: fmt.Errorf("unknown source %q", src)}
		}
		r.Source = src
		results = append(results, r)
		if r.Err != nil {
			failed = append(failed, src)
		}
	}
	if ctx.Err() != nil {
		return results, ctx.Err()
	}
	if len(failed) > 0 {
		return results, fmt.Errorf("%s failed", strings.Join(failed, ", "))
	}
	return results, nil
}

func newClient(o Options) *http.Client {
	proxy := http.ProxyFromEnvironment
	if o.Proxy != nil {
		proxy = http.ProxyURL(o.Proxy)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 proxy,
			DialContext:           (&net.Dialer{Timeout: o.Timeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   o.Timeout,
			ResponseHeaderTimeout: o.Timeout,
			ForceAttemptHTTP2:     true,
		},
	}
}

func (u *updater) logf(format string, args ...any) {
	fmt.Fprintf(u.o.Log, format+"\n", args...)
}

// get sends a GET and returns the response when the status is 200.
func (u *updater) get(ctx context.Context, rawURL string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cmsrecon/"+buildinfo.Version+" (+https://github.com/theodoros997/cmsrecon)")
	for k, v := range header {
		req.Header[k] = v
	}
	res, err := u.hc.Do(req)
	if err != nil {
		// url.Error repeats the whole URL, query included; keep it short.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("%s: %w", shortURL(rawURL), err)
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		res.Body.Close()
		return nil, &StatusError{URL: shortURL(rawURL), Status: res.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return res, nil
}

// shortURL drops the query string, which can be long and can hold tokens.
func shortURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery, u.User = "", nil
	return u.String()
}

// getBytes fetches a whole response body, up to limit bytes.
func (u *updater) getBytes(ctx context.Context, rawURL string, header http.Header, limit int64) ([]byte, error) {
	res, err := u.get(ctx, rawURL, header)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rawURL, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: response larger than %d MB", rawURL, limit>>20)
	}
	return data, nil
}

// StatusError is an unexpected HTTP status from a data source.
type StatusError struct {
	URL    string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("%s: HTTP %d", e.URL, e.Status)
	if e.Body != "" {
		msg += ": " + firstLine(e.Body, 200)
	}
	return msg
}

func firstLine(s string, n int) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func (u *updater) path(name string) string { return filepath.Join(u.o.DataDir, name) }

// wordfence downloads the Wordfence Intelligence production feed.
func (u *updater) wordfence(ctx context.Context) Result {
	if u.o.WordfenceKey == "" {
		return Result{Skipped: true, Summary: "no API key. Set WORDFENCE_API_KEY or use --wordfence-key; the key is free with a Wordfence account " +
			"(https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/)"}
	}
	start := time.Now()
	u.logf("Wordfence Intelligence: downloading the vulnerability feed...")
	res, err := u.get(ctx, u.o.Endpoints.Wordfence, http.Header{"Authorization": {"Bearer " + u.o.WordfenceKey}, "Accept": {"application/json"}})
	var se *StatusError
	if errors.As(err, &se) && (se.Status == http.StatusUnauthorized || se.Status == http.StatusForbidden) {
		return Result{Err: fmt.Errorf("the API key was rejected (HTTP %d)", se.Status)}
	}
	if err != nil {
		return Result{Err: err}
	}
	defer res.Body.Close()
	vulns, err := vulndb.ParseWordfence(res.Body)
	if err != nil {
		return Result{Err: err}
	}
	if len(vulns) == 0 {
		return Result{Err: errors.New("the feed has no vulnerabilities")}
	}
	sf := &vulndb.SourceFile{Source: vulndb.SourceWordfence, UpdatedAt: time.Now().UTC(), Vulnerabilities: vulns}
	if err := vulndb.WriteSource(u.path(vulndb.WordfenceFile), sf); err != nil {
		return Result{Err: err}
	}
	return Result{Summary: fmt.Sprintf("%s affected plugins, themes and core versions (%s)", count(len(vulns)), since(start))}
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

var allCVEsAssetRe = regexp.MustCompile(`(?i)_all_CVEs_at_midnight.*\.zip$`)

// cve downloads the latest daily CVE List release and keeps its WordPress
// records. The release is about half a gigabyte, so it is skipped when the
// stored data comes from the same release.
func (u *updater) cve(ctx context.Context) Result {
	start := time.Now()
	header := http.Header{"Accept": {"application/vnd.github+json"}}
	if u.o.GitHubToken != "" {
		header.Set("Authorization", "Bearer "+u.o.GitHubToken)
	}
	data, err := u.getBytes(ctx, u.o.Endpoints.CVERelease, header, 16<<20)
	if err != nil {
		return Result{Err: err}
	}
	var rel ghRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return Result{Err: fmt.Errorf("release information: %w", err)}
	}
	var name, assetURL string
	var size int64
	for _, a := range rel.Assets {
		if allCVEsAssetRe.MatchString(a.Name) {
			name, assetURL, size = a.Name, a.URL, a.Size
			break
		}
	}
	if assetURL == "" {
		return Result{Err: fmt.Errorf("release %s has no all-CVEs archive", rel.TagName)}
	}
	if old, err := vulndb.ReadSource(u.path(vulndb.CVEFile)); err == nil && old.Release == name {
		return Result{Summary: fmt.Sprintf("already up to date (%s, %s vulnerabilities)", name, count(len(old.Vulnerabilities)))}
	}

	u.logf("CVE List: downloading %s (%s)...", name, megabytes(size))
	tmp, err := os.CreateTemp(u.o.DataDir, ".cmsrecon-cvelist-*.zip")
	if err != nil {
		return Result{Err: err}
	}
	defer os.Remove(tmp.Name())
	res, err := u.get(ctx, assetURL, nil)
	if err != nil {
		tmp.Close()
		return Result{Err: err}
	}
	_, err = io.Copy(tmp, &progressReader{r: res.Body, total: size, report: func(done int64) {
		u.logf("CVE List: %s of %s", megabytes(done), megabytes(size))
	}})
	res.Body.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Result{Err: fmt.Errorf("downloading %s: %w", name, err)}
	}

	u.logf("CVE List: reading the records...")
	vulns, err := vulndb.ParseCVEZip(tmp.Name(), func(n int) {
		if n%100000 == 0 {
			u.logf("CVE List: %s records read", count(n))
		}
	})
	if err != nil {
		return Result{Err: err}
	}
	if len(vulns) == 0 {
		return Result{Err: fmt.Errorf("%s has no WordPress records", name)}
	}
	sf := &vulndb.SourceFile{Source: vulndb.SourceCVE, UpdatedAt: time.Now().UTC(), Release: name, Vulnerabilities: vulns}
	if err := vulndb.WriteSource(u.path(vulndb.CVEFile), sf); err != nil {
		return Result{Err: err}
	}
	return Result{Summary: fmt.Sprintf("%s WordPress core, plugin and theme vulnerabilities from %s (%s)", count(len(vulns)), name, since(start))}
}

// progressReader reports download progress every 50 MB.
type progressReader struct {
	r            io.Reader
	total, done  int64
	lastReported int64
	report       func(done int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.done-p.lastReported >= 50<<20 {
		p.lastReported = p.done
		p.report(p.done)
	}
	return n, err
}

// wporg downloads the popular plugin and theme lists with their latest
// versions, and the lists of every plugin and theme slug.
func (u *updater) wporg(ctx context.Context) Result {
	start := time.Now()
	u.logf("WordPress.org: downloading the popular plugins and themes...")
	plugins, err := u.popular(ctx, u.o.Endpoints.PluginsAPI, "query_plugins", "plugins", 250, u.o.Endpoints.PopularPlugins)
	if err != nil {
		return Result{Err: fmt.Errorf("popular plugins: %w", err)}
	}
	themes, err := u.popular(ctx, u.o.Endpoints.ThemesAPI, "query_themes", "themes", 100, u.o.Endpoints.PopularThemes)
	if err != nil {
		return Result{Err: fmt.Errorf("popular themes: %w", err)}
	}
	core, err := u.coreLatest(ctx)
	if err != nil {
		return Result{Err: fmt.Errorf("latest WordPress version: %w", err)}
	}
	w := &wordlists.WPOrg{UpdatedAt: time.Now().UTC(), CoreLatest: core, Plugins: plugins, Themes: themes}
	if err := wordlists.WriteWPOrg(u.path(wordlists.WPOrgFile), w); err != nil {
		return Result{Err: err}
	}

	u.logf("WordPress.org: downloading every plugin and theme slug...")
	var totals []string
	for _, l := range []struct {
		url, file, what string
	}{{u.o.Endpoints.PluginsSVN, wordlists.AllPluginsFile, "plugin"}, {u.o.Endpoints.ThemesSVN, wordlists.AllThemesFile, "theme"}} {
		slugs, err := u.svnSlugs(ctx, l.url)
		if err != nil {
			return Result{Err: fmt.Errorf("%s slugs: %w", l.what, err)}
		}
		if err := wordlists.WriteSlugs(u.path(l.file), slugs); err != nil {
			return Result{Err: err}
		}
		totals = append(totals, fmt.Sprintf("%s %s slugs", count(len(slugs)), l.what))
	}
	return Result{Summary: fmt.Sprintf("WordPress %s, %s popular plugins, %s popular themes, %s (%s)",
		core, count(len(plugins)), count(len(themes)), strings.Join(totals, ", "), since(start))}
}

// coreLatest asks the version check API for the latest WordPress release.
func (u *updater) coreLatest(ctx context.Context) (string, error) {
	data, err := u.getBytes(ctx, u.o.Endpoints.CoreAPI, nil, 4<<20)
	if err != nil {
		return "", err
	}
	var resp struct {
		Offers []struct {
			Current string `json:"current"`
		} `json:"offers"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", err
	}
	if len(resp.Offers) == 0 || !vulndb.Valid(resp.Offers[0].Current) {
		return "", errors.New("no release in the answer")
	}
	return resp.Offers[0].Current, nil
}

// apiItem is a plugin or theme in a WordPress.org API response.
type apiItem struct {
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	ActiveInstalls int    `json:"active_installs"`
	LastUpdated    string `json:"last_updated"` // "2024-05-01 3:04pm GMT" for plugins, "2024-05-01" for themes
}

// popular pages through query_plugins or query_themes, most popular first.
func (u *updater) popular(ctx context.Context, api, action, key string, perPage, want int) ([]wordlists.Item, error) {
	var out []wordlists.Item
	seen := map[string]bool{}
	for page := 1; len(out) < want; page++ {
		q := url.Values{}
		q.Set("action", action)
		q.Set("request[browse]", "popular")
		q.Set("request[per_page]", fmt.Sprint(perPage))
		q.Set("request[page]", fmt.Sprint(page))
		// Only the fields cmsrecon keeps; the others make pages large.
		for _, f := range []string{"description", "sections", "short_description", "rating", "ratings", "downloaded",
			"download_link", "added", "tags", "compatibility", "homepage", "donate_link", "icons",
			"banners", "screenshot_url", "preview_url", "author", "author_profile", "contributors", "requires",
			"tested", "requires_php", "num_ratings", "support_threads", "support_threads_resolved"} {
			q.Set("request[fields]["+f+"]", "0")
		}
		q.Set("request[fields][active_installs]", "1")
		q.Set("request[fields][version]", "1")
		q.Set("request[fields][last_updated]", "1")
		data, err := u.getBytes(ctx, api+"?"+q.Encode(), nil, 32<<20)
		if err != nil {
			return nil, err
		}
		var resp map[string]json.RawMessage
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		var info struct {
			Pages int `json:"pages"`
		}
		var list []apiItem
		if err := json.Unmarshal(resp["info"], &info); err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		if err := json.Unmarshal(resp[key], &list); err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		for _, it := range list {
			if it.Slug == "" || seen[it.Slug] || len(out) >= want {
				continue
			}
			seen[it.Slug] = true
			item := wordlists.Item{Slug: it.Slug, Name: it.Name, Version: it.Version, ActiveInstalls: it.ActiveInstalls}
			if d := it.LastUpdated; len(d) >= 10 && d[4] == '-' && d[7] == '-' {
				item.LastUpdated = d[:10]
			}
			out = append(out, item)
		}
		if len(list) == 0 || page >= info.Pages {
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("the API returned nothing")
	}
	return out, nil
}

var svnEntryRe = regexp.MustCompile(`<li><a href="([^"/?#]+)/">`)

// svnSlugs reads the slugs from a WordPress.org SVN root listing.
func (u *updater) svnSlugs(ctx context.Context, rawURL string) ([]string, error) {
	data, err := u.getBytes(ctx, rawURL, nil, 64<<20)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range svnEntryRe.FindAllSubmatch(data, -1) {
		if s, err := url.PathUnescape(string(m[1])); err == nil && s != "" && s != ".." {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no slugs in the listing")
	}
	return out, nil
}

// retire downloads the retire.js repository.
func (u *updater) retire(ctx context.Context) Result {
	data, err := u.getBytes(ctx, u.o.Endpoints.RetireJS, nil, 32<<20)
	if err != nil {
		return Result{Err: err}
	}
	if err := vulndb.ValidateRetire(data); err != nil {
		return Result{Err: fmt.Errorf("not a retire.js repository: %w", err)}
	}
	repo, err := vulndb.ParseJSRepo(data)
	if err != nil {
		return Result{Err: err}
	}
	if err := fsutil.WriteFileAtomic(u.path(vulndb.RetireFile), data); err != nil {
		return Result{Err: err}
	}
	return Result{Summary: fmt.Sprintf("%s JavaScript libraries recognized", count(len(repo.Libraries())))}
}

// count formats an integer with thousands separators.
func count(n int) string {
	s := fmt.Sprint(n)
	var b bytes.Buffer
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func megabytes(n int64) string {
	if n <= 0 {
		return "unknown size"
	}
	return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
}

func since(t time.Time) string {
	return time.Since(t).Round(time.Second).String()
}
