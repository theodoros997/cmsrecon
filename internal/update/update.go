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
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/corehash"
	"github.com/theodoros997/cmsrecon/internal/fsutil"
	"github.com/theodoros997/cmsrecon/internal/progress"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// Source names accepted by --sources.
const (
	SourceWordfence = "wordfence"
	SourceCVE       = "cve"
	SourceWPOrg     = "wporg"
	SourceRetire    = "retirejs"
	SourceExploits  = "exploits"
	SourceCoreHash  = "corehashes"
)

// AllSources is the default --sources list, in the order they run.
var AllSources = []string{SourceWordfence, SourceCVE, SourceWPOrg, SourceRetire, SourceExploits, SourceCoreHash}

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
	case SourceExploits:
		return "Public exploits"
	case SourceCoreHash:
		return "WordPress core checksums"
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
	ExploitDB      string // Exploit-DB's files_exploits.csv
	Metasploit     string // Metasploit's modules_metadata_base.json
	Nuclei         string // nuclei-templates' cves.json
	PoCInGitHub    string // PoC-in-GitHub's README.md
	CoreStable     string // WordPress.org list of every release
	CoreChecksums  string // WordPress.org checksums of one release
	PopularPlugins int    // how many popular plugins to fetch
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
	ExploitDB:      "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
	Metasploit:     "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
	Nuclei:         "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
	PoCInGitHub:    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md",
	CoreStable:     "https://api.wordpress.org/core/stable-check/1.0/",
	CoreChecksums:  "https://api.wordpress.org/core/checksums/1.0/",
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
	Log          io.Writer         // progress lines, for people, when Steps is nil
	Steps        progress.Reporter // live progress: each source is a step
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
		if o.Steps != nil {
			o.Steps.Start(Label(src))
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
		case SourceExploits:
			r = u.exploits(ctx)
		case SourceCoreHash:
			r = u.coreHashes(ctx)
		default:
			r = Result{Err: fmt.Errorf("unknown source %q", src)}
		}
		r.Source = src
		if r.Summary != "" && !r.Skipped {
			if size := u.stored(src); size > 0 {
				r.Summary += "; " + FormatSize(size) + " on disk"
			}
		}
		results = append(results, r)
		if r.Err != nil {
			failed = append(failed, src)
		}
		if o.Steps != nil {
			switch {
			case r.Err != nil && r.Summary != "":
				o.Steps.Fail(Label(src), fmt.Sprintf("%v; stored what it could: %s", r.Err, r.Summary))
			case r.Err != nil:
				o.Steps.Fail(Label(src), r.Err.Error())
			case r.Skipped:
				o.Steps.Done(Label(src), "skipped: "+r.Summary)
			default:
				o.Steps.Done(Label(src), r.Summary)
			}
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

// status says what a source is busy with: on the live status line, or as
// a log line.
func (u *updater) status(src, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if u.o.Steps != nil {
		u.o.Steps.Update(Label(src), msg)
		return
	}
	fmt.Fprintf(u.o.Log, "%s: %s\n", Label(src), msg)
}

// download returns a progress callback for a download of total bytes (0
// when unknown): live, it shows the megabytes and the speed; in a log, a
// line every 50 MB.
func (u *updater) download(src, what string, total int64) func(done int64) {
	start := time.Now()
	var logged int64
	return func(done int64) {
		if u.o.Steps == nil {
			if done-logged >= 50<<20 {
				logged = done
				u.status(src, "%s: %s of %s", what, megabytes(done), megabytes(total))
			}
			return
		}
		msg := what + ": " + megabytes(done)
		if total > 0 {
			msg += " of " + megabytes(total)
		}
		if secs := time.Since(start).Seconds(); secs > 0.5 {
			msg += fmt.Sprintf(", %.1f MB/s", float64(done)/(1<<20)/secs)
		}
		u.status(src, "%s", msg)
	}
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
	u.status(SourceWordfence, "connecting")
	res, err := u.get(ctx, u.o.Endpoints.Wordfence, http.Header{"Authorization": {"Bearer " + u.o.WordfenceKey}, "Accept": {"application/json"}})
	var se *StatusError
	if errors.As(err, &se) && (se.Status == http.StatusUnauthorized || se.Status == http.StatusForbidden) {
		return Result{Err: fmt.Errorf("the API key was rejected (HTTP %d)", se.Status)}
	}
	if err != nil {
		return Result{Err: err}
	}
	defer res.Body.Close()
	vulns, err := vulndb.ParseWordfence(&progressReader{r: res.Body, report: u.download(SourceWordfence, "downloading and reading the feed", res.ContentLength)})
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

	u.status(SourceCVE, "downloading %s (%s)", name, megabytes(size))
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
	_, err = io.Copy(tmp, &progressReader{r: res.Body, report: u.download(SourceCVE, "downloading the daily release", size)})
	res.Body.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Result{Err: fmt.Errorf("downloading %s: %w", name, err)}
	}

	u.status(SourceCVE, "reading the records")
	vulns, err := vulndb.ParseCVEZip(tmp.Name(), func(n int) {
		if n%100000 == 0 || (u.o.Steps != nil && n%5000 == 0) {
			u.status(SourceCVE, "reading the records: %s read", count(n))
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

// progressReader reports how much was read, at most a few times a second.
type progressReader struct {
	r      io.Reader
	done   int64
	last   time.Time
	report func(done int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if time.Since(p.last) >= 250*time.Millisecond {
		p.last = time.Now()
		p.report(p.done)
	}
	return n, err
}

// wporg downloads the popular plugin and theme lists with their latest
// versions, and the lists of every plugin and theme slug.
func (u *updater) wporg(ctx context.Context) Result {
	start := time.Now()
	u.status(SourceWPOrg, "popular plugins and themes")
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

	u.status(SourceWPOrg, "every plugin and theme slug")
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

// exploits builds the index of public exploits by CVE. A part that fails
// keeps its entries from the previous index; the others are refreshed.
func (u *updater) exploits(ctx context.Context) Result {
	start := time.Now()
	x := vulndb.NewExploitIndex()
	parts := []struct {
		source, label, url string
		parse              func(io.Reader, *vulndb.ExploitIndex) error
	}{
		{vulndb.ExploitDB, "Exploit-DB", u.o.Endpoints.ExploitDB, vulndb.ParseExploitDB},
		{vulndb.ExploitMetasploit, "Metasploit", u.o.Endpoints.Metasploit, vulndb.ParseMetasploit},
		{vulndb.ExploitNuclei, "Nuclei templates", u.o.Endpoints.Nuclei, vulndb.ParseNuclei},
		{vulndb.ExploitGitHub, "PoC-in-GitHub", u.o.Endpoints.PoCInGitHub, vulndb.ParsePoCInGitHub},
	}
	failed := map[string]bool{}
	var errs []string
	for i, p := range parts {
		if ctx.Err() != nil {
			return Result{Err: ctx.Err()}
		}
		u.status(SourceExploits, "%s, %d/%d", p.label, i+1, len(parts))
		data, err := u.getBytes(ctx, p.url, nil, 128<<20)
		if err == nil {
			err = p.parse(bytes.NewReader(data), x)
		}
		if err != nil {
			failed[p.source] = true
			errs = append(errs, fmt.Sprintf("%s: %v", p.label, err))
		}
	}
	if len(failed) == len(parts) {
		return Result{Err: errors.New(strings.Join(errs, "; "))}
	}
	if old, err := vulndb.ReadExploits(u.path(vulndb.ExploitsFile)); err == nil && len(failed) > 0 {
		for cve, es := range old.ByCVE {
			for _, e := range es {
				if failed[e.Source] {
					x.Add(cve, e)
				}
			}
		}
		if failed[vulndb.ExploitDB] {
			x.NoCVE = old.NoCVE
		}
	}
	x.UpdatedAt = time.Now().UTC()
	if err := vulndb.WriteExploits(u.path(vulndb.ExploitsFile), x); err != nil {
		return Result{Err: err}
	}
	r := Result{Summary: fmt.Sprintf("%s CVEs with a public exploit: %s Metasploit modules, %s Exploit-DB entries, %s Nuclei templates, %s GitHub repositories; and %s WordPress plugin and theme exploits without a CVE, matched by name (%s)",
		count(x.Entries()), count(x.Counts[vulndb.ExploitMetasploit]), count(x.Counts[vulndb.ExploitDB]),
		count(x.Counts[vulndb.ExploitNuclei]), count(x.Counts[vulndb.ExploitGitHub]), count(len(x.NoCVE)), since(start))}
	if len(errs) > 0 {
		r.Err = fmt.Errorf("%s (their previous data is kept)", strings.Join(errs, "; "))
	}
	return r
}

// sourceFiles are the files each source stores in the data directory.
var sourceFiles = map[string][]string{
	SourceWordfence: {vulndb.WordfenceFile},
	SourceCVE:       {vulndb.CVEFile},
	SourceWPOrg:     {wordlists.WPOrgFile, wordlists.AllPluginsFile, wordlists.AllThemesFile},
	SourceRetire:    {vulndb.RetireFile},
	SourceExploits:  {vulndb.ExploitsFile},
	SourceCoreHash:  {corehash.File},
}

// stored is the size on disk of a source's files.
func (u *updater) stored(src string) int64 {
	var total int64
	for _, name := range sourceFiles[src] {
		if fi, err := os.Stat(u.path(name)); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// FormatSize says 850 KB, 12.4 MB or 1.2 GB.
func FormatSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d KB", (n+1023)/1024)
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

// coreHashes downloads WordPress.org's checksums of every release since
// corehash.MinVersion that the stored database does not have yet. A release
// that fails is left out and asked for again by the next update.
func (u *updater) coreHashes(ctx context.Context) Result {
	start := time.Now()
	data, err := u.getBytes(ctx, u.o.Endpoints.CoreStable, nil, 8<<20)
	if err != nil {
		return Result{Err: err}
	}
	releases, err := corehash.ParseReleases(data)
	if err != nil {
		return Result{Err: fmt.Errorf("release list: %w", err)}
	}
	old, err := corehash.Read(u.path(corehash.File))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		u.status(SourceCoreHash, "the stored data is unreadable, starting over (%v)", err)
		old = nil
	}
	b := corehash.NewBuilder(old)
	var todo []string
	for _, v := range releases {
		if !b.Has(v) {
			todo = append(todo, v)
		}
	}
	if len(todo) == 0 {
		return Result{Summary: fmt.Sprintf("already up to date (%s releases)", count(b.Len()))}
	}
	u.status(SourceCoreHash, "%s releases to download", count(len(todo)))

	type answer struct {
		version string
		sums    map[string]string
		err     error
	}
	jobs := make(chan string)
	answers := make(chan answer)
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for v := range jobs {
				q := url.Values{"version": {v}, "locale": {"en_US"}}
				data, err := u.getBytes(ctx, u.o.Endpoints.CoreChecksums+"?"+q.Encode(), nil, 16<<20)
				var sums map[string]string
				if err == nil {
					sums, err = corehash.ParseChecksums(data, v)
				}
				answers <- answer{v, sums, err}
			}
		})
	}
	go func() {
		defer close(jobs)
		for _, v := range todo {
			select {
			case jobs <- v:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(answers) }()

	var failed []string
	done := 0
	for a := range answers {
		done++
		if done%100 == 0 || u.o.Steps != nil {
			u.status(SourceCoreHash, "releases %d/%d", done, len(todo))
		}
		if a.err != nil {
			failed = append(failed, a.version)
			continue
		}
		// A release WordPress.org has no checksums for is remembered
		// with no files, so it is not asked for again.
		b.Add(a.version, a.sums)
	}
	if ctx.Err() != nil {
		return Result{Err: ctx.Err()}
	}
	db := b.DB()
	if len(db.Files) == 0 {
		return Result{Err: errors.New("no checksums were downloaded")}
	}
	if err := corehash.Write(u.path(corehash.File), db); err != nil {
		return Result{Err: err}
	}
	r := Result{Summary: fmt.Sprintf("%s releases, %s static files (%s)", count(len(db.Versions)), count(len(db.Files)), since(start))}
	if len(failed) > 0 {
		slices.SortFunc(failed, vulndb.Compare)
		r.Err = fmt.Errorf("%d releases could not be downloaded (%s); the next update asks for them again", len(failed), strings.Join(failed[:min(len(failed), 5)], ", "))
	}
	return r
}
