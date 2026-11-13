// Package wporg reads two public facts about a plugin from WordPress.org
// while a scan runs: the releases it has, and the checksums of the files of
// each release. A scan compares them with the files a site serves to tell
// which release is installed, without guessing from version strings.
//
// Nothing about the target is sent: only the plugin's slug. Answers are
// cached in the data directory, the checksums forever (a release never
// changes) and the list of releases for a day.
package wporg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// The WordPress.org endpoints. %s is the plugin's slug, then the version.
const (
	DefaultInfoURL      = "https://api.wordpress.org/plugins/info/1.0/%s.json"
	DefaultChecksumsURL = "https://downloads.wordpress.org/plugin-checksums/%s/%s.json"
)

const (
	versionsTTL = 24 * time.Hour
	maxAnswer   = 8 << 20
)

// ErrNotFound means WordPress.org does not host the plugin (a premium or
// private one) or has no checksums for the release.
var ErrNotFound = errors.New("not on WordPress.org")

// Client asks WordPress.org, through its cache.
type Client struct {
	HTTP         *http.Client
	Dir          string // the cache directory; empty for no cache
	InfoURL      string
	ChecksumsURL string
	UserAgent    string
}

// New returns a client that caches under dir and sends its requests
// through proxy, or the environment's proxy when proxy is nil.
func New(dir string, proxy *url.URL, userAgent string) *Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 15 * time.Second}
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	if dir != "" {
		dir = filepath.Join(dir, "plugin-checksums")
	}
	return &Client{
		HTTP: &http.Client{Transport: tr, Timeout: 20 * time.Second},
		Dir:  dir, InfoURL: DefaultInfoURL, ChecksumsURL: DefaultChecksumsURL, UserAgent: userAgent,
	}
}

var (
	slugRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	releaseRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,4}$`)
	md5Re     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Static reports whether a plugin file is served as it is, so that its
// hash on a site can be compared: scripts, stylesheets and text files. PHP
// files run instead.
func Static(path string) bool {
	if strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\ ") || strings.HasPrefix(path, "/") {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".css", ".txt", ".md", ".json", ".svg", ".pot", ".xml":
		return true
	}
	return false
}

type versionsFile struct {
	FetchedAt time.Time `json:"fetched_at"`
	Versions  []string  `json:"versions"`
}

// Versions returns the stable releases of a plugin, newest first.
func (c *Client) Versions(ctx context.Context, slug string) ([]string, error) {
	if !slugRe.MatchString(slug) {
		return nil, ErrNotFound
	}
	slug = strings.ToLower(slug)
	cache := c.path(slug, "versions.json")
	var cached versionsFile
	if readJSON(cache, &cached) == nil && time.Since(cached.FetchedAt) < versionsTTL {
		if len(cached.Versions) == 0 {
			return nil, ErrNotFound
		}
		return cached.Versions, nil
	}
	data, err := c.get(ctx, fmt.Sprintf(c.InfoURL, url.PathEscape(slug)))
	if errors.Is(err, ErrNotFound) {
		writeJSON(cache, versionsFile{FetchedAt: time.Now().UTC()}) // remember that it is not there
		return nil, ErrNotFound
	}
	if err != nil {
		if len(cached.Versions) > 0 {
			return cached.Versions, nil // a stale list beats none
		}
		return nil, err
	}
	versions, err := ParseVersions(data)
	if err != nil {
		return nil, err
	}
	writeJSON(cache, versionsFile{FetchedAt: time.Now().UTC(), Versions: versions})
	if len(versions) == 0 {
		return nil, ErrNotFound
	}
	return versions, nil
}

// ParseVersions reads the releases from a plugin information answer:
// {"version": "5.9", "versions": {"5.8": "…zip", "trunk": "…zip"}}.
// Development and pre-release versions are left out.
func ParseVersions(data []byte) ([]string, error) {
	var info struct {
		Error    any             `json:"error"`
		Version  string          `json:"version"`
		Versions json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("WordPress.org plugin information: %w", err)
	}
	if info.Error != nil {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if releaseRe.MatchString(v) && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(info.Version)
	// "versions" is an object, or an empty array for a plugin without tags.
	var versions map[string]json.RawMessage
	if json.Unmarshal(info.Versions, &versions) == nil {
		for v := range versions {
			add(v)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return vulndb.Compare(b, a) })
	return out, nil
}

// Checksums returns the MD5 hashes of the static files of a release, by
// path inside the plugin's folder. A file can have several hashes.
func (c *Client) Checksums(ctx context.Context, slug, version string) (map[string][]string, error) {
	if !slugRe.MatchString(slug) || !releaseRe.MatchString(version) {
		return nil, ErrNotFound
	}
	slug = strings.ToLower(slug)
	cache := c.path(slug, version+".json")
	var sums map[string][]string
	if readJSON(cache, &sums) == nil && sums != nil {
		if len(sums) == 0 {
			return nil, ErrNotFound
		}
		return sums, nil
	}
	data, err := c.get(ctx, fmt.Sprintf(c.ChecksumsURL, url.PathEscape(slug), url.PathEscape(version)))
	if errors.Is(err, ErrNotFound) {
		writeJSON(cache, map[string][]string{})
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if sums, err = ParseChecksums(data); err != nil {
		return nil, err
	}
	writeJSON(cache, sums)
	if len(sums) == 0 {
		return nil, ErrNotFound
	}
	return sums, nil
}

// ParseChecksums reads a plugin checksums answer, keeping the static
// files: {"files": {"path": {"md5": "…" or ["…", "…"], "sha256": …}}}.
func ParseChecksums(data []byte) (map[string][]string, error) {
	var answer struct {
		Files map[string]struct {
			MD5 json.RawMessage `json:"md5"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &answer); err != nil {
		return nil, fmt.Errorf("WordPress.org plugin checksums: %w", err)
	}
	out := map[string][]string{}
	for path, f := range answer.Files {
		if !Static(path) {
			continue
		}
		var one string
		var many []string
		switch {
		case json.Unmarshal(f.MD5, &one) == nil:
			many = []string{one}
		case json.Unmarshal(f.MD5, &many) != nil:
			continue
		}
		for _, sum := range many {
			if sum = strings.ToLower(strings.TrimSpace(sum)); md5Re.MatchString(sum) {
				out[path] = append(out[path], sum)
			}
		}
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: HTTP %d", req.URL.Host, res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, maxAnswer))
}

func (c *Client) path(slug, name string) string {
	if c.Dir == "" {
		return ""
	}
	return filepath.Join(c.Dir, slug, name)
}

func readJSON(path string, v any) error {
	if path == "" {
		return os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// writeJSON writes a cache file. A cache that cannot be written only
// costs the same request again.
func writeJSON(path string, v any) {
	if path == "" {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o755) != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		os.Rename(tmp, path)
	}
}
