package scan

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/corehash"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
	"github.com/theodoros997/cmsrecon/internal/wporg"
)

// Confidence of the plugin version signals of this file.
const (
	confHashRelease    = 95 // the plugin's files match one release only
	confHashAgrees     = 85 // they match a few releases, among them the one other signals found
	confHashReleases   = 50 // they match a few releases and nothing picks one: each gets this
	confVersionPot     = 50 // the translation template's header, which developers do not always refresh
	confVersionPackage = 50 // package.json, which build tools keep but some projects never touch
)

// Limits of the file hash check of a plugin.
const (
	maxChecksumReleases = 40 // releases whose checksums are asked from WordPress.org
	checksumBatch       = 8  // how many at a time while nothing matches
	maxHashRequests     = 4  // files requested from the target beyond those its pages load
	maxHashReleases     = 4  // more releases than this still matching is too vague to report
)

// settledPluginConfidence is the confidence from which a plugin's version
// needs no more evidence: a readme's stable tag reaches it.
const settledPluginConfidence = 80

func (s *Scanner) pluginVersionSettled(set *componentSet, c *component) bool {
	if s.thorough() {
		return false // --aggressive tries every way
	}
	set.mu.Lock()
	ev := slices.Clone(c.versions)
	set.mu.Unlock()
	v := combineVersions(ev)
	return v.Number != "" && v.Confidence >= settledPluginConfidence
}

// org returns the WordPress.org client, or nil when the scan may not use
// it: --offline, passive detection, or after it failed once.
func (s *Scanner) org() *wporg.Client {
	if s.opts.Offline || !s.aggressive() || s.orgDown.Load() {
		return nil
	}
	s.orgOnce.Do(func() {
		if s.Org == nil {
			s.Org = wporg.New(s.opts.DataDir, s.opts.Proxy, s.client.UserAgent())
		}
	})
	return s.Org
}

// orgFailed stops asking WordPress.org after a failure and says so once.
func (s *Scanner) orgFailed(err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	if s.orgDown.CompareAndSwap(false, true) {
		s.notice("WordPress.org could not be asked for plugin checksums (%s), so plugin versions were not checked against them. --offline skips that step.", shortErr(err))
	}
}

func shortErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	if len(msg) > 100 {
		msg = msg[:100] + "…"
	}
	return msg
}

// hashVersionOfPlugin tells which release of a WordPress.org plugin is
// installed from the hashes of its files, compared with the checksums
// WordPress.org publishes for every release.
//
// It starts from the files the site's pages already load, so it often
// needs no request a visitor's browser would not send. It asks
// WordPress.org for the checksums of the newest releases first, then of
// the neighbours of those that match, until the releases around the match
// no longer do. Then, when several releases still match (a release that
// changed no script or stylesheet looks like the one before), it requests
// the file that tells the most of them apart, a few times at most.
func (s *Scanner) hashVersionOfPlugin(ctx context.Context, set *componentSet, c *component, dir *url.URL) {
	org := s.org()
	if org == nil {
		return
	}
	// With the full list of WordPress.org plugins, a slug that is not on
	// it is a premium or private plugin: there is nothing to ask.
	if l := s.data.lists; len(l.AllPlugins) > 0 && !l.Known(wordlists.Plugins, c.slug) {
		return
	}
	releases, err := org.Versions(ctx, c.slug)
	switch {
	case errors.Is(err, wporg.ErrNotFound):
		return
	case err != nil:
		s.orgFailed(err)
		return
	case len(releases) == 0:
		return
	}

	base := under(dir, c.slug+"/")
	observed := map[string]string{} // path in the plugin -> MD5 of what the site serves
	tried := map[string]bool{}
	requests := 0
	fetch := func(rel string, counted bool) {
		if tried[rel] {
			return
		}
		tried[rel] = true
		if counted {
			requests++
		}
		res := s.get(ctx, base+rel)
		if res == nil || res.StatusCode != http.StatusOK || res.Truncated || res.Blocked != "" || isHTML(res.Body) {
			return
		}
		sum := md5.Sum(res.Body)
		observed[rel] = hex.EncodeToString(sum[:])
	}
	set.mu.Lock()
	assets, hints := slices.Clone(c.assets), slices.Clone(c.versions)
	set.mu.Unlock()
	for _, a := range assets {
		if rel := relativeTo(a, c.slug); rel != "" && wporg.Static(rel) {
			fetch(rel, false) // a page loads it: no new kind of request
		}
	}

	// Checksums are loaded for a growing set of releases; index 0 is the
	// newest.
	sums := map[int]map[string][]string{}
	asked := 0
	load := func(i int) bool {
		if i < 0 || i >= len(releases) || asked >= maxChecksumReleases {
			return false
		}
		if _, ok := sums[i]; ok {
			return false
		}
		asked++
		m, err := org.Checksums(ctx, c.slug, releases[i])
		switch {
		case errors.Is(err, wporg.ErrNotFound):
			m = map[string][]string{}
		case err != nil:
			s.orgFailed(err)
			return false
		}
		sums[i] = m
		return true
	}
	// The versions other signals suggest first: one of them is often right.
	for _, h := range hints {
		load(slices.Index(releases, h.Value))
	}
	next := 0 // the newest release not loaded by the batches yet
	var picker *corehash.Picker
	matched := false
	narrow := func() []int {
		db := checksumDB(releases, sums)
		picker = corehash.NewPicker(db)
		matched = false
		for rel, sum := range observed {
			if picker.Observe(rel, sum) {
				matched = true
			}
		}
		for rel := range tried {
			picker.Skip(rel)
		}
		if !matched {
			return nil
		}
		var idx []int
		for _, v := range picker.Candidates() {
			idx = append(idx, slices.Index(releases, v))
		}
		return idx
	}
	var cands []int
	for ctx.Err() == nil && !s.orgDown.Load() {
		cands = narrow()
		grew := false
		if len(cands) > 0 {
			// Releases next to the match may be the same files: load them
			// until one on each side differs.
			grew = load(slices.Max(cands)+1) || grew
			grew = load(slices.Min(cands)-1) || grew
		} else {
			if len(observed) == 0 && len(sums) > 0 {
				// No page shows a file of the plugin: ask for the one
				// that tells the most releases apart.
				rel, ok := picker.Next()
				if !ok || requests >= maxHashRequests {
					break // nothing of the plugin can be read: its releases do not matter
				}
				fetch(rel, true)
				continue
			}
			for n := 0; n < checksumBatch && next < len(releases); next++ {
				if load(next) {
					n++
					grew = true
				}
			}
		}
		if !grew {
			break
		}
	}
	if len(cands) == 0 || s.orgDown.Load() {
		return
	}
	// The match must be closed on both sides, or older or newer releases
	// that were not loaded may be the same files.
	if hi := slices.Min(cands) - 1; hi >= 0 && sums[hi] == nil {
		return
	}
	if lo := slices.Max(cands) + 1; lo < len(releases) && sums[lo] == nil {
		return
	}
	for len(cands) > 1 && requests < maxHashRequests && ctx.Err() == nil {
		rel, ok := picker.Next()
		if !ok {
			break
		}
		fetch(rel, true)
		cands = narrow()
	}
	if len(cands) == 0 || len(cands) > maxHashReleases {
		return
	}
	names := make([]string, len(cands))
	for i, idx := range cands {
		names[i] = releases[idx]
	}
	slices.SortFunc(names, vulndb.Compare)
	u := base
	for rel := range observed {
		u = base + rel
		break
	}
	if len(names) == 1 {
		set.addVersion(c.slug, Evidence{Method: "File hashes (WordPress.org checksums)", Mode: modeAggressive, URL: u, Value: names[0], Confidence: confHashRelease})
		set.confirm(c.slug)
		return
	}
	method := "File hashes (WordPress.org checksums; one of " + strings.Join(names, ", ") + ")"
	current := combineVersions(hints).Number
	if slices.Contains(names, current) {
		set.addVersion(c.slug, Evidence{Method: method, Mode: modeAggressive, URL: u, Value: current, Confidence: confHashAgrees})
	} else {
		for _, v := range names {
			set.addVersion(c.slug, Evidence{Method: method, Mode: modeAggressive, URL: u, Value: v, Confidence: confHashReleases})
		}
	}
	set.confirm(c.slug)
}

// checksumDB indexes the loaded releases for the picker.
func checksumDB(releases []string, sums map[int]map[string][]string) *corehash.DB {
	db := &corehash.DB{Files: map[string]map[string][]int{}}
	var loaded []int
	for i := range sums {
		loaded = append(loaded, i)
	}
	slices.SortFunc(loaded, func(a, b int) int { return b - a }) // oldest first, as the picker expects
	for n, i := range loaded {
		db.Versions = append(db.Versions, releases[i])
		for path, hashes := range sums[i] {
			if db.Files[path] == nil {
				db.Files[path] = map[string][]int{}
			}
			for _, h := range hashes {
				db.Files[path][h] = append(db.Files[path][h], n)
			}
		}
	}
	return db
}

// relativeTo returns the path of a plugin's file inside the plugin's
// folder: "assets/css/a.css" for ".../plugins/slug/assets/css/a.css?ver=1".
func relativeTo(raw, slug string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	i := strings.Index(strings.ToLower(u.Path), "/"+strings.ToLower(slug)+"/")
	if i < 0 {
		return ""
	}
	return u.Path[i+len(slug)+2:]
}

var (
	potProjectRe = regexp.MustCompile(`(?m)^"Project-Id-Version:\s*(.*?)\\n"`)
	potVersionRe = regexp.MustCompile(`\bv?(\d+(?:\.\d+){1,3})\s*$`)
)

// potVersion reads the version from the header of the plugin's
// translation template, which the tools that build it fill in:
// "Project-Id-Version: Plugin Name 1.2.3". Developers do not always
// rebuild it, so it can lag behind.
func (s *Scanner) potVersion(ctx context.Context, set *componentSet, c *component, dir *url.URL) {
	base := under(dir, c.slug+"/")
	paths := []string{"languages/" + c.slug + ".pot"}
	if s.thorough() {
		paths = append(paths, "lang/"+c.slug+".pot", "i18n/languages/"+c.slug+".pot")
	}
	for _, p := range paths {
		u := base + p
		res := s.get(ctx, u)
		if res == nil || res.StatusCode != http.StatusOK || isHTML(res.Body) {
			continue
		}
		head := res.Body[:min(len(res.Body), 4096)]
		m := potProjectRe.FindSubmatch(head)
		if m == nil {
			continue
		}
		set.confirm(c.slug)
		if v := potVersionRe.FindSubmatch(m[1]); v != nil && vulndb.Valid(string(v[1])) {
			set.addVersion(c.slug, Evidence{Method: "Translation template (" + p + ")", Mode: modeAggressive, URL: u, Value: vulndb.Normalize(string(v[1])), Confidence: confVersionPot})
		}
		return
	}
}

// packageVersion reads the version from the plugin's package.json, which
// some plugins ship with their build. A project that never set it still
// says 1.0.0, so that value does not count.
func (s *Scanner) packageVersion(ctx context.Context, set *componentSet, c *component, dir *url.URL) {
	u := under(dir, c.slug+"/") + "package.json"
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != http.StatusOK || isHTML(res.Body) {
		return
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(res.Body, &pkg) != nil || pkg.Name == "" {
		return
	}
	set.confirm(c.slug)
	switch v := vulndb.Normalize(pkg.Version); {
	case !vulndb.Valid(v) || !strings.Contains(v, "."):
	case v == "1.0.0" || v == "0.0.0" || v == "0.1.0":
	default:
		set.addVersion(c.slug, Evidence{Method: "package.json", Mode: modeAggressive, URL: u, Value: v, Confidence: confVersionPackage})
	}
}
