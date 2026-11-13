package scan

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/corehash"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// MinVersionConfidence is the confidence below which a version is reported
// as unknown.
const MinVersionConfidence = 40

// Confidence of each core version signal.
const (
	confMetaGenerator = 60
	confFeedGenerator = 80
	confReadme        = 70
	confVersionPHP    = 100
	confLoadStyles    = 60  // ?ver= on load-styles.php, load-scripts.php or the emoji script, which WordPress sets to its version
	confInstallPage   = 80  // ?ver= on the install page, which no plugin or theme can change
	confHashOne       = 100 // the file hashes match one release only
	confHashNewest    = 60  // they match the newest release the checksums know, which a later one may look like
	confHashConfirms  = 90  // they match a few releases, among them the one the other signals found
	confHashFew       = 50  // they match a few releases and nothing else picks one: each gets this
	maxHashCandidates = 4
)

// Limits of the file hash check: how many files it downloads at most, and
// after how many misses in a row (blocked, missing or modified files) it
// gives up.
const (
	maxHashFiles  = 6
	maxHashMisses = 3
)

// versionRe matches WordPress version numbers: 6.4, 6.4.2, 6.5-RC1.
var versionRe = regexp.MustCompile(`^\d{1,2}\.\d{1,2}(?:\.\d{1,3})?(?:-[0-9A-Za-z.-]+)?$`)

var (
	metaGeneratorRe = regexp.MustCompile(`(?i)^WordPress\s+(\S+)$`)
	feedElementRe   = regexp.MustCompile(`(?is)<generator\b[^>]*>.*?</generator>|<admin:generatorAgent\b[^>]*>`)
	feedVersionRe   = regexp.MustCompile(`(?i)(?:\?v=|version=["'])([0-9][0-9A-Za-z.-]*)`)
	readmeVersionRe = regexp.MustCompile(`(?i)<br\s*/?>\s*version\s+(\d+\.\d+(?:\.\d+)?)`)
)

// coreVendorPaths are libraries bundled in wp-includes whose ?ver= is the
// library's own version, not WordPress's.
var coreVendorPaths = []string{
	"js/tinymce/", "js/mediaelement/", "js/dist/vendor/", "js/plupload/",
	"js/codemirror/", "js/crop/", "js/imgareaselect/", "js/jcrop/", "js/swfupload/", "js/thickbox/",
	"js/underscore", "js/backbone", "js/masonry", "js/imagesloaded", "js/hoverintent", "js/clipboard",
	"js/zxcvbn", "js/json2", "js/colorpicker", "js/twemoji", "js/swfobject", "js/tw-sack",
	"js/jquery", "css/jquery-ui",
}

func validVersion(v string) bool { return versionRe.MatchString(v) }

// settledConfidence is the confidence from which a version needs no more
// evidence: two independent signals that agree reach it.
const settledConfidence = 90

// settled reports whether the version is certain enough to stop asking:
// one number at settledConfidence or more, and no other number a signal
// seriously suggests.
func settled(v *Version) bool {
	if v.Number == "" || v.Confidence < settledConfidence {
		return false
	}
	for _, c := range v.Candidates[1:] {
		if c.Confidence >= MinVersionConfidence {
			return false
		}
	}
	return true
}

// detectVersion runs the core version finders the detection mode allows.
//
// The passive ones cost nothing: they read the pages the scan already
// has. The others are tried from the cheapest to the dearest, and the
// scan stops at the first that settles the version, so a site that shows
// its version in its feed costs one request, and only a site that hides it
// everywhere gets the file hashes. --aggressive tries them all.
func (s *Scanner) detectVersion(ctx context.Context) *Version {
	var ev []Evidence
	linked := map[string]bool{}
	if s.passive() {
		ev = append(ev, s.metaGeneratorVersion()...)
		ev = append(ev, s.coreAssetVersions(s.pages())...)
		for _, u := range s.linkedFeeds() {
			linked[u] = true
			ev = append(ev, s.feedVersion(ctx, u, modePassive)...)
		}
	}
	if !s.aggressive() {
		return combineVersions(ev)
	}
	feeds := []string{s.url("feed/"), s.url("feed/atom/"), s.url("feed/rdf/")}
	steps := []func() []Evidence{
		func() []Evidence {
			if linked[feeds[0]] {
				return nil
			}
			e := s.feedVersion(ctx, feeds[0], modeAggressive)
			if res := s.get(ctx, feeds[0]); res == nil || res.StatusCode != 200 {
				// Without pretty permalinks the feed lives at ?feed=rss2.
				e = append(e, s.feedVersion(ctx, s.urlWithQuery("", "feed=rss2"), modeAggressive)...)
			}
			return e
		},
		// The crawled pages, the login page among them, load core assets
		// too (load-styles.php keeps ?ver= when themes strip it).
		func() []Evidence { return s.coreAssetVersions(s.sitePages(ctx).pages) },
		func() []Evidence { return s.readmeVersion(ctx) },
		func() []Evidence { return s.opmlVersion(ctx) },
		func() []Evidence { return s.installPageVersion(ctx) },
		func() []Evidence { return s.versionPHPSource(ctx) },
		func() []Evidence {
			var e []Evidence
			for _, u := range feeds[1:] {
				if !linked[u] {
					e = append(e, s.feedVersion(ctx, u, modeAggressive)...)
				}
			}
			return e
		},
		func() []Evidence {
			cands, u := s.hashVersion(ctx)
			if len(cands) == 0 {
				return nil
			}
			return hashEvidence(cands, u, combineVersions(ev), s.data.hashes.Versions[len(s.data.hashes.Versions)-1])
		},
	}
	for _, step := range steps {
		if ctx.Err() != nil || (!s.thorough() && settled(combineVersions(ev))) {
			break
		}
		ev = append(ev, step()...)
	}
	return combineVersions(ev)
}

var opmlGeneratorRe = regexp.MustCompile(`generator="WordPress/([0-9][0-9A-Za-z.-]*)"`)

// opmlVersion reads the generator comment of wp-links-opml.php, which
// WordPress still serves although the link manager it belongs to is long
// hidden: themes and plugins that remove the version from pages and feeds
// often forget it.
func (s *Scanner) opmlVersion(ctx context.Context) []Evidence {
	u := s.coreURL("wp-links-opml.php")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 || !bytes.Contains(res.Body, []byte("<opml")) {
		return nil
	}
	if m := opmlGeneratorRe.FindSubmatch(res.Body); m != nil && validVersion(string(m[1])) {
		return []Evidence{{Method: "wp-links-opml.php generator", Mode: modeAggressive, URL: u, Value: string(m[1]), Confidence: confFeedGenerator}}
	}
	return nil
}

// installPageVersion reads ?ver= on the stylesheets of
// wp-admin/install.php. On an installed site the page only says so, but
// WordPress builds it without loading plugins or the theme, so nothing
// can strip the version from its links.
func (s *Scanner) installPageVersion(ctx context.Context) []Evidence {
	u := s.coreURL("wp-admin/install.php")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 || res.Blocked != "" {
		return nil
	}
	versions := map[string]int{}
	own := false // the page links its own stylesheet: it is the install page, not a soft 404
	for _, ref := range parsePage(res).urls {
		_, admin, adm := strings.Cut(ref.Path, "/wp-admin/css/")
		_, rel, inc := strings.Cut(ref.Path, "/wp-includes/")
		if !adm && !(inc && !isCoreVendor(rel)) {
			continue
		}
		own = own || strings.HasPrefix(admin, "install")
		if ver := ref.Query().Get("ver"); validVersion(ver) {
			versions[ver]++
		}
	}
	if !own || len(versions) != 1 {
		return nil
	}
	for ver := range versions {
		return []Evidence{{Method: "?ver= on the stylesheets of wp-admin/install.php", Mode: modeAggressive, URL: u, Value: ver, Confidence: confInstallPage}}
	}
	return nil
}

// hashEvidence turns the releases whose files match into evidence. One
// release is certain. A few (security releases often change no static
// file) confirm the version the other signals found when it is one of
// them; otherwise each becomes a candidate.
//
// newest is the newest release the checksums know. A release that came out
// after the last "cmsrecon update" and changed no static file looks like
// it, so the newest release alone is not certain, and when the pages name
// a newer release, the checksums cannot tell at all.
func hashEvidence(cands []string, u string, others *Version, newest string) []Evidence {
	if others.Number != "" && newest != "" && vulndb.Compare(others.Number, newest) > 0 {
		return nil
	}
	switch {
	case len(cands) == 1 && cands[0] == newest:
		return []Evidence{{Method: "File hashes (this or a later release that changed no static file)", Mode: modeAggressive, URL: u, Value: cands[0], Confidence: confHashNewest}}
	case len(cands) == 1:
		return []Evidence{{Method: "File hashes", Mode: modeAggressive, URL: u, Value: cands[0], Confidence: confHashOne}}
	case len(cands) > maxHashCandidates:
		return nil // too vague to count
	}
	method := "File hashes (one of " + strings.Join(cands, ", ") + ")"
	if others.Number != "" && slices.Contains(cands, others.Number) {
		return []Evidence{{Method: method, Mode: modeAggressive, URL: u, Value: others.Number, Confidence: confHashConfirms}}
	}
	var ev []Evidence
	for _, v := range cands {
		ev = append(ev, Evidence{Method: method, Mode: modeAggressive, URL: u, Value: v, Confidence: confHashFew})
	}
	return ev
}

// hashVersion downloads a few core scripts and stylesheets and compares
// their MD5 hashes with those of every release since 3.0, from the
// checksums "cmsrecon update" downloads from WordPress.org. Each file is
// picked to split the remaining versions best, so a handful of requests
// usually leaves one release, or the few security releases that changed no
// static file.
//
// It returns the releases still possible and the last file that matched,
// or nothing when no file matched.
func (s *Scanner) hashVersion(ctx context.Context) ([]string, string) {
	db := s.data.hashes
	if db == nil || len(db.Versions) == 0 {
		return nil, ""
	}
	p := corehash.NewPicker(db)
	var matched []string
	misses := 0
	for range maxHashFiles {
		if misses >= maxHashMisses {
			break
		}
		path, ok := p.Next()
		if !ok {
			break
		}
		u := s.coreURL(path)
		res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 4 << 20})
		if res == nil || res.StatusCode != http.StatusOK || res.Truncated || (isHTML(res.Body) && !strings.HasSuffix(path, ".html")) {
			p.Skip(path)
			misses++
			continue
		}
		sum := md5.Sum(res.Body)
		if p.Observe(path, hex.EncodeToString(sum[:])) {
			matched = append(matched, u)
			misses = 0
		} else {
			misses++
		}
	}
	if len(matched) == 0 {
		return nil, ""
	}
	return p.Candidates(), matched[len(matched)-1]
}

// combineVersions groups evidence by version number and picks the number
// with the highest combined confidence. Below MinVersionConfidence the
// version is unknown (empty Number), but candidates and evidence are kept.
func combineVersions(ev []Evidence) *Version {
	v := &Version{Candidates: []Candidate{}, Evidence: ev}
	if v.Evidence == nil {
		v.Evidence = []Evidence{}
	}
	byNumber := map[string][]Evidence{}
	for _, e := range ev {
		byNumber[e.Value] = append(byNumber[e.Value], e)
	}
	for n, e := range byNumber {
		v.Candidates = append(v.Candidates, Candidate{Number: n, Confidence: combine(e)})
	}
	sort.Slice(v.Candidates, func(i, j int) bool {
		a, b := v.Candidates[i], v.Candidates[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return compareVersions(a.Number, b.Number) > 0
	})
	sortEvidence(v.Evidence)
	if len(v.Candidates) > 0 && v.Candidates[0].Confidence >= MinVersionConfidence {
		v.Number, v.Confidence = v.Candidates[0].Number, v.Candidates[0].Confidence
	}
	return v
}

// compareVersions compares dotted version numbers numerically; a
// pre-release suffix sorts before the release.
func compareVersions(a, b string) int {
	ma, pa, _ := strings.Cut(a, "-")
	mb, pb, _ := strings.Cut(b, "-")
	sa, sb := strings.Split(ma, "."), strings.Split(mb, ".")
	for i := range max(len(sa), len(sb)) {
		var x, y int
		if i < len(sa) {
			x, _ = strconv.Atoi(sa[i])
		}
		if i < len(sb) {
			y, _ = strconv.Atoi(sb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	return strings.Compare(pa, pb)
}

func (s *Scanner) metaGeneratorVersion() []Evidence {
	for _, g := range s.home.generators {
		if m := metaGeneratorRe.FindStringSubmatch(g); m != nil && validVersion(m[1]) {
			return []Evidence{{
				Method: "Meta generator", Mode: modePassive, URL: s.base.String(), Value: m[1], Confidence: confMetaGenerator,
			}}
		}
	}
	return nil
}

// coreAssetVersions reads ?ver= from core scripts and styles under
// wp-includes. WordPress stamps its own version on them, so the more core
// assets agree, the higher the confidence: 30% for one, up to 60% for four.
func (s *Scanner) coreAssetVersions(pages []labelledPage) []Evidence {
	assets := map[string]map[string]bool{} // version -> asset paths
	example := map[string]string{}
	loaders := map[string]string{} // version -> a load-styles.php or load-scripts.php URL
	emoji := map[string]string{}   // version -> the emoji script's URL, from the page's emoji settings
	mode := modePassive
	for _, p := range pages {
		for _, orig := range p.urls {
			u, ok := s.siteURL(orig)
			if !ok {
				continue
			}
			// The core's own scripts and styles: wp-includes, minus the
			// libraries it bundles, and wp-admin's CSS and the
			// load-styles.php and load-scripts.php the login page uses.
			_, rel, inc := strings.Cut(u.Path, "/wp-includes/")
			_, admin, adm := strings.Cut(u.Path, "/wp-admin/")
			switch {
			case inc && !isCoreVendor(rel):
			case adm && (admin == "load-styles.php" || admin == "load-scripts.php" || strings.HasPrefix(admin, "css/")):
			default:
				continue
			}
			ver := u.Query().Get("ver")
			if !validVersion(ver) {
				continue
			}
			if p.mode == modeAggressive {
				mode = modeAggressive
			}
			// WordPress always sets these to its own version, whatever
			// the theme does with the other links.
			if adm && (admin == "load-styles.php" || admin == "load-scripts.php") {
				loaders[ver] = u.String()
				continue
			}
			if inc && rel == "js/wp-emoji-release.min.js" {
				emoji[ver] = u.String()
				continue
			}
			if assets[ver] == nil {
				assets[ver] = map[string]bool{}
				example[ver] = u.String()
			}
			assets[ver][u.Path] = true
		}
	}
	var ev []Evidence
	for ver, u := range loaders {
		ev = append(ev, Evidence{Method: "?ver= on wp-admin's load-styles.php", Mode: mode, URL: u, Value: ver, Confidence: confLoadStyles})
	}
	for ver, u := range emoji {
		ev = append(ev, Evidence{Method: "?ver= on the emoji script", Mode: mode, URL: u, Value: ver, Confidence: confLoadStyles})
	}
	for ver, paths := range assets {
		ev = append(ev, Evidence{
			Method: "?ver= on core assets", Mode: mode, URL: example[ver], Value: ver,
			Confidence: min(20+10*len(paths), 60),
		})
	}
	return ev
}

func isCoreVendor(rel string) bool {
	rel = strings.ToLower(rel)
	for _, p := range coreVendorPaths {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// linkedFeeds returns the in-scope feeds the homepage links to.
func (s *Scanner) linkedFeeds() []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range s.home.links {
		if !strings.Contains(l.rel, "alternate") || !s.client.InScope(l.href) {
			continue
		}
		switch l.typ {
		case "application/rss+xml", "application/atom+xml", "application/rdf+xml":
			if u := l.href.String(); !seen[u] && len(out) < 5 {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

// feedVersion reads the generator of an RSS, Atom or RDF feed.
func (s *Scanner) feedVersion(ctx context.Context, u, mode string) []Evidence {
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 {
		return nil
	}
	kind := "RSS"
	switch head := bytes.ToLower(res.Body[:min(len(res.Body), 2048)]); {
	case bytes.Contains(head, []byte("<feed")):
		kind = "Atom"
	case bytes.Contains(head, []byte("<rdf:rdf")):
		kind = "RDF"
	case !bytes.Contains(head, []byte("<rss")):
		return nil
	}
	for _, el := range feedElementRe.FindAll(res.Body, -1) {
		if !bytes.Contains(bytes.ToLower(el), []byte("wordpress")) {
			continue
		}
		if m := feedVersionRe.FindSubmatch(el); m != nil && validVersion(string(m[1])) {
			return []Evidence{{
				Method: kind + " feed generator", Mode: mode, URL: u, Value: string(m[1]), Confidence: confFeedGenerator,
			}}
		}
	}
	return nil
}

func (s *Scanner) readmeVersion(ctx context.Context) []Evidence {
	u := s.coreURL("readme.html")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 {
		return nil
	}
	if m := readmeVersionRe.FindSubmatch(res.Body); m != nil && validVersion(string(m[1])) {
		if ref, _ := url.Parse(u); !s.isNotFound(ctx, ref, res) {
			return []Evidence{{Method: "readme.html", Mode: modeAggressive, URL: u, Value: string(m[1]), Confidence: confReadme}}
		}
	}
	return nil
}

// versionPHPSource reads $wp_version when the server returns PHP source.
func (s *Scanner) versionPHPSource(ctx context.Context) []Evidence {
	u := s.coreURL("wp-includes/version.php")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 || !bytes.Contains(res.Body, []byte("<?php")) {
		return nil
	}
	if m := wpVersionVarRe.FindSubmatch(res.Body); m != nil && validVersion(string(m[1])) {
		return []Evidence{{Method: "wp-includes/version.php source", Mode: modeAggressive, URL: u, Value: string(m[1]), Confidence: confVersionPHP}}
	}
	return nil
}
