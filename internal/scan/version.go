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
	confHashOne       = 100 // the file hashes match one release only
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

// detectVersion runs the core version finders the detection mode allows.
func (s *Scanner) detectVersion(ctx context.Context) *Version {
	var ev []Evidence
	linked := map[string]bool{}
	if s.passive() {
		ev = append(ev, s.metaGeneratorVersion()...)
		ev = append(ev, s.coreAssetVersions()...)
		for _, u := range s.linkedFeeds() {
			linked[u] = true
			ev = append(ev, s.feedVersion(ctx, u, modePassive)...)
		}
	}
	if s.aggressive() {
		feeds := []string{s.url("feed/"), s.url("feed/atom/"), s.url("feed/rdf/")}
		for _, u := range feeds {
			if !linked[u] {
				ev = append(ev, s.feedVersion(ctx, u, modeAggressive)...)
			}
		}
		if res := s.get(ctx, feeds[0]); res == nil || res.StatusCode != 200 {
			// Without pretty permalinks the feed lives at ?feed=rss2.
			ev = append(ev, s.feedVersion(ctx, s.urlWithQuery("", "feed=rss2"), modeAggressive)...)
		}
		ev = append(ev, s.readmeVersion(ctx)...)
		ev = append(ev, s.versionPHPSource(ctx)...)
		if cands, u := s.hashVersion(ctx); len(cands) > 0 {
			ev = append(ev, hashEvidence(cands, u, combineVersions(ev))...)
		}
	}
	return combineVersions(ev)
}

// hashEvidence turns the releases whose files match into evidence. One
// release is certain. A few (security releases often change no static
// file) confirm the version the other signals found when it is one of
// them; otherwise each becomes a candidate.
func hashEvidence(cands []string, u string, others *Version) []Evidence {
	switch {
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
		u := s.url(path)
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
func (s *Scanner) coreAssetVersions() []Evidence {
	assets := map[string]map[string]bool{} // version -> asset paths
	example := map[string]string{}
	for _, p := range s.pages() {
		for _, u := range s.scopedURLs(p.page) {
			_, rel, ok := strings.Cut(u.Path, "/wp-includes/")
			if !ok || isCoreVendor(rel) {
				continue
			}
			ver := u.Query().Get("ver")
			if !validVersion(ver) {
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
	for ver, paths := range assets {
		ev = append(ev, Evidence{
			Method: "?ver= on core assets", Mode: modePassive, URL: example[ver], Value: ver,
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
	u := s.url("readme.html")
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
	u := s.url("wp-includes/version.php")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 || !bytes.Contains(res.Body, []byte("<?php")) {
		return nil
	}
	if m := wpVersionVarRe.FindSubmatch(res.Body); m != nil && validVersion(string(m[1])) {
		return []Evidence{{Method: "wp-includes/version.php source", Mode: modeAggressive, URL: u, Value: string(m[1]), Confidence: confVersionPHP}}
	}
	return nil
}
