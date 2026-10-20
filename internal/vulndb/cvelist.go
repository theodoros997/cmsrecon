package vulndb

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CVE List V5 records, as published in github.com/CVEProject/cvelistV5.
// Only the fields cmsrecon uses are decoded.
type cveRecord struct {
	Metadata struct {
		ID            string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cveContainer   `json:"cna"`
		ADP []cveContainer `json:"adp"`
	} `json:"containers"`
}

type cveContainer struct {
	Title        string `json:"title"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Affected []struct {
		Vendor        string `json:"vendor"`
		Product       string `json:"product"`
		CollectionURL string `json:"collectionURL"`
		PackageName   string `json:"packageName"`
		Versions      []struct {
			Version         string `json:"version"`
			Status          string `json:"status"`
			LessThan        string `json:"lessThan"`
			LessThanOrEqual string `json:"lessThanOrEqual"`
		} `json:"versions"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Metrics []struct {
		V40 *cvssMetric `json:"cvssV4_0"`
		V31 *cvssMetric `json:"cvssV3_1"`
		V30 *cvssMetric `json:"cvssV3_0"`
		V20 *cvssMetric `json:"cvssV2_0"`
	} `json:"metrics"`
	ProblemTypes []struct {
		Descriptions []struct {
			CWEID       string `json:"cweId"`
			Description string `json:"description"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
}

type cvssMetric struct {
	BaseScore    flexFloat `json:"baseScore"`
	BaseSeverity string    `json:"baseSeverity"`
	VectorString string    `json:"vectorString"`
}

var (
	// Plugin and theme slugs in reference URLs.
	pluginRefRe = regexp.MustCompile(`(?i)(?:plugins\.trac\.wordpress\.org/(?:browser|log|changeset/\d+)|plugins\.svn\.wordpress\.org|wordpress\.org/plugins|downloads\.wordpress\.org/plugin|github\.com/WordpressPluginDirectory|patchstack\.com/database/(?:wordpress/plugin|vulnerability)|wpscan\.com/plugin|wordfence\.com/threat-intel/vulnerabilities/wordpress-plugins)/([a-z0-9][a-z0-9_-]*)`)
	themeRefRe  = regexp.MustCompile(`(?i)(?:themes\.trac\.wordpress\.org/(?:browser|log|changeset/\d+)|themes\.svn\.wordpress\.org|wordpress\.org/themes|downloads\.wordpress\.org/theme|patchstack\.com/database/wordpress/theme|wpscan\.com/theme|wordfence\.com/threat-intel/vulnerabilities/wordpress-themes)/([a-z0-9][a-z0-9_-]*)`)

	// Path segments after wordpress.org/plugins/ that are not slugs.
	notSlugs = map[string]bool{"browse": true, "tags": true, "tag": true, "search": true, "developers": true, "about": true, "author": true, "filter": true}

	// "The contact-form-7 (aka Contact Form 7) plugin": a slug in MITRE's
	// older descriptions.
	akaSlugRe = regexp.MustCompile(`(?i)\bthe ([a-z0-9][a-z0-9_-]*[a-z0-9]) \(aka [^)]*\) (plugin|theme)\b`)

	// Upper bounds in descriptions, for records without version data.
	descBeforeRe  = regexp.MustCompile(`(?i)\b(?:before|prior to|below|lower than|older than|<)\s*(?:version\s+|v)?(\d+(?:\.\d+)+)`)
	descThroughRe = regexp.MustCompile(`(?i)\b(?:through|up to,? and including,?|up to|until|<=)\s*(?:version\s+|v)?(\d+(?:\.\d+)+)`)
	descAndLowRe  = regexp.MustCompile(`(?i)\b(?:version\s+|v)?(\d+(?:\.\d+)+)\s+(?:and|or)\s+(?:earlier|older|below|lower|prior)\b`)

	coreDescRe = regexp.MustCompile(`(?i)^(?:in\s+)?wordpress(?:\s+core)?\s+(?:before|through|prior to|up to|versions?|<|\d)`)

	// Words that mark a premium edition in a product name.
	premiumWordRe = regexp.MustCompile(`(?i)\b(?:pro|premium|multisite|business|agency)\b`)
	// Product name noise removed before turning a name into a slug.
	productNoiseRe = regexp.MustCompile(`(?i)\b(?:wordpress\s+plugin|plugin\s+for\s+wordpress|for\s+wordpress|wordpress\s+theme|theme\s+for\s+wordpress|plugin|theme)\b`)
	slugCharsRe    = regexp.MustCompile(`[^a-z0-9]+`)
)

// ParseCVERecord turns a CVE List V5 record into the WordPress core,
// plugin or theme vulnerabilities it describes. Records about other
// software, rejected records and records without usable version ranges
// give nothing. The slug comes from the record's package name, then from
// wordpress.org, Trac, Patchstack, WPScan or Wordfence reference URLs,
// then from the product name; the affected versions from the structured
// version data, then from the description ("before 5.3.2").
func ParseCVERecord(data []byte) []*Vuln {
	var rec cveRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil
	}
	if !strings.EqualFold(rec.Metadata.State, "PUBLISHED") || !strings.HasPrefix(rec.Metadata.ID, "CVE-") {
		return nil
	}
	cna := &rec.Containers.CNA
	desc := cna.description()

	kind, slugs, guessed := cna.wordpressComponent(rec.Containers.ADP, desc)
	if kind == "" {
		return nil
	}

	base := Vuln{
		ID:        rec.Metadata.ID,
		Title:     cna.title(desc),
		Kind:      kind,
		Guessed:   guessed,
		CVE:       []string{rec.Metadata.ID},
		Published: datePart(rec.Metadata.DatePublished),
	}
	seen := map[string]bool{}
	for _, c := range append([]cveContainer{*cna}, rec.Containers.ADP...) {
		for _, r := range c.References {
			if u := strings.TrimSpace(r.URL); u != "" && !seen[u] {
				seen[u] = true
				base.References = append(base.References, u)
			}
		}
		if base.CVSS == 0 {
			base.CVSS, base.CVSSVector, base.Severity = c.cvss()
		}
		if base.CWE == "" {
			base.CWE = c.cwe()
		}
	}
	base.References = append(base.References, "https://www.cve.org/CVERecord?id="+rec.Metadata.ID)

	var out []*Vuln
	for _, slug := range slugs {
		v := base
		v.Slug = slug
		v.Affected, v.Fixed = cna.ranges(kind, slug, desc)
		if len(v.Affected) == 0 {
			continue
		}
		out = append(out, &v)
	}
	return out
}

func (c *cveContainer) description() string {
	for _, d := range c.Descriptions {
		if strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			return strings.TrimSpace(d.Value)
		}
	}
	if len(c.Descriptions) > 0 {
		return strings.TrimSpace(c.Descriptions[0].Value)
	}
	return ""
}

func (c *cveContainer) title(desc string) string {
	if t := strings.TrimSpace(c.Title); t != "" {
		return t
	}
	// The first sentence of the description, cut to a readable length.
	t := desc
	if i := strings.Index(t, ". "); i > 0 {
		t = t[:i]
	}
	if r := []rune(t); len(r) > 140 {
		t = strings.TrimSpace(string(r[:139])) + "…"
	}
	return t
}

func (c *cveContainer) cvss() (float64, string, string) {
	for _, m := range c.Metrics {
		for _, v := range []*cvssMetric{m.V31, m.V30, m.V40, m.V20} {
			if v != nil && v.BaseScore > 0 {
				sev := normalizeSeverity(v.BaseSeverity)
				if sev == "" {
					sev = SeverityFromScore(float64(v.BaseScore))
				}
				return float64(v.BaseScore), v.VectorString, sev
			}
		}
	}
	return 0, "", ""
}

func (c *cveContainer) cwe() string {
	for _, pt := range c.ProblemTypes {
		for _, d := range pt.Descriptions {
			if !strings.HasPrefix(d.CWEID, "CWE-") {
				continue
			}
			name := strings.TrimSpace(strings.TrimPrefix(d.Description, d.CWEID))
			if name == "" {
				return d.CWEID
			}
			return d.CWEID + " " + name
		}
	}
	return ""
}

// wordpressComponent decides whether the record is about WordPress core, a
// plugin or a theme, and which slugs it affects. guessed is true when the
// slugs come from product names rather than from the record.
func (c *cveContainer) wordpressComponent(adp []cveContainer, desc string) (kind string, slugs []string, guessed bool) {
	// 1. Package names: Patchstack and others give the wordpress.org slug.
	pkg := map[string][]string{}
	for _, a := range c.Affected {
		col := strings.ToLower(a.CollectionURL)
		name := strings.ToLower(strings.TrimSpace(a.PackageName))
		switch {
		case name == "":
		case strings.Contains(col, "wordpress.org/plugins"):
			pkg[KindPlugin] = appendUnique(pkg[KindPlugin], name)
		case strings.Contains(col, "wordpress.org/themes"):
			pkg[KindTheme] = appendUnique(pkg[KindTheme], name)
		}
	}
	if len(pkg[KindPlugin]) > 0 {
		return KindPlugin, pkg[KindPlugin], false
	}
	if len(pkg[KindTheme]) > 0 {
		return KindTheme, pkg[KindTheme], false
	}

	// 2. Reference URLs; the most referenced slug wins.
	var refs []string
	for _, ct := range append([]cveContainer{*c}, adp...) {
		for _, r := range ct.References {
			refs = append(refs, r.URL)
		}
	}
	if slug := mostReferenced(pluginRefRe, refs); slug != "" {
		return KindPlugin, []string{slug}, false
	}
	if slug := mostReferenced(themeRefRe, refs); slug != "" {
		return KindTheme, []string{slug}, false
	}

	lower := strings.ToLower(desc)
	if m := akaSlugRe.FindStringSubmatch(desc); m != nil && strings.Contains(lower, "wordpress") {
		return strings.ToLower(m[2]), []string{strings.ToLower(m[1])}, false
	}

	// 3. Core: the product is WordPress itself.
	for _, a := range c.Affected {
		p := strings.ToLower(strings.TrimSpace(a.Product))
		if p == "wordpress" || p == "wordpress-develop" || p == "wordpress core" {
			return KindCore, []string{CoreSlug}, false
		}
	}
	if coreDescRe.MatchString(desc) && !strings.Contains(lower[:min(len(lower), 120)], " plugin") && !strings.Contains(lower[:min(len(lower), 120)], " theme") {
		return KindCore, []string{CoreSlug}, false
	}

	// 4. A plugin or theme named in the description: the product name
	// turned into a slug, the way wordpress.org derives most slugs.
	isPlugin := strings.Contains(lower, "plugin for wordpress") || strings.Contains(lower, "wordpress plugin") ||
		(strings.Contains(lower, "plugin before") && strings.Contains(lower, "for wordpress"))
	isTheme := strings.Contains(lower, "theme for wordpress") || strings.Contains(lower, "wordpress theme")
	if !isPlugin && !isTheme {
		return "", nil, false
	}
	kind = KindPlugin
	if isTheme && !isPlugin {
		kind = KindTheme
	}
	for _, a := range c.Affected {
		if s := slugify(a.Product); s != "" && s != "n-a" {
			slugs = appendUnique(slugs, s)
		}
	}
	if len(slugs) == 0 {
		return "", nil, false
	}
	return kind, slugs, true
}

func mostReferenced(re *regexp.Regexp, refs []string) string {
	counts := map[string]int{}
	var order []string
	for _, r := range refs {
		for _, m := range re.FindAllStringSubmatch(r, -1) {
			s := strings.ToLower(m[1])
			if notSlugs[s] {
				continue
			}
			if counts[s] == 0 {
				order = append(order, s)
			}
			counts[s]++
		}
	}
	best := ""
	for _, s := range order {
		if counts[s] > counts[best] {
			best = s
		}
	}
	return best
}

// slugify turns a product name into the slug wordpress.org would most
// likely give it: "WooCommerce Payments WordPress Plugin" gives
// "woocommerce-payments".
func slugify(name string) string {
	name = productNoiseRe.ReplaceAllString(name, " ")
	return strings.Trim(slugCharsRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// ranges returns the affected ranges and fixed versions for one slug.
func (c *cveContainer) ranges(kind, slug, desc string) ([]Range, []string) {
	// With several products (a free and a premium edition) and one slug,
	// prefer the editions whose names fit the slug.
	affected := c.Affected
	if len(affected) > 1 && kind != KindCore {
		var fit []int
		for i, a := range affected {
			if strings.EqualFold(a.PackageName, slug) || (!premiumWordRe.MatchString(a.Product) || premiumWordRe.MatchString(strings.ReplaceAll(slug, "-", " "))) {
				fit = append(fit, i)
			}
		}
		if len(fit) > 0 && len(fit) < len(affected) {
			var keep = affected[:0:0]
			for _, i := range fit {
				keep = append(keep, affected[i])
			}
			affected = keep
		}
	}

	var out []Range
	var fixed []string
	for _, a := range affected {
		if a.PackageName != "" && !strings.EqualFold(a.PackageName, slug) {
			continue
		}
		for _, v := range a.Versions {
			if !strings.EqualFold(v.Status, "affected") {
				continue
			}
			r, fix, ok := versionRange(v.Version, v.LessThan, v.LessThanOrEqual)
			if !ok {
				continue
			}
			out = append(out, r)
			if fix != "" {
				fixed = appendUnique(fixed, fix)
			}
		}
	}
	if len(out) == 0 {
		if r, fix, ok := descriptionRange(desc); ok {
			out = append(out, r)
			if fix != "" {
				fixed = append(fixed, fix)
			}
		}
	}
	sort.Slice(fixed, func(i, j int) bool { return Compare(fixed[i], fixed[j]) < 0 })
	return out, fixed
}

// versionRange turns one CVE "versions" entry into a range. It returns the
// fixed version when the entry has an exclusive upper bound.
func versionRange(version, lessThan, lessThanOrEqual string) (Range, string, bool) {
	version = Normalize(version)
	var r Range
	var fix string
	switch {
	case lessThan != "":
		if openBound(lessThan) {
			break
		}
		r.To = Normalize(lessThan)
		fix = r.To
	case lessThanOrEqual != "":
		if !openBound(lessThanOrEqual) {
			r.To, r.ToInclusive = Normalize(lessThanOrEqual), true
		}
	default:
		// GitHub's CNA writes expressions such as "< 5.8.3" in the version.
		if er, ok := parseRangeExpr(version); ok {
			if er.To != "" && !er.ToInclusive {
				fix = er.To
			}
			return er, fix, true
		}
		if version == "*" {
			return Range{}, "", true
		}
		if openBound(version) || !Valid(version) {
			return Range{}, "", false
		}
		return Range{From: version, FromInclusive: true, To: version, ToInclusive: true}, "", true
	}
	if r.To != "" && !Valid(r.To) {
		return Range{}, "", false
	}
	// "version" is the lower bound, unless it is a placeholder or, as in
	// WPScan's records, the upper bound repeated.
	if !openBound(version) && Valid(version) && (r.To == "" || Compare(version, r.To) < 0) {
		r.From, r.FromInclusive = version, true
	}
	return r, fix, true
}

// descriptionRange reads an upper bound from a description: "before
// 5.3.2", "through 6.3", "up to, and including, 1.2.3", "5.6.1 and lower".
func descriptionRange(desc string) (Range, string, bool) {
	type hit struct {
		pos  int
		r    Range
		fix  string
		incl bool
	}
	var best *hit
	try := func(re *regexp.Regexp, incl bool) {
		if loc := re.FindStringSubmatchIndex(desc); loc != nil {
			v := desc[loc[2]:loc[3]]
			h := &hit{pos: loc[0], r: Range{To: v, ToInclusive: incl}}
			if !incl {
				h.fix = v
			}
			if best == nil || h.pos < best.pos {
				best = h
			}
		}
	}
	try(descBeforeRe, false)
	try(descThroughRe, true)
	try(descAndLowRe, true)
	if best == nil {
		return Range{}, "", false
	}
	return best.r, best.fix, true
}

// ParseCVEZip reads a CVE List V5 archive, such as the
// "<date>_all_CVEs_at_midnight.zip.zip" release asset, and returns the
// WordPress vulnerabilities in it. Zip files inside the archive are
// opened too (the release asset is a zip that holds cves.zip). progress,
// when not nil, is called with the number of records read so far.
func ParseCVEZip(file string, progress func(records int)) ([]*Vuln, error) {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var out []*Vuln
	n := 0
	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(name, ".zip"):
			inner, err := extractTemp(f, filepath.Dir(file))
			if err != nil {
				return nil, err
			}
			vulns, err := ParseCVEZip(inner, func(k int) {
				if progress != nil {
					progress(n + k)
				}
			})
			os.Remove(inner)
			if err != nil {
				return nil, err
			}
			out = append(out, vulns...)
		case strings.HasSuffix(name, ".json") && strings.HasPrefix(path.Base(name), "cve-"):
			data, err := readZipFile(f)
			if err != nil {
				return nil, err
			}
			n++
			if progress != nil && n%20000 == 0 {
				progress(n)
			}
			// Most records are not about WordPress; skip them before
			// decoding.
			if !bytes.Contains(data, []byte("ordpress")) && !bytes.Contains(data, []byte("ORDPRESS")) {
				continue
			}
			out = append(out, ParseCVERecord(data)...)
		}
	}
	return out, nil
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Name, err)
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 16<<20))
}

func extractTemp(f *zip.File, dir string) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", fmt.Errorf("%s: %w", f.Name, err)
	}
	defer rc.Close()
	tmp, err := os.CreateTemp(dir, ".cmsrecon-cve-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("%s: %w", f.Name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}
