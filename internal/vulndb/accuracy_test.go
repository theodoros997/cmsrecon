package vulndb

import (
	"strings"
	"testing"
)

func adv(source, slug string, cve string, ranges ...Range) *Vuln {
	return &Vuln{ID: source + "-" + slug, Title: slug + " issue", Kind: KindPlugin, Slug: slug, CVE: []string{cve}, Affected: ranges}
}

func TestMergeByCVEKeepsSlugs(t *testing.T) {
	upTo := func(v string) Range { return Range{To: v, ToInclusive: true} }
	db := New(
		&SourceFile{Source: SourceWordfence, Vulnerabilities: []*Vuln{adv("wf", "foo", "CVE-2026-1", upTo("1.5")), adv("wf", "foo-pro", "CVE-2026-1", upTo("4.2"))}},
		&SourceFile{Source: SourceCVE, Vulnerabilities: []*Vuln{adv("cve", "foo", "CVE-2026-1", upTo("1.5")), adv("cve", "foo-pro", "CVE-2026-1", upTo("4.2")), adv("cve", "foo-other", "CVE-2026-1", upTo("9"))}},
	)
	pro := db.Advisories(KindPlugin, "foo-pro")
	if len(pro) != 1 || len(pro[0].Sources) != 2 || pro[0].Sources[1].Affected[0].To != "4.2" {
		t.Fatalf("foo-pro = %+v: the CVE List's foo-pro entry belongs to foo-pro, once", pro)
	}
	if ms := db.Match(KindPlugin, "foo-pro", Detected{Version: "4.0", Confidence: 90}); len(ms) != 1 || ms[0].Verdict != VerdictConfirmed {
		t.Errorf("foo-pro 4.0 = %+v, want one confirmed match", ms)
	}
	if other := db.Advisories(KindPlugin, "foo-other"); len(other) != 0 {
		t.Errorf("an entry under a third slug for a CVE that names two plugins was kept: %+v", other)
	}
	// A CVE with a single advisory still takes a cross-check under another
	// slug: the primary source's slug is trusted.
	single := New(
		&SourceFile{Source: SourceWordfence, Vulnerabilities: []*Vuln{adv("wf", "bar", "CVE-2026-2", upTo("2.0"))}},
		&SourceFile{Source: SourceCVE, Vulnerabilities: []*Vuln{adv("cve", "bar-plugin", "CVE-2026-2", upTo("2.0"))}},
	)
	if b := single.Advisories(KindPlugin, "bar"); len(b) != 1 || len(b[0].Sources) != 2 || len(single.Advisories(KindPlugin, "bar-plugin")) != 0 {
		t.Errorf("bar = %+v", b)
	}
}

func TestGuessedSlugIsAtMostLikely(t *testing.T) {
	v := adv("cve", "some-plugin", "CVE-2026-3", Range{To: "2.0", ToInclusive: true})
	v.Guessed = true
	db := New(&SourceFile{Source: SourceCVE, Vulnerabilities: []*Vuln{v}})
	ms := db.Match(KindPlugin, "some-plugin", Detected{Version: "1.0", Confidence: 100})
	if len(ms) != 1 || ms[0].Verdict != VerdictLikely || !strings.Contains(ms[0].Note, "product name") {
		t.Errorf("guessed = %+v", ms)
	}
}

func TestCoreBackports(t *testing.T) {
	mk := func(source string, fixed []string, ranges ...Range) *Advisory {
		return &Advisory{Title: "core", Kind: KindCore, Slug: CoreSlug, Fixed: fixed, Sources: []SourceRanges{{Source: source, Affected: ranges}}}
	}
	below := func(v string) Range { return Range{To: v} }
	cveOnly := mk(SourceCVE, []string{"5.8.3"}, below("5.8.3"))
	branchFixes := mk(SourceCVE, []string{"5.7.5", "5.8.3"}, below("5.8.3"))
	wordfence := mk(SourceWordfence, []string{"5.8.3"}, below("5.8.3"))
	for _, tt := range []struct {
		version string
		advs    []*Advisory
		want    []string // verdicts
	}{
		{"5.8.2", []*Advisory{cveOnly}, []string{VerdictConfirmed}},     // the fix's own branch
		{"5.7.5", []*Advisory{cveOnly}, []string{VerdictPossible}},      // an older branch may have it backported
		{"5.7.5", []*Advisory{branchFixes}, nil},                        // 5.7.5 is the backport
		{"5.7.4", []*Advisory{branchFixes}, []string{VerdictConfirmed}}, // before the backport
		{"5.7.5", []*Advisory{wordfence}, []string{VerdictConfirmed}},   // Wordfence ranges are per branch already
	} {
		d := Detected{Version: tt.version, Confidence: 100}
		ms := CoreBackports(MatchAdvisories(tt.advs, d), tt.version)
		var got []string
		for _, m := range ms {
			got = append(got, m.Verdict)
		}
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("%s: verdicts %v, want %v", tt.version, got, tt.want)
		}
	}
}

const multiProductRecord = `{"cveMetadata": {"cveId": "CVE-2026-9000", "state": "PUBLISHED", "datePublished": "2026-01-01T00:00:00Z"},
 "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Acme Forms and Acme Gallery plugins for WordPress are vulnerable to XSS."}],
  "affected": [
   {"vendor": "acme", "product": "Acme Forms", "versions": [{"version": "*", "lessThanOrEqual": "1.4", "status": "affected"}]},
   {"vendor": "acme", "product": "Acme Gallery", "versions": [{"version": "*", "lessThanOrEqual": "3.1", "status": "affected"}]}],
  "references": [{"url": "https://wordpress.org/plugins/acme-forms/"}, {"url": "https://plugins.trac.wordpress.org/changeset/1/acme-forms"}, {"url": "https://wordpress.org/plugins/acme-gallery/"}]}}}`

const patchstackThemeRecord = `{"cveMetadata": {"cveId": "CVE-2026-9001", "state": "PUBLISHED"},
 "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Cross-site scripting in Astrid."}],
  "affected": [{"vendor": "x", "product": "Astrid", "versions": [{"version": "n/a", "lessThanOrEqual": "1.2", "status": "affected"}]}],
  "references": [{"url": "https://patchstack.com/database/vulnerability/astrid/wordpress-astrid-theme-1-2-cross-site-scripting-xss-vulnerability"}]}}}`

func TestCVERecordProducts(t *testing.T) {
	vulns := ParseCVERecord([]byte(multiProductRecord))
	got := map[string]string{}
	for _, v := range vulns {
		got[v.Slug] = strings.Join(rangeStrings(v.Affected), " ")
	}
	if got["acme-forms"] != "<= 1.4" || got["acme-gallery"] != "<= 3.1" || len(got) != 2 {
		t.Errorf("multi-product record = %v, want each product's own range", got)
	}
	theme := ParseCVERecord([]byte(patchstackThemeRecord))
	if len(theme) != 1 || theme[0].Kind != KindTheme || theme[0].Slug != "astrid" {
		t.Errorf("legacy Patchstack theme URL = %+v", theme)
	}
}
