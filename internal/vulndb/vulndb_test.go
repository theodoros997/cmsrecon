package vulndb

import (
	"archive/zip"
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"6.4.2", "6.4.2", 0},
		{"6.4", "6.4.0", 0},
		{"6.4.10", "6.4.9", 1},
		{"5.9", "6.0", -1},
		{"1.2.3.4", "1.2.3", 1},
		{"6.5-RC1", "6.5", -1},
		{"6.5-beta2", "6.5-RC1", -1},
		{"6.5-alpha", "6.5-beta", -1},
		{"2.0-dev", "2.0-alpha", -1},
		{"1.0", "1.0-p1", -1},
		{"v3.1", "3.1", 0},
		{"4.0.0RC2", "4.0.0", -1},
		{"10.0", "9.99", 1},
		{"1.01", "1.1", 0},
		{"2024.1.5", "2023.12.31", 1},
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := Compare(tt.b, tt.a); got != -tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestRange(t *testing.T) {
	tests := []struct {
		r    Range
		in   []string
		out  []string
		text string
	}{
		{Range{To: "5.3.1", ToInclusive: true}, []string{"1.0", "5.3.1"}, []string{"5.3.2", "6.0"}, "<= 5.3.1"},
		{Range{To: "5.3.2"}, []string{"5.3.1"}, []string{"5.3.2"}, "< 5.3.2"},
		{Range{From: "4.2", FromInclusive: true, To: "4.2.34", ToInclusive: true}, []string{"4.2", "4.2.34"}, []string{"4.1.9", "4.2.35", "4.3"}, "4.2 - 4.2.34"},
		{Range{From: "9.0.0", FromInclusive: true, To: "9.1.2"}, []string{"9.0.0", "9.1.1.1"}, []string{"8.9", "9.1.2"}, ">= 9.0.0, < 9.1.2"},
		{Range{}, []string{"0.1", "99"}, nil, "all versions"},
		{Range{From: "1.2", FromInclusive: true, To: "1.2", ToInclusive: true}, []string{"1.2", "1.2.0"}, []string{"1.2.1"}, "1.2"},
	}
	for _, tt := range tests {
		for _, v := range tt.in {
			if !tt.r.Contains(v) {
				t.Errorf("%s should contain %s", tt.text, v)
			}
		}
		for _, v := range tt.out {
			if tt.r.Contains(v) {
				t.Errorf("%s should not contain %s", tt.text, v)
			}
		}
		if s := tt.r.String(); s != tt.text {
			t.Errorf("String() = %q, want %q", s, tt.text)
		}
	}
}

func TestParseRangeExpr(t *testing.T) {
	tests := map[string]Range{
		"< 5.8.3":           {To: "5.8.3"},
		">= 4.2, < 4.2.34":  {From: "4.2", FromInclusive: true, To: "4.2.34"},
		"<= 1.0":            {To: "1.0", ToInclusive: true},
		">3.0.0,<=3.1.0":    {From: "3.0.0", To: "3.1.0", ToInclusive: true},
		"= 2.1":             {From: "2.1", FromInclusive: true, To: "2.1", ToInclusive: true},
		"Fixed version 5.6": {},
	}
	for expr, want := range tests {
		got, ok := parseRangeExpr(expr)
		if want == (Range{}) {
			if ok {
				t.Errorf("parseRangeExpr(%q) = %+v, want no match", expr, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("parseRangeExpr(%q) = %+v, %v; want %+v", expr, got, ok, want)
		}
	}
}

const wordfenceFeed = `{
 "a1b2": {
  "id": "a1b2",
  "title": "Contact Form 7 <= 5.3.1 - Unrestricted File Upload",
  "software": [{
   "type": "plugin", "name": "Contact Form 7", "slug": "contact-form-7",
   "affected_versions": {"* - 5.3.1": {"from_version": "*", "from_inclusive": true, "to_version": "5.3.1", "to_inclusive": true}},
   "patched": true, "patched_versions": ["5.3.2"], "remediation": "Update to version 5.3.2"
  }],
  "informational": false,
  "description": "...",
  "references": ["https://contactform7.com/2020/12/17/contact-form-7-532/"],
  "cwe": {"id": 434, "name": "Unrestricted Upload of File with Dangerous Type", "description": "..."},
  "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8, "rating": "Critical"},
  "cve": "CVE-2020-35489",
  "cve_link": "https://www.cve.org/CVERecord?id=CVE-2020-35489",
  "published": "2020-12-17 00:00:00",
  "updated": "2023-01-01 00:00:00"
 },
 "c3d4": {
  "id": "c3d4",
  "title": "WordPress Core 5.8 - 5.8.2 - SQL Injection",
  "software": [{
   "type": "core", "name": "WordPress", "slug": "wordpress",
   "affected_versions": {
    "5.8 - 5.8.2": {"from_version": "5.8", "from_inclusive": true, "to_version": "5.8.2", "to_inclusive": true},
    "5.7 - 5.7.4": {"from_version": "5.7", "from_inclusive": true, "to_version": "5.7.4", "to_inclusive": true}
   },
   "patched": true, "patched_versions": ["5.8.3", "5.7.5"]
  }],
  "informational": false,
  "references": [],
  "cwe": null,
  "cvss": {"vector": "", "score": "7.5", "rating": "High"},
  "cve": "CVE-2022-21661",
  "published": "2022-01-06 00:00:00"
 },
 "e5f6": {
  "id": "e5f6",
  "title": "Some Theme <= 2.0 - Reflected XSS (unpatched)",
  "software": [{
   "type": "theme", "name": "Some Theme", "slug": "Some-Theme",
   "affected_versions": {"* - 2.0": {"from_version": "*", "from_inclusive": true, "to_version": "2.0", "to_inclusive": true}},
   "patched": false, "patched_versions": []
  }],
  "informational": false, "references": [], "cwe": null, "cvss": null, "cve": null, "published": "2024-05-01 10:00:00"
 },
 "info": {
  "id": "info", "title": "Plugin closed", "informational": true,
  "software": [{"type": "plugin", "slug": "x", "affected_versions": {"*": {"from_version": "*", "to_version": "*"}}}]
 }
}`

func TestParseWordfence(t *testing.T) {
	vulns, err := ParseWordfence(strings.NewReader(wordfenceFeed))
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 3 {
		t.Fatalf("got %d vulns, want 3 (informational skipped): %+v", len(vulns), vulns)
	}
	cf7 := vulns[0]
	if cf7.Kind != KindPlugin || cf7.Slug != "contact-form-7" || cf7.CVE[0] != "CVE-2020-35489" || cf7.Severity != "critical" ||
		cf7.CVSS != 9.8 || cf7.Published != "2020-12-17" || !slices.Equal(cf7.Fixed, []string{"5.3.2"}) || cf7.Unfixed {
		t.Errorf("cf7 = %+v", cf7)
	}
	if cf7.CWE != "CWE-434 Unrestricted Upload of File with Dangerous Type" {
		t.Errorf("cwe = %q", cf7.CWE)
	}
	if !strings.Contains(cf7.References[0], "wordfence.com/threat-intel/vulnerabilities/id/a1b2") {
		t.Errorf("references = %v", cf7.References)
	}
	if len(cf7.Affected) != 1 || cf7.Affected[0] != (Range{To: "5.3.1", ToInclusive: true}) {
		t.Errorf("affected = %+v", cf7.Affected)
	}
	core := vulns[1]
	if core.Kind != KindCore || core.Slug != CoreSlug || len(core.Affected) != 2 || core.CVSS != 7.5 || core.Severity != "high" {
		t.Errorf("core = %+v", core)
	}
	theme := vulns[2]
	if theme.Kind != KindTheme || theme.Slug != "some-theme" || !theme.Unfixed || len(theme.CVE) != 0 {
		t.Errorf("theme = %+v", theme)
	}
}

func TestParseWordfenceRejectsGarbage(t *testing.T) {
	if _, err := ParseWordfence(strings.NewReader(`"unauthorized"`)); err == nil {
		t.Error("a string is not a feed")
	}
	if _, err := ParseWordfence(strings.NewReader(`{"a": {"id": "a", "software": [}`)); err == nil {
		t.Error("broken JSON should fail")
	}
}

// CVE records trimmed from the CVE List; each CNA writes them differently.
var cveRecords = map[string]string{
	// Wordfence: semver ranges, slug only in Trac references.
	"wordfence": `{"cveMetadata": {"cveId": "CVE-2023-6553", "state": "PUBLISHED", "datePublished": "2023-12-15T09:00:00Z"},
	 "containers": {"cna": {"title": "Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution",
	  "descriptions": [{"lang": "en", "value": "The Backup Migration plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.3.7."}],
	  "affected": [{"vendor": "inisev", "product": "BackupBliss", "versions": [{"version": "0", "status": "affected", "lessThanOrEqual": "1.3.7", "versionType": "semver"}], "defaultStatus": "unaffected"}],
	  "references": [{"url": "https://www.wordfence.com/threat-intel/vulnerabilities/id/3511ba64?source=cve"}, {"url": "https://plugins.trac.wordpress.org/browser/backup-backup/tags/1.3.7/includes/backup-heart.php#L38"}, {"url": "https://plugins.trac.wordpress.org/browser/backup-backup/tags/1.3.7/includes/backup-heart.php#L62"}],
	  "metrics": [{"cvssV3_1": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
	  "problemTypes": [{"descriptions": [{"lang": "en", "description": "CWE-94 Improper Control of Generation of Code ('Code Injection')", "cweId": "CWE-94", "type": "CWE"}]}]}}}`,
	// Patchstack: package name and collection URL.
	"patchstack": `{"cveMetadata": {"cveId": "CVE-2024-54386", "state": "PUBLISHED"},
	 "containers": {"cna": {"title": "WordPress Push Monkey Pro plugin <= 3.9 - CSRF to Stored XSS vulnerability",
	  "affected": [{"collectionURL": "https://wordpress.org/plugins", "defaultStatus": "unaffected", "packageName": "push-monkey-desktop-push-notifications", "product": "Push Monkey Pro", "vendor": "pushmonkey", "versions": [{"lessThanOrEqual": "3.9", "status": "affected", "version": "n/a", "versionType": "custom"}]}],
	  "references": [{"url": "https://patchstack.com/database/Wordpress/Plugin/push-monkey-desktop-push-notifications/vulnerability/x"}]}}}`,
	// WPScan: the upper bound repeated in "version", no slug anywhere.
	"wpscan": `{"cveMetadata": {"cveId": "CVE-2021-24145", "state": "PUBLISHED"},
	 "containers": {"cna": {"title": "Modern Events Calendar Lite < 5.16.5 - Authenticated Arbitrary File Upload leading to RCE",
	  "descriptions": [{"lang": "en", "value": "Arbitrary file upload in the Modern Events Calendar Lite WordPress plugin, versions before 5.16.5, did not properly check the imported file."}],
	  "affected": [{"product": "Modern Events Calendar Lite", "vendor": "Unknown", "versions": [{"lessThan": "5.16.5", "status": "affected", "version": "5.16.5", "versionType": "custom"}]}],
	  "references": [{"url": "https://wpscan.com/vulnerability/f42cc26b"}]}}}`,
	// GitHub (WordPress core): range expression in "version".
	"github": `{"cveMetadata": {"cveId": "CVE-2022-21661", "state": "PUBLISHED", "datePublished": "2022-01-06T00:00:00Z"},
	 "containers": {"cna": {"title": "SQL injection in WordPress",
	  "affected": [{"product": "wordpress-develop", "vendor": "WordPress", "versions": [{"status": "affected", "version": "< 5.8.3"}]}],
	  "references": [{"url": "https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release/"}]}}}`,
	// MITRE (old): no version data, slug in the description.
	"mitre": `{"cveMetadata": {"cveId": "CVE-2020-35489", "state": "PUBLISHED"},
	 "containers": {"cna": {"descriptions": [{"lang": "en", "value": "The contact-form-7 (aka Contact Form 7) plugin before 5.3.2 for WordPress allows Unrestricted File Upload and remote code execution because a filename may contain special characters."}],
	  "affected": [{"product": "n/a", "vendor": "n/a", "versions": [{"status": "affected", "version": "n/a"}]}],
	  "references": [{"url": "https://wordpress.org/plugins/contact-form-7/#developers"}]},
	  "adp": [{"references": [{"url": "https://wpscan.com/vulnerability/10508"}]}]}}`,
	// HackerOne: junk in "version", bound only in the description.
	"hackerone": `{"cveMetadata": {"cveId": "CVE-2023-28121", "state": "PUBLISHED"},
	 "containers": {"cna": {"descriptions": [{"lang": "en", "value": "An issue in WooCommerce Payments plugin for WordPress (versions 5.6.1 and lower) allows an unauthenticated attacker to send requests on behalf of an elevated user."}],
	  "affected": [{"vendor": "n/a", "product": "WooCommerce Payments WordPress Plugin", "versions": [{"version": "Fixed version 5.6.2", "status": "affected"}]}]}}}`,
	"rejected": `{"cveMetadata": {"cveId": "CVE-2024-0001", "state": "REJECTED"}, "containers": {"cna": {}}}`,
	"other":    `{"cveMetadata": {"cveId": "CVE-2024-0002", "state": "PUBLISHED"}, "containers": {"cna": {"descriptions": [{"lang": "en", "value": "A bug in nginx before 1.2."}], "affected": [{"product": "nginx", "vendor": "F5", "versions": [{"version": "0", "lessThan": "1.2", "status": "affected"}]}]}}}`,
}

func TestParseCVERecord(t *testing.T) {
	tests := []struct {
		name, kind, slug string
		in, out          []string
		fixed            []string
	}{
		{"wordfence", KindPlugin, "backup-backup", []string{"1.3.7", "1.0"}, []string{"1.3.8"}, nil},
		{"patchstack", KindPlugin, "push-monkey-desktop-push-notifications", []string{"3.9"}, []string{"3.10"}, nil},
		{"wpscan", KindPlugin, "modern-events-calendar-lite", []string{"5.16.4", "1.0"}, []string{"5.16.5"}, []string{"5.16.5"}},
		{"github", KindCore, CoreSlug, []string{"5.8.2"}, []string{"5.8.3"}, []string{"5.8.3"}},
		{"mitre", KindPlugin, "contact-form-7", []string{"5.3.1"}, []string{"5.3.2"}, []string{"5.3.2"}},
		{"hackerone", KindPlugin, "woocommerce-payments", []string{"5.6.1"}, []string{"5.6.2"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := ParseCVERecord([]byte(cveRecords[tt.name]))
			if len(vulns) != 1 {
				t.Fatalf("got %d vulns: %+v", len(vulns), vulns)
			}
			v := vulns[0]
			if v.Kind != tt.kind || v.Slug != tt.slug {
				t.Errorf("kind/slug = %s/%s, want %s/%s", v.Kind, v.Slug, tt.kind, tt.slug)
			}
			for _, ver := range tt.in {
				if !AnyContains(v.Affected, ver) {
					t.Errorf("%s should be affected: %+v", ver, v.Affected)
				}
			}
			for _, ver := range tt.out {
				if AnyContains(v.Affected, ver) {
					t.Errorf("%s should not be affected: %+v", ver, v.Affected)
				}
			}
			if !slices.Equal(v.Fixed, tt.fixed) {
				t.Errorf("fixed = %v, want %v", v.Fixed, tt.fixed)
			}
			if v.Title == "" || v.CVE[0] != v.ID {
				t.Errorf("title %q, cve %v", v.Title, v.CVE)
			}
		})
	}
	wf := ParseCVERecord([]byte(cveRecords["wordfence"]))[0]
	if wf.CVSS != 9.8 || wf.Severity != "critical" || !strings.HasPrefix(wf.CWE, "CWE-94 Improper Control") || wf.Published != "2023-12-15" {
		t.Errorf("metadata = %+v", wf)
	}
	for name, want := range map[string]bool{"wpscan": true, "hackerone": true, "wordfence": false, "patchstack": false, "mitre": false} {
		if v := ParseCVERecord([]byte(cveRecords[name]))[0]; v.Guessed != want {
			t.Errorf("%s: guessed = %v", name, v.Guessed)
		}
	}
	guessed := New(&SourceFile{Source: SourceCVE, Vulnerabilities: ParseCVERecord([]byte(cveRecords["wpscan"]))})
	if s := guessed.Slugs(KindPlugin); len(s) != 0 || len(guessed.Advisories(KindPlugin, "modern-events-calendar-lite")) != 1 {
		t.Errorf("a guessed slug is matched but not brute-forced: slugs %v", s)
	}
	for _, name := range []string{"rejected", "other"} {
		if v := ParseCVERecord([]byte(cveRecords[name])); len(v) != 0 {
			t.Errorf("%s: got %+v", name, v)
		}
	}
}

func TestParseCVEZipReadsNestedArchives(t *testing.T) {
	dir := t.TempDir()
	inner := zipBytes(t, map[string]string{
		"cves/2023/6xxx/CVE-2023-6553.json":   cveRecords["wordfence"],
		"cves/2024/0xxx/CVE-2024-0002.json":   cveRecords["other"],
		"cves/2022/21xxx/CVE-2022-21661.json": cveRecords["github"],
		"cves/delta.json":                     `{}`,
	})
	outer := zipBytes(t, map[string]string{"cves.zip": string(inner)})
	p := filepath.Join(dir, "all.zip.zip")
	if err := os.WriteFile(p, outer, 0o644); err != nil {
		t.Fatal(err)
	}
	vulns, err := ParseCVEZip(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"CVE-2022-21661", "CVE-2023-6553"}) {
		t.Errorf("ids = %v", ids)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".cmsrecon-cve-*")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testDB(t *testing.T) *DB {
	wf, err := ParseWordfence(strings.NewReader(wordfenceFeed))
	if err != nil {
		t.Fatal(err)
	}
	var cve []*Vuln
	for _, name := range []string{"mitre", "github", "wordfence"} {
		cve = append(cve, ParseCVERecord([]byte(cveRecords[name]))...)
	}
	// Given in the "wrong" order: Wordfence must still be the primary source.
	return New(
		&SourceFile{Source: SourceCVE, UpdatedAt: time.Now(), Vulnerabilities: cve},
		&SourceFile{Source: SourceWordfence, UpdatedAt: time.Now(), Vulnerabilities: wf},
	)
}

func TestMergeAndMatch(t *testing.T) {
	db := testDB(t)
	if got := db.Slugs(KindPlugin); !slices.Equal(got, []string{"backup-backup", "contact-form-7"}) {
		t.Errorf("vulnerable plugins = %v", got)
	}
	advs := db.Advisories(KindPlugin, "contact-form-7")
	if len(advs) != 1 || len(advs[0].Sources) != 2 || advs[0].Sources[0].Source != SourceWordfence || advs[0].Sources[1].Source != SourceCVE {
		t.Fatalf("contact-form-7 advisories = %+v", advs)
	}

	tests := []struct {
		name    string
		d       Detected
		verdict string
		fixedIn string
	}{
		{"confirmed", Detected{Version: "5.3.1", Confidence: 80}, VerdictConfirmed, "5.3.2"},
		{"low confidence", Detected{Version: "5.3.1", Confidence: 50}, VerdictLikely, "5.3.2"},
		{"other candidate not affected", Detected{Version: "5.3.1", Confidence: 90, Alternatives: []string{"5.4"}}, VerdictLikely, "5.3.2"},
		{"unknown version", Detected{}, VerdictPossible, "5.3.2"},
		{"not affected", Detected{Version: "5.3.2", Confidence: 100}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := db.Match(KindPlugin, "contact-form-7", tt.d)
			if tt.verdict == "" {
				if len(ms) != 0 {
					t.Errorf("matches = %v", ms)
				}
				return
			}
			if len(ms) != 1 || ms[0].Verdict != tt.verdict || ms[0].FixedIn != tt.fixedIn {
				t.Fatalf("matches = %v (fixed in %q)", ms, ms[0].FixedIn)
			}
		})
	}

	// Core: Wordfence lists two branches; the CVE List says < 5.8.3 for
	// everything, so 5.6 is a disagreement.
	ms := db.Match(KindCore, CoreSlug, Detected{Version: "5.8.1", Confidence: 90})
	if len(ms) != 1 || ms[0].Verdict != VerdictConfirmed || ms[0].FixedIn != "5.8.3" {
		t.Errorf("core 5.8.1 = %v", ms)
	}
	ms = db.Match(KindCore, CoreSlug, Detected{Version: "5.7.4", Confidence: 90})
	if len(ms) != 1 || ms[0].FixedIn != "5.7.5" {
		t.Errorf("core 5.7.4 = %v (fixed in %q)", ms, ms[0].FixedIn)
	}
	ms = db.Match(KindCore, CoreSlug, Detected{Version: "5.6", Confidence: 90})
	if len(ms) != 1 || ms[0].Verdict != VerdictPossible || !strings.Contains(ms[0].Note, "disagree") {
		t.Errorf("core 5.6 = %v, note %q", ms, ms[0].Note)
	}

	// A CVE only in the CVE List is its own advisory.
	if advs := db.Advisories(KindPlugin, "backup-backup"); len(advs) != 1 || advs[0].Sources[0].Source != SourceCVE {
		t.Errorf("backup-backup = %+v", advs)
	}
}

func TestSourceFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	wf, _ := ParseWordfence(strings.NewReader(wordfenceFeed))
	sf := &SourceFile{Source: SourceWordfence, UpdatedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Vulnerabilities: wf}
	if err := WriteSource(filepath.Join(dir, WordfenceFile), sf); err != nil {
		t.Fatal(err)
	}
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if db.Empty() || len(db.Sources) != 1 || db.Sources[0].Entries != 3 || !db.OldestUpdate().Equal(sf.UpdatedAt) {
		t.Errorf("sources = %+v", db.Sources)
	}
	if len(db.Advisories(KindTheme, "some-theme")) != 1 {
		t.Error("theme advisory missing after the round trip")
	}

	empty, err := Open(t.TempDir())
	if err != nil || !empty.Empty() {
		t.Errorf("empty dir: %v, %+v", err, empty.Sources)
	}
	os.WriteFile(filepath.Join(dir, CVEFile), []byte("not gzip"), 0o644)
	if db, err := Open(dir); err == nil || db.Empty() {
		t.Errorf("a broken file should be reported and the others still loaded: %v", err)
	}
}

const retireRepo = `{
 "retire-example": {"extractors": {}, "vulnerabilities": []},
 "jquery": {
  "extractors": {
   "uri": ["/(§§version§§)/jquery(\\.min)?\\.js"],
   "filename": ["jquery-(§§version§§)(\\.min)?\\.js"],
   "filecontent": ["/\\*!? jQuery v(§§version§§)", "=\"(§§version§§)\",.{50,300}(.)\\.fn=(\\2)\\.prototype=\\{jquery:"]
  },
  "vulnerabilities": [
   {"below": "1.9.0b1", "severity": "medium", "identifiers": {"summary": "Selector interpreted as HTML", "CVE": ["CVE-2012-6708"]}, "info": ["https://bugs.jquery.com/ticket/11290"]},
   {"atOrAbove": "1.2", "below": "3.5.0", "severity": "medium", "identifiers": {"summary": "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS", "CVE": ["CVE-2020-11022"], "githubID": "GHSA-gxr4-xjj5-5px2"}, "info": []}
  ]
 },
 "vue": {"extractors": {"filecontent": ["'(§§version§§)'[^\\n]{0,8000}Vue compiler"]}, "vulnerabilities": []}
}`

func TestJSRepo(t *testing.T) {
	r, err := ParseJSRepo([]byte(retireRepo))
	if err != nil {
		t.Fatal(err)
	}
	detect := func(raw string) []JSDetection {
		u, _ := url.Parse(raw)
		return r.FromURL(u)
	}
	tests := []struct {
		url, lib, version, method string
	}{
		{"https://code.jquery.com/jquery-1.12.4.min.js", "jquery", "1.12.4", JSMethodURL},
		{"https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js", "jquery", "3.4.1", JSMethodURL},
		{"https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.6.0", "jquery", "3.6.0", JSMethodVer},
		{"https://example.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2", "jquery-migrate", "3.3.2", JSMethodVer},
		{"https://example.com/wp-includes/js/jquery/ui/core.min.js?ver=1.13.1", "jquery-ui", "1.13.1", JSMethodVer},
		{"https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.bundle.min.js", "bootstrap", "4.3.1", JSMethodURL},
		{"https://example.com/wp-content/themes/x/js/jquery.min.js", "jquery", "", JSMethodName},
		{"https://example.com/wp-includes/js/tinymce/tinymce.min.js?ver=49110-20201110", "tinyMCE", "", JSMethodName},
	}
	for _, tt := range tests {
		found := false
		for _, d := range detect(tt.url) {
			if d.Library == tt.lib {
				found = true
				if d.Version != tt.version || d.Method != tt.method {
					t.Errorf("%s: %+v, want %s %s", tt.url, d, tt.version, tt.method)
				}
			}
		}
		if !found {
			t.Errorf("%s: %s not detected in %+v", tt.url, tt.lib, detect(tt.url))
		}
	}
	if d := detect("https://example.com/wp-content/plugins/x/app.js?ver=1.0"); len(d) != 0 {
		t.Errorf("app.js detected as %+v", d)
	}

	content := r.FromContent([]byte("/*! jQuery v1.8.3 jquery.com | jquery.org/license */\n(function(e,t){...})"))
	if len(content) != 1 || content[0].Library != "jquery" || content[0].Version != "1.8.3" {
		t.Errorf("content = %+v", content)
	}
	// The pattern with a repeat count above Go's limit still works.
	vue := r.FromContent([]byte(`x='2.6.10'` + strings.Repeat("a", 1500) + `Vue compiler`))
	if len(vue) != 1 || vue[0].Version != "2.6.10" {
		t.Errorf("vue = %+v", vue)
	}

	ms := MatchAdvisories(r.Advisories("jquery"), Detected{Version: "1.8.3", Confidence: 100})
	if len(ms) != 2 || ms[0].Verdict != VerdictConfirmed {
		t.Errorf("jquery 1.8.3 = %v", ms)
	}
	if ms := MatchAdvisories(r.Advisories("jquery"), Detected{Version: "3.6.0", Confidence: 100}); len(ms) != 0 {
		t.Errorf("jquery 3.6.0 = %v", ms)
	}
	if ms := MatchAdvisories(r.Advisories("jquery"), Detected{Version: "1.1", Confidence: 100}); len(ms) != 1 {
		t.Errorf("jquery 1.1 is below atOrAbove of the second vulnerability: %v", ms)
	}
	if !slices.Contains(r.Libraries(), "slick") || slices.Contains(r.Libraries(), "retire-example") {
		t.Errorf("libraries = %v", r.Libraries())
	}
}
