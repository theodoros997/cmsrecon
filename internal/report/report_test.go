package report

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/theodoros997/cmsrecon/internal/scan"
)

func sampleResult() *scan.Result {
	ev := []scan.Evidence{{Method: "Meta generator", Mode: "passive", URL: "https://example.com/", Value: "6.4.2", Confidence: 60}}
	return &scan.Result{
		SchemaVersion: scan.SchemaVersion,
		Tool:          scan.Tool{Name: "cmsrecon", Version: "dev", UserAgent: "cmsrecon/dev"},
		Target: scan.Target{
			URL: "http://example.com/", EffectiveURL: "https://example.com/",
			Redirects: []scan.Redirect{{From: "http://example.com/", To: "https://example.com/", Status: 301, Followed: true, Reason: scan.RedirectInScope}},
			Scope:     []string{"example.com"},
		},
		DetectionMode: "mixed",
		StartedAt:     time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 10, 20, 10, 0, 5, 0, time.UTC),
		Status:        scan.StatusCompleted,
		WebServer:     &scan.WebServer{Header: "nginx", Family: "nginx"},
		WordPress:     &scan.WordPress{Detected: true, ContentURL: "https://example.com/wp-content/", Evidence: ev},
		InterestingFindings: []scan.Finding{{
			ID: "xmlrpc", Title: "XML-RPC is enabled", Severity: scan.SeverityLow, URL: "https://example.com/xmlrpc.php",
			Confidence: 100, Entries: []string{"pingback.ping is exposed"}, References: []string{"https://codex.wordpress.org/XML-RPC_Pingback_API"},
			Data:     map[string]any{"methods": 80, "pingback_ping": true, "system_multicall": true},
			Evidence: []scan.Evidence{{Method: "system.listMethods", Mode: "aggressive", URL: "https://example.com/xmlrpc.php", Confidence: 100}},
		}, {
			ID: "debug-log", Title: "Debug log exposed", Severity: scan.SeverityHigh, URL: "https://example.com/wp-content/debug.log",
			Confidence: 100, Entries: []string{}, References: []string{}, Evidence: ev,
		}},
		Version: &scan.Version{Number: "6.4.2", Confidence: 60, Candidates: []scan.Candidate{{Number: "6.4.2", Confidence: 60}}, Evidence: ev},
		MainTheme: &scan.Theme{
			Slug: "child", Location: "https://example.com/wp-content/themes/child/", StyleURL: "https://example.com/wp-content/themes/child/style.css",
			Confidence: 70, Name: "Child", Version: &scan.Version{Number: "1.0", Confidence: 80, Candidates: []scan.Candidate{}, Evidence: []scan.Evidence{}},
			Evidence: ev,
			Parent: &scan.Theme{Slug: "parent", Location: "https://example.com/wp-content/themes/parent/", Confidence: 100,
				Version: &scan.Version{Candidates: []scan.Candidate{}, Evidence: []scan.Evidence{}}, Evidence: []scan.Evidence{}},
		},
		Themes: []*scan.Theme{{
			Slug: "twentytwenty", Location: "https://example.com/wp-content/themes/twentytwenty/", StyleURL: "https://example.com/wp-content/themes/twentytwenty/style.css",
			Confidence: 80, Version: &scan.Version{Latest: "2.8", Candidates: []scan.Candidate{}, Evidence: []scan.Evidence{}}, Evidence: ev,
			Possible: &scan.PossibleVulns{Count: 3, Critical: 1, FixedIn: "2.5"},
		}},
		Plugins: []*scan.Plugin{{
			Slug: "contact-form-7", Name: "Contact Form 7", Location: "https://example.com/wp-content/plugins/contact-form-7/",
			ReadmeURL: "https://example.com/wp-content/plugins/contact-form-7/readme.txt", Confidence: 100,
			Version: &scan.Version{Number: "5.3.1", Confidence: 92, Latest: "6.1", Outdated: true,
				Candidates: []scan.Candidate{{Number: "5.3.1", Confidence: 92}},
				Evidence:   []scan.Evidence{{Method: "readme.txt Stable tag", Mode: "aggressive", URL: "https://example.com/wp-content/plugins/contact-form-7/readme.txt", Value: "5.3.1", Confidence: 80}}},
			Evidence: []scan.Evidence{{Method: "readme.txt", Mode: "aggressive", URL: "https://example.com/wp-content/plugins/contact-form-7/readme.txt", Confidence: 100}},
			Vulnerabilities: []scan.Vulnerability{{
				Title: "Contact Form 7 <= 5.3.1 - Unrestricted File Upload", Verdict: scan.VerdictConfirmed, Severity: scan.SeverityCritical,
				CVSS: 9.8, CVE: []string{"CVE-2020-35489"}, CWE: "CWE-434", Affected: []string{"<= 5.3.1"}, FixedIn: "5.3.2",
				Published: "2020-12-17", Sources: []string{"wordfence", "cve"},
				References: []string{"https://www.wordfence.com/threat-intel/vulnerabilities/id/a1", "https://contactform7.com/"},
				Exploits: []scan.Exploit{
					{Source: "metasploit", URL: "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/wp_cf7_upload.rb", Title: "CF7 upload", Ref: "exploit/multi/http/wp_cf7_upload"},
					{Source: "exploitdb", URL: "https://www.exploit-db.com/exploits/49294", Title: "Contact Form 7 5.3.1 - Unrestricted File Upload", Verified: true},
					{Source: "github", URL: "https://github.com/someone/CVE-2020-35489", Title: "someone/CVE-2020-35489"},
					{Source: "github", URL: "https://github.com/other/cf7-poc", Title: "other/cf7-poc"},
				},
			}},
			Possible:    &scan.PossibleVulns{Count: 1, FixedIn: "5.0"},
			LastUpdated: "2026-09-30",
			Exploits:    []scan.Exploit{{Source: "exploitdb", URL: "https://www.exploit-db.com/exploits/50000", Title: "WordPress Plugin Contact Form 7 5.3 - Something"}},
			Warnings:    []string{"Directory listing is enabled: https://example.com/wp-content/plugins/contact-form-7/ (12 entries)"},
		}},
		JSLibraries: []*scan.JSLibrary{{
			Name: "jquery", URLs: []string{"https://example.com/wp-includes/js/jquery/jquery.min.js?ver=1.12.4"},
			Version: &scan.Version{Number: "1.12.4", Confidence: 80, Candidates: []scan.Candidate{{Number: "1.12.4", Confidence: 80}}, Evidence: []scan.Evidence{}},
			Vulnerabilities: []scan.Vulnerability{{Title: "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS", Verdict: scan.VerdictConfirmed,
				Severity: scan.SeverityMedium, CVE: []string{"CVE-2020-11022"}, Affected: []string{">= 1.2, < 3.5.0"}, FixedIn: "3.5.0", Sources: []string{"retirejs"}}},
		}},
		Users: []*scan.User{
			{ID: 1, Username: "admin", DisplayName: "Site Admin", Confidence: 100, Evidence: ev},
			{DisplayName: "Guest Writer", Confidence: 60, Evidence: ev},
		},
		Timthumbs: []*scan.Timthumb{{
			URL:      "https://example.com/wp-content/themes/old/timthumb.php",
			Version:  &scan.Version{Number: "1.33", Confidence: 100, Candidates: []scan.Candidate{{Number: "1.33", Confidence: 100}}, Evidence: ev},
			Evidence: ev,
			Vulnerabilities: []scan.Vulnerability{{Title: "TimThumb < 2.0 - Remote Code Execution", Verdict: scan.VerdictConfirmed, Severity: scan.SeverityCritical,
				CVE: []string{"CVE-2011-4106"}, Affected: []string{"< 2.0"}, FixedIn: "2.0", Sources: []string{"cmsrecon"}, References: []string{}}},
		}},
		Media: []*scan.Media{
			{ID: 4, URL: "https://example.com/wp-content/uploads/2026/10/photo.jpg", MimeType: "image/jpeg", Evidence: ev},
			{ID: 9, URL: "https://example.com/wp-content/uploads/2026/10/salaries.xlsx", MimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Evidence: ev},
		},
		VulnerabilityData: &scan.DataInfo{Directory: "/data", Sources: []scan.DataSource{
			{Name: "wordfence", UpdatedAt: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), Entries: 30000},
		}},
		VulnerabilityCounts: scan.VulnCounts{Confirmed: 2, Possible: 4},
		CoreVulnerabilities: []scan.Vulnerability{},
		Notices:             []string{"The vulnerability data is 9 days old: run \"cmsrecon update\" to refresh it."},
		Errors:              []scan.RequestError{{URL: "https://example.com/feed/", Error: "timeout"}},
		Stats:               scan.Stats{Requests: 42, BytesSent: 9000, BytesReceived: 1500000, ElapsedSeconds: 4.2},
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestJSONShape pins the field names documented in docs/json-report.md.
func TestJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	obj := func(v any) map[string]any { return v.(map[string]any) }
	first := func(v any) map[string]any { return v.([]any)[0].(map[string]any) }

	tests := []struct {
		name string
		got  map[string]any
		want []string
	}{
		{"top level", doc, []string{"core_vulnerabilities", "detection_mode", "errors", "finished_at", "interesting_findings", "js_libraries",
			"main_theme", "media", "notices", "plugins", "schema_version", "started_at", "stats", "status", "stop", "target", "themes", "timthumbs", "tool",
			"users", "version", "vulnerability_counts", "vulnerability_data", "web_server", "wordpress"}},
		{"timthumb", first(doc["timthumbs"]), []string{"evidence", "url", "version", "vulnerabilities"}},
		{"media", first(doc["media"]), []string{"evidence", "id", "mime_type", "url"}},
		{"tool", obj(doc["tool"]), []string{"name", "user_agent", "version"}},
		{"target", obj(doc["target"]), []string{"effective_url", "redirects", "scope", "url"}},
		{"redirect", first(obj(doc["target"])["redirects"]), []string{"followed", "from", "reason", "status", "to"}},
		{"web_server", obj(doc["web_server"]), []string{"family", "header"}},
		{"wordpress", obj(doc["wordpress"]), []string{"content_url", "detected", "evidence"}},
		{"evidence", first(obj(doc["wordpress"])["evidence"]), []string{"confidence", "method", "mode", "url", "value"}},
		{"finding", first(doc["interesting_findings"]), []string{"confidence", "data", "entries", "evidence", "id", "references", "severity", "title", "url"}},
		{"xmlrpc data", obj(first(doc["interesting_findings"])["data"]), []string{"methods", "pingback_ping", "system_multicall"}},
		{"version", obj(doc["version"]), []string{"candidates", "confidence", "evidence", "number"}},
		{"candidate", first(obj(doc["version"])["candidates"]), []string{"confidence", "number"}},
		{"main_theme", obj(doc["main_theme"]), []string{"confidence", "evidence", "location", "name", "parent", "slug", "style_url", "version", "vulnerabilities", "warnings"}},
		{"plugin", first(doc["plugins"]), []string{"confidence", "evidence", "exploits", "last_updated", "location", "name", "possible_vulnerabilities", "readme_url", "slug", "version", "vulnerabilities", "warnings"}},
		{"possible_vulnerabilities", obj(first(doc["plugins"])["possible_vulnerabilities"]), []string{"count", "critical", "fixed_in", "high", "listed", "with_exploits"}},
		{"plugin version", obj(first(doc["plugins"])["version"]), []string{"candidates", "confidence", "evidence", "latest", "number", "outdated"}},
		{"vulnerability", first(first(doc["plugins"])["vulnerabilities"]), []string{"affected_versions", "cve", "cvss", "cwe", "exploits", "fixed_in",
			"published", "references", "severity", "sources", "title", "verdict"}},
		{"exploit", first(first(first(doc["plugins"])["vulnerabilities"])["exploits"]), []string{"ref", "source", "title", "url"}},
		{"js library", first(doc["js_libraries"]), []string{"name", "urls", "version", "vulnerabilities"}},
		{"user", first(doc["users"]), []string{"confidence", "display_name", "evidence", "id", "username"}},
		{"vulnerability_data", obj(doc["vulnerability_data"]), []string{"directory", "sources"}},
		{"data source", first(obj(doc["vulnerability_data"])["sources"]), []string{"entries", "name", "updated_at"}},
		{"vulnerability_counts", obj(doc["vulnerability_counts"]), []string{"confirmed", "likely", "possible"}},
		{"error", first(doc["errors"]), []string{"error", "url"}},
		{"stats", obj(doc["stats"]), []string{"bytes_received", "bytes_sent", "elapsed_seconds", "requests"}},
	}
	for _, tt := range tests {
		if got := keys(tt.got); !slices.Equal(got, tt.want) {
			t.Errorf("%s keys = %v, want %v", tt.name, got, tt.want)
		}
	}
	if doc["stop"] != nil {
		t.Errorf("stop = %v, want null for a completed scan", doc["stop"])
	}
	if doc["started_at"] != "2026-10-20T10:00:00Z" {
		t.Errorf("started_at = %v", doc["started_at"])
	}
	// Empty lists are [] rather than null so consumers can iterate them.
	if f := obj(doc["interesting_findings"].([]any)[1]); f["entries"] == nil || f["references"] == nil {
		t.Errorf("empty lists must be [], got %v", f)
	}
	if _, ok := obj(doc["interesting_findings"].([]any)[1])["data"]; ok {
		t.Error("data is omitted when a finding has none")
	}
}

func TestCLIReport(t *testing.T) {
	var plain, verbose, colored bytes.Buffer
	r := sampleResult()
	if err := WriteCLI(&plain, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := WriteCLI(&verbose, r, Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if err := WriteCLI(&colored, r, Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Effective URL: https://example.com/", "Redirect: http://example.com/ -> https://example.com/ (HTTP 301, followed: in scope)",
		"Interesting findings (2)", "XML-RPC is enabled", "HIGH", "Debug log exposed", "6.4.2 (confidence 60%)",
		"child (confidence 70%)", "Parent theme: parent", "9 days old", "1 request failed",
		"Other themes (1)", "twentytwenty (confidence 80%)",
		"Plugins (1)", "[!] contact-form-7 (confidence 100%)", "Name: Contact Form 7",
		"Version: 5.3.1 (confidence 92%); outdated: the latest is 6.1",
		"Vulnerabilities: 1 confirmed", "[CRITICAL] Contact Form 7 <= 5.3.1 - Unrestricted File Upload",
		"confirmed - CVE-2020-35489 - CVSS 9.8 - fixed in 5.3.2", "https://www.wordfence.com/threat-intel/vulnerabilities/id/a1",
		"Possible vulnerabilities: 1, fixed in 5.0 (not listed: only a secondary source says 5.3.1 is affected; --possible lists it)",
		"Last updated: 2026-09-30 (on WordPress.org)", "[!] Directory listing is enabled: https://example.com/wp-content/plugins/contact-form-7/ (12 entries)",
		"Possible vulnerabilities: 3 (1 critical), all fixed in 2.5 (not listed: the version is unknown; --possible lists them)",
		"(the possible ones are counted, not listed: --possible lists them)",
		"Public exploits: 1 Metasploit module, 1 Exploit-DB entry (1 verified), 2 GitHub repositories (unreviewed)",
		"Metasploit: exploit/multi/http/wp_cf7_upload - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/wp_cf7_upload.rb",
		"Exploit-DB, verified: Contact Form 7 5.3.1 - Unrestricted File Upload - https://www.exploit-db.com/exploits/49294",
		"GitHub repository: https://github.com/someone/CVE-2020-35489", "1 more: -v lists them",
		"1 of the confirmed and likely ones has a public exploit or proof of concept",
		"Exploits that name this plugin but no CVE: 1 Exploit-DB entry (check that they apply to 5.3.1)",
		"Exploit-DB: WordPress Plugin Contact Form 7 5.3 - Something - https://www.exploit-db.com/exploits/50000",
		"Timthumbs (1)", "[!] https://example.com/wp-content/themes/old/timthumb.php", "Version: 1.33 (confidence 100%)", "[CRITICAL] TimThumb < 2.0 - Remote Code Execution",
		"Media (2): 1 document, 1 image", "[i] ID 9: https://example.com/wp-content/uploads/2026/10/salaries.xlsx",
		"JavaScript libraries (1)", "[!] jquery 1.12.4", "[MEDIUM] Regex in its jQuery.htmlPrefilter",
		"Users (2)", "admin (ID 1)", "Display name: Site Admin", `"Guest Writer" (display name only; not a username)`,
		"2 confirmed, 4 possible", "Data: Wordfence (2026-10-19)",
		"Finished in 4.2s: 42 requests, 8.8 KB sent, 1.4 MB received",
	} {
		if !strings.Contains(plain.String(), want) {
			t.Errorf("CLI report missing %q:\n%s", want, &plain)
		}
	}
	if strings.Contains(plain.String(), "Found by") || strings.Contains(plain.String(), "\x1b[") || strings.Contains(plain.String(), "Old XSS") {
		t.Errorf("default report must have no evidence, no colours and no possible vulnerabilities:\n%s", &plain)
	}
	for _, want := range []string{"Found by:", "system.listMethods (aggressive, 100%)", "Reference: https://codex", "https://example.com/feed/: timeout",
		"Affected: <= 5.3.1 (wordfence, cve)", "CWE-434", "https://contactform7.com/",
		"Readme: https://example.com/wp-content/plugins/contact-form-7/readme.txt", "readme.txt Stable tag (aggressive, 80%): 5.3.1"} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose report missing %q:\n%s", want, &verbose)
		}
	}
	if !strings.Contains(colored.String(), "\x1b[") {
		t.Error("coloured report has no ANSI sequences")
	}
	if !strings.Contains(verbose.String(), "https://github.com/other/cf7-poc") || strings.Contains(plain.String(), "https://github.com/other/cf7-poc") {
		t.Error("-v lists every exploit; the default report the first three")
	}
	if strings.Contains(verbose.String(), "Old XSS") {
		t.Error("-v must not list the possible vulnerabilities: --possible does")
	}

	// With --possible they are listed, and not summed up.
	r = sampleResult()
	pl := r.Plugins[0]
	pl.Vulnerabilities = append(pl.Vulnerabilities, scan.Vulnerability{
		Title: "Contact Form 7 < 5.0 - Old XSS", Verdict: scan.VerdictPossible, Severity: scan.SeverityMedium,
		Affected: []string{"< 5.0"}, Sources: []string{"cve"}, Note: "The sources disagree",
	})
	pl.Possible.Listed = true
	r.Themes[0].Possible.Listed = true
	var listed bytes.Buffer
	if err := WriteCLI(&listed, r, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Vulnerabilities: 1 confirmed, 1 possible", "Old XSS", "The sources disagree"} {
		if !strings.Contains(listed.String(), want) {
			t.Errorf("--possible report missing %q:\n%s", want, &listed)
		}
	}
	if strings.Contains(listed.String(), "--possible lists") {
		t.Errorf("--possible report must not point to --possible:\n%s", &listed)
	}
}

func TestCLIWordPressNotDetected(t *testing.T) {
	base := func() *scan.Result {
		return &scan.Result{
			Tool: scan.Tool{Name: "cmsrecon", Version: "dev"}, Target: scan.Target{URL: "http://example.com/", EffectiveURL: "http://example.com/"},
			DetectionMode: "mixed", WordPress: &scan.WordPress{Detected: false},
		}
	}
	stopped := base()
	stopped.Status = scan.StatusStopped
	stopped.Stop = &scan.Stop{Code: scan.StopNotWordPress, Message: "The site does not look like WordPress.", Hint: "Use --force to scan it anyway."}
	forced := base()
	forced.Status = scan.StatusCompleted

	var buf bytes.Buffer
	if err := WriteCLI(&buf, stopped, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "scanning anyway") {
		t.Errorf("a stopped scan must not claim it is scanning anyway:\n%s", &buf)
	}
	buf.Reset()
	if err := WriteCLI(&buf, forced, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "WordPress not detected; scanning anyway because of --force") {
		t.Errorf("a forced scan should say so:\n%s", &buf)
	}
}

func TestCLIStoppedReport(t *testing.T) {
	r := &scan.Result{
		Tool: scan.Tool{Name: "cmsrecon", Version: "dev"}, Target: scan.Target{URL: "http://example.com/", EffectiveURL: "http://example.com/"},
		DetectionMode: "mixed", Status: scan.StatusStopped,
		Stop: &scan.Stop{Code: scan.StopNotWordPress, Message: "The site does not look like WordPress.", Hint: "Use --force to scan it anyway."},
	}
	var buf bytes.Buffer
	if err := WriteCLI(&buf, r, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Scan stopped: The site does not look like WordPress.") || !strings.Contains(out, "--force") {
		t.Errorf("report:\n%s", out)
	}
	if strings.Contains(out, "Interesting findings") || strings.Contains(out, "Main theme") {
		t.Errorf("a stopped scan must not show empty sections:\n%s", out)
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 1536: "1.5 KB", 5 << 20: "5.0 MB"} {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %s, want %s", n, got, want)
		}
	}
}
