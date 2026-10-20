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
			Redirects: []scan.Redirect{{From: "http://example.com/", To: "https://example.com/", Status: 301, Followed: true}},
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
		Notices: []string{"Not implemented yet, skipped: users (u1-10)."},
		Errors:  []scan.RequestError{{URL: "https://example.com/feed/", Error: "timeout"}},
		Stats:   scan.Stats{Requests: 42, BytesSent: 9000, BytesReceived: 1500000, ElapsedSeconds: 4.2},
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
		{"top level", doc, []string{"detection_mode", "errors", "finished_at", "interesting_findings", "main_theme", "notices",
			"schema_version", "started_at", "stats", "status", "stop", "target", "tool", "version", "web_server", "wordpress"}},
		{"tool", obj(doc["tool"]), []string{"name", "user_agent", "version"}},
		{"target", obj(doc["target"]), []string{"effective_url", "redirects", "scope", "url"}},
		{"redirect", first(obj(doc["target"])["redirects"]), []string{"followed", "from", "status", "to"}},
		{"web_server", obj(doc["web_server"]), []string{"family", "header"}},
		{"wordpress", obj(doc["wordpress"]), []string{"content_url", "detected", "evidence"}},
		{"evidence", first(obj(doc["wordpress"])["evidence"]), []string{"confidence", "method", "mode", "url", "value"}},
		{"finding", first(doc["interesting_findings"]), []string{"confidence", "data", "entries", "evidence", "id", "references", "severity", "title", "url"}},
		{"xmlrpc data", obj(first(doc["interesting_findings"])["data"]), []string{"methods", "pingback_ping", "system_multicall"}},
		{"version", obj(doc["version"]), []string{"candidates", "confidence", "evidence", "number"}},
		{"candidate", first(obj(doc["version"])["candidates"]), []string{"confidence", "number"}},
		{"main_theme", obj(doc["main_theme"]), []string{"confidence", "evidence", "location", "name", "parent", "slug", "style_url", "version"}},
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
		"Effective URL: https://example.com/", "Redirect: http://example.com/ -> https://example.com/ (HTTP 301, followed)",
		"Interesting findings (2)", "XML-RPC is enabled", "HIGH", "Debug log exposed", "6.4.2 (confidence 60%)",
		"child (confidence 70%)", "Parent theme: parent", "Not implemented yet", "1 request failed",
		"Finished in 4.2s: 42 requests, 8.8 KB sent, 1.4 MB received",
	} {
		if !strings.Contains(plain.String(), want) {
			t.Errorf("CLI report missing %q:\n%s", want, &plain)
		}
	}
	if strings.Contains(plain.String(), "Found by") || strings.Contains(plain.String(), "\x1b[") {
		t.Errorf("default report must have no evidence and no colours:\n%s", &plain)
	}
	for _, want := range []string{"Found by:", "system.listMethods (aggressive, 100%)", "Reference: https://codex", "https://example.com/feed/: timeout"} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose report missing %q:\n%s", want, &verbose)
		}
	}
	if !strings.Contains(colored.String(), "\x1b[") {
		t.Error("coloured report has no ANSI sequences")
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
