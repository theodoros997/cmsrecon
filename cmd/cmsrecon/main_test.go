package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/scan"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  []string // substrings expected in stdout
	}{
		{"no args", nil, exitUsage, nil},
		{"unknown command", []string{"bogus"}, exitUsage, nil},
		{"version", []string{"version"}, exitOK, []string{"cmsrecon "}},
		{"help", []string{"--help"}, exitOK, []string{"Usage:"}},
		{"scan help", []string{"scan", "-h"}, exitOK, []string{"--enumerate", "Exit codes:"}},
		{"wpscan style dry run", []string{"-u", "example.com", "--dry-run"}, exitOK,
			[]string{"http://example.com/", "Plugins:         found on the site\n", "up to 10 more pages", "author IDs 1-10", "Data:"}},
		{"positional url before flags", []string{"scan", "https://example.com/blog", "-e", "ap,u1-3", "--plugins-detection", "mixed", "--dry-run"}, exitOK,
			[]string{"https://example.com/blog/", "found on the site, then brute force of all plugins", "author IDs 1-3"}},
		{"bad plugins detection", []string{"-u", "example.com", "--plugins-detection", "loud", "--dry-run"}, exitUsage, nil},
		{"crawl out of range", []string{"-u", "example.com", "--crawl", "-1", "--dry-run"}, exitUsage, nil},
		{"rest inventory replaces enumeration", []string{"-u", "example.com", "--wp-auth", "admin:abcd efgh", "--dry-run"}, exitOK,
			[]string{"REST API inventory as admin"}},
		{"nothing to enumerate", []string{"-u", "example.com", "-e", "none", "--dry-run"}, exitOK, nil},
		{"conflicting enumeration", []string{"-u", "example.com", "-e", "vp,ap", "--dry-run"}, exitUsage, nil},
		{"missing url", []string{"scan", "--dry-run"}, exitUsage, nil},
		{"stealthy", []string{"-u", "example.com", "--stealthy", "--dry-run"}, exitOK,
			[]string{"Detection mode:  passive", "homepage and 404 page only"}},
		{"named plugins and folders", []string{"-u", "example.com", "--plugins-list", "akismet, contact-form-7", "--themes-list", "astra",
			"--wp-content-dir", "assets", "--wp-plugins-dir", "https://cdn.example.com/ext/", "--dry-run"}, exitOK,
			[]string{"found on the site, then check of the named plugins (2)", "check of the named themes (1)", "wp-content:      assets", "Plugins folder:  https://cdn.example.com/ext/"}},
		{"bad named plugin", []string{"-u", "example.com", "--plugins-list", "../etc", "--dry-run"}, exitUsage, nil},
		{"timthumbs, media and a time limit", []string{"-u", "example.com", "-e", "tt,m1-50", "--max-scan-duration", "600", "--dry-run"}, exitOK,
			[]string{"Timthumbs:       yes", "attachment IDs 1-50 when it is closed", "Max duration:    10m0s"}},
		{"bad time limit", []string{"-u", "example.com", "--max-scan-duration", "soon", "--dry-run"}, exitUsage, nil},
		{"negative time limit", []string{"-u", "example.com", "--max-scan-duration", "-5m", "--dry-run"}, exitUsage, nil},
		{"scan help lists exit code 5", []string{"scan", "-h"}, exitOK, []string{"5    The scan completed and found confirmed or likely vulnerabilities"}},
		{"update help", []string{"update", "-h"}, exitOK, []string{"cmsrecon update [options]", "retirejs"}},
		{"update unknown source", []string{"update", "--sources", "nvd"}, exitUsage, nil},
		{"additive enumeration", []string{"-u", "example.com", "-e", "+tt,+m1-5", "--dry-run"}, exitOK,
			[]string{"Timthumbs:       yes", "attachment IDs 1-5", "Config backups:  yes", "author IDs 1-10"}},
		{"dry run estimate and data", []string{"-u", "example.com", "--dry-run", "--data-dir", os.TempDir() + "/cmsrecon-none"}, exitOK,
			[]string{"Requests:        about ", "plus about 4 for each plugin and theme found", "at most 10 requests per second", "WordPress.org:", "(empty: run \"cmsrecon update\" or add --update)", "User-Agent:      cmsrecon/"}},
		{"dry run ap without brute force", []string{"-u", "example.com", "-e", "ap", "--dry-run"}, exitOK,
			[]string{"no brute force: -e ap only chooses the list to brute-force, which --plugins-detection passive does not do (use mixed)"}},
		{"dry run vhost", []string{"-u", "https://10.0.0.5/", "--vhost", "www.example.com", "--login-uri", "/door/", "--dry-run"}, exitOK,
			[]string{"Target:          https://www.example.com/", "Connect to:      10.0.0.5 for www.example.com", "Login page:      /door/"}},
		{"aggressive preset", []string{"-u", "example.com", "--aggressive", "--offline", "--dry-run", "--data-dir", os.TempDir() + "/cmsrecon-none"}, exitOK,
			[]string{"mixed, --aggressive: every check and the full lists", "then brute force of popular plugins", "then brute force of popular themes",
				"up to 25 more pages", "author IDs 1-25", "Timthumbs:       yes", "attachment IDs 1-100"}},
		{"aggressive keeps the options given", []string{"-u", "example.com", "--aggressive", "-e", "u1-3", "--crawl", "2", "--plugins-detection", "passive", "--dry-run"}, exitOK,
			[]string{"author IDs 1-3", "up to 2 more pages", "Plugins:         found on the site\n", "Config backups:  no"}},
		{"aggressive and stealthy", []string{"-u", "example.com", "--aggressive", "--stealthy", "--dry-run"}, exitUsage, nil},
		{"aggressive and passive", []string{"-u", "example.com", "--aggressive", "--detection-mode", "passive", "--dry-run"}, exitUsage, nil},
		{"rate and throttle", []string{"-u", "example.com", "--rate", "2.5", "--dry-run"}, exitOK, []string{"at most 2.5 requests per second"}},
		{"no rate limit", []string{"-u", "example.com", "--rate", "0", "--offline", "--dry-run"}, exitOK, []string{"Concurrency:     5 threads; slower by itself"}},
		{"negative rate", []string{"-u", "example.com", "--rate", "-1", "--dry-run"}, exitUsage, nil},
		{"report help", []string{"report", "-h"}, exitOK, []string{"cmsrecon report [options] REPORT.json"}},
		{"report without a file", []string{"report"}, exitUsage, nil},
		{"target that is an option", []string{"scan", "--", "-e"}, exitUsage, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, tt.wantCode, &stdout, &stderr)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, &stdout)
				}
			}
		})
	}
}

// fakeSite is a minimal WordPress homepage with a pingback header.
func fakeSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		base := "http://" + r.Host + "/"
		w.Header().Set("X-Pingback", base+"xmlrpc.php")
		fmt.Fprintf(w, `<html><head><meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="%swp-content/themes/twentytwentyfour/style.css" /></head><body></body></html>`, base)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestScanCLI(t *testing.T) {
	srv := fakeSite(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-u", srv.URL, "--detection-mode", "passive", "-v", "--data-dir", t.TempDir()}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d\nstdout:\n%s\nstderr:\n%s", code, &stdout, &stderr)
	}
	out := stdout.String()
	for _, want := range []string{"WordPress detected", "XML-RPC seems to be enabled", "6.4.2", "twentytwentyfour", "Found by:", "No vulnerability data", "Plugins (0)", "requests"} {
		if !strings.Contains(out, want) {
			t.Errorf("CLI report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colours must be off when stdout is not a terminal")
	}
	if stderr.Len() > 0 {
		t.Errorf("the CLI report on stdout carries the notices; stderr = %q", &stderr)
	}
}

func TestScanJSONToFile(t *testing.T) {
	srv := fakeSite(t)
	out := filepath.Join(t.TempDir(), "report.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", srv.URL, "-f", "json", "-o", out, "--detection-mode", "passive", "--data-dir", t.TempDir()}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d\nstderr:\n%s", code, &stderr)
	}
	if stdout.Len() > 0 {
		t.Errorf("stdout should be empty with -o, got %q", &stdout)
	}
	if !strings.Contains(stderr.String(), "notice: No vulnerability data") || !strings.Contains(stderr.String(), "Report written to") {
		t.Errorf("stderr = %q", &stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Status  string `json:"status"`
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
		Notices []string `json:"notices"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
	if report.Status != "completed" || report.Version.Number != "6.4.2" || len(report.Notices) == 0 {
		t.Errorf("report = %+v", report)
	}
}

func TestScanStoppedExitCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>not a CMS</html>")
	}))
	defer srv.Close()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-u", srv.URL, "-e", "none", "--data-dir", t.TempDir()}, &stdout, &stderr); code != exitStopped {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitStopped, &stdout)
	}
	if !strings.Contains(stdout.String(), "Scan stopped") || !strings.Contains(stdout.String(), "--force") {
		t.Errorf("stdout:\n%s", &stdout)
	}
}

func TestOutputFileError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	bad := filepath.Join(t.TempDir(), "missing-dir", "report.json")
	if code := run([]string{"-u", "example.com", "-o", bad}, &stdout, &stderr); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
}

func TestScanExit(t *testing.T) {
	tests := []struct {
		name string
		res  scan.Result
		want int
	}{
		{"clean", scan.Result{Status: scan.StatusCompleted}, exitOK},
		{"possible only", scan.Result{Status: scan.StatusCompleted, VulnerabilityCounts: scan.VulnCounts{Possible: 40}}, exitOK},
		{"likely", scan.Result{Status: scan.StatusCompleted, VulnerabilityCounts: scan.VulnCounts{Likely: 1}}, exitVulnerable},
		{"confirmed", scan.Result{Status: scan.StatusCompleted, VulnerabilityCounts: scan.VulnCounts{Confirmed: 2}}, exitVulnerable},
		{"stopped", scan.Result{Status: scan.StatusStopped}, exitStopped},
		{"timed out with vulnerabilities", scan.Result{Status: scan.StatusTimedOut, VulnerabilityCounts: scan.VulnCounts{Confirmed: 1}}, exitTimedOut},
		{"interrupted with vulnerabilities", scan.Result{Status: scan.StatusInterrupted, VulnerabilityCounts: scan.VulnCounts{Confirmed: 1}}, exitInterrupted},
	}
	for _, tt := range tests {
		if got := scanExit(&tt.res); got != tt.want {
			t.Errorf("%s: scanExit = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// TestMain keeps the developer's own config file out of the tests.
func TestMain(m *testing.M) {
	os.Setenv(cli.ConfigEnv, "none")
	os.Exit(m.Run())
}

func TestUnknownCommandHint(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"example.com", "-e", "vp"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), "cmsrecon scan example.com -e vp") {
		t.Errorf("stderr = %q", &stderr)
	}
}

func TestScanHTMLToFileWithLog(t *testing.T) {
	srv := fakeSite(t)
	dir := t.TempDir()
	out, log := filepath.Join(dir, "report.html"), filepath.Join(dir, "requests.tsv")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", srv.URL, "-o", out, "--log-requests", log, "--detection-mode", "passive", "--data-dir", t.TempDir()}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d\nstderr:\n%s", code, &stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "<!DOCTYPE html>") || !strings.Contains(string(data), "6.4.2") {
		t.Errorf("-o report.html should write HTML:\n%.300s", data)
	}
	for _, want := range []string{"Found: WordPress 6.4.2", "Vulnerabilities not checked", "Summary", "Report written to " + out, "Requests logged to " + log} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, &stderr)
		}
	}
	logged, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(logged), "\tGET\t200\t") {
		t.Errorf("request log = %q, %v", logged, err)
	}
}

func TestReportCommand(t *testing.T) {
	srv := fakeSite(t)
	dir := t.TempDir()
	saved := filepath.Join(dir, "scan.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", srv.URL, "-o", saved, "--detection-mode", "passive", "--data-dir", t.TempDir()}, &stdout, &stderr); code != exitOK {
		t.Fatalf("scan exit code = %d\n%s", code, &stderr)
	}

	md := filepath.Join(dir, "scan.md")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"report", saved, "-o", md}, &stdout, &stderr); code != exitOK {
		t.Fatalf("report exit code = %d\n%s", code, &stderr)
	}
	data, err := os.ReadFile(md)
	if err != nil || !strings.HasPrefix(string(data), "# WordPress scan report") || !strings.Contains(string(data), "6.4.2") {
		t.Errorf("Markdown report = %.300s, %v", data, err)
	}

	stdout.Reset()
	if code := run([]string{"report", saved}, &stdout, &stderr); code != exitOK {
		t.Fatalf("report to stdout exit code = %d\n%s", code, &stderr)
	}
	if !strings.Contains(stdout.String(), "WordPress detected") || !strings.Contains(stdout.String(), "Summary") {
		t.Errorf("CLI report:\n%s", &stdout)
	}

	notJSON := filepath.Join(dir, "notes.txt")
	os.WriteFile(notJSON, []byte("hello"), 0o600)
	if code := run([]string{"report", notJSON}, &stdout, &stderr); code != exitError {
		t.Errorf("a file that is not a report: exit code %d", code)
	}
}

func TestUpdateArgs(t *testing.T) {
	o, err := cli.ParseScan([]string{"example.com", "--data-dir", "/data", "--timeout", "20", "--proxy", "http://127.0.0.1:8080", "--update"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(updateArgs(o), " ")
	if got != "--data-dir /data --timeout 20s --proxy http://127.0.0.1:8080 --config none" {
		t.Errorf("updateArgs = %q", got)
	}
	u, err := cli.ParseUpdate(updateArgs(o), &bytes.Buffer{})
	if err != nil || u.DataDir != "/data" || u.Proxy.Host != "127.0.0.1:8080" {
		t.Errorf("the update command must accept them: %+v, %v", u, err)
	}
}

// TestPluginEvidenceIsVerifiable is a plugin seen only through a file the
// homepage loads, whose folder answers 404 and which has no readme: the
// report must give a URL that works and say where the version came from.
func TestPluginEvidenceIsVerifiable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host + "/"
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><head><meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="%[1]swp-content/themes/twentytwentyfour/style.css" />
<link rel="stylesheet" href="%[1]swp-content/plugins/goodlayers-core/plugins/style.css?ver=1.3.9" /></head><body></body></html>`, base)
		case "/wp-content/plugins/goodlayers-core/plugins/style.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, "body{}")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-u", srv.URL, "-e", "none", "--offline", "--data-dir", t.TempDir()}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d\n%s\n%s", code, &stdout, &stderr)
	}
	out := stdout.String()
	asset := srv.URL + "/wp-content/plugins/goodlayers-core/plugins/style.css?ver=1.3.9"
	for _, want := range []string{
		"goodlayers-core",
		"Found by: " + asset + ", referenced by " + srv.URL + "/",
		"Version: 1.3.9 (confidence 40%)",
		"Version from: ?ver= on the plugin's assets: " + asset + " (weak: plugins and themes do not always set ?ver= to their version; check it)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Location: "+srv.URL+"/wp-content/plugins/goodlayers-core/") {
		t.Error("the default report should not offer the plugin's folder, which answers 404")
	}
}
