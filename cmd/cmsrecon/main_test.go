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
		{"update help", []string{"update", "-h"}, exitOK, []string{"cmsrecon update [options]", "retirejs"}},
		{"update unknown source", []string{"update", "--sources", "nvd"}, exitUsage, nil},
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
