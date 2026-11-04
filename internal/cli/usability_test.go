package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigFile(t *testing.T) {
	cfg := writeConfig(t, `# cmsrecon defaults
wordfence-key = abc123
throttle = 200
user-agent = "Mozilla/5.0 (test)"
--stealthy = true
e = vp,vt,u1-5
`)
	o, err := ParseScan([]string{"--config", cfg, "example.com"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.Throttle != 200*time.Millisecond || o.UserAgent != "Mozilla/5.0 (test)" || o.DetectionMode != ModePassive || o.ConfigFile != cfg {
		t.Errorf("config defaults = throttle %v, UA %q, mode %s, file %q", o.Throttle, o.UserAgent, o.DetectionMode, o.ConfigFile)
	}
	if o.Enumerate.Users == nil || o.Enumerate.Users.To != 5 {
		t.Errorf("-e from the config = %+v", o.Enumerate)
	}

	// The command line wins over the file.
	o, err = ParseScan([]string{"example.com", "--throttle", "1s", "--config=" + cfg, "-e", "u1-2"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.Throttle != time.Second || o.Enumerate.Users.To != 2 {
		t.Errorf("command line override = %v, %+v", o.Throttle, o.Enumerate.Users)
	}

	// The update command takes its own keys from the same file, and skips
	// the scan's.
	u, err := ParseUpdate([]string{"--config", cfg}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if u.WordfenceKey != "abc123" {
		t.Errorf("update wordfence-key = %q", u.WordfenceKey)
	}

	// $CMSRECON_CONFIG names the file when --config does not.
	t.Setenv(ConfigEnv, cfg)
	if o, err = ParseScan([]string{"example.com"}, io.Discard); err != nil || o.Throttle != 200*time.Millisecond {
		t.Errorf("config from %s = %v, %v", ConfigEnv, o, err)
	}
	t.Setenv(ConfigEnv, "none")
	if o, err = ParseScan([]string{"example.com"}, io.Discard); err != nil || o.Throttle != 0 || o.ConfigFile != "" {
		t.Errorf("%s=none still read a file: %+v, %v", ConfigEnv, o, err)
	}
}

func TestConfigFileErrors(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
	}{
		{"typo", "trottle = 1s\n", `unknown option "trottle"`},
		{"no equals", "stealthy\n", "expected \"option = value\""},
		{"bad value", "threads = many\n", "invalid value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeConfig(t, tc.content)
			_, err := ParseScan([]string{"--config", cfg, "example.com"}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
	_, err := ParseScan([]string{"--config", filepath.Join(t.TempDir(), "missing"), "example.com"}, io.Discard)
	if err == nil {
		t.Error("a --config file that does not exist must be an error")
	}
	// A typo is an error for update too, while the scan's options are not.
	cfg := writeConfig(t, "threads = 3\nwordfence-ky = x\n")
	if _, err := ParseUpdate([]string{"--config", cfg}, io.Discard); err == nil || !strings.Contains(err.Error(), "wordfence-ky") {
		t.Errorf("update with a typo = %v", err)
	}
	if !scanOnlyOptions["login-uri"] || !scanOnlyOptions["log-requests"] || !scanOnlyOptions["resolve"] {
		t.Error("every scan option must be in the scan help, so that update's config check knows it")
	}
}

func TestFormatFromOutputFile(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want Format
	}{
		{[]string{"-o", "scan.json"}, FormatJSON},
		{[]string{"-o", "Scan.HTML"}, FormatHTML},
		{[]string{"-o", "scan.md"}, FormatMarkdown},
		{[]string{"-o", "scan.txt"}, FormatCLI},
		{[]string{"-o", "scan.json", "-f", "cli"}, FormatCLI},
		{[]string{"-f", "markdown"}, FormatMarkdown},
		{nil, FormatCLI},
	} {
		o, err := ParseScan(append([]string{"example.com"}, tc.args...), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if o.Format != tc.want {
			t.Errorf("%v: format = %s, want %s", tc.args, o.Format, tc.want)
		}
	}
}

func TestWPScanAliasesAndHints(t *testing.T) {
	o, err := ParseScan([]string{"--url", "example.com", "--max-threads", "3", "--request-timeout", "20", "--disable-tls-checks",
		"--cookie-string", "a=1", "--headers", "X-A: 1; X-B: 2", "--no-banner", "--throttle", "500"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.Threads != 1 || o.Timeout != 20*time.Second || !o.Insecure || o.Cookie != "a=1" || o.Throttle != 500*time.Millisecond {
		t.Errorf("WPScan options = threads %d, timeout %v, insecure %v, cookie %q, throttle %v", o.Threads, o.Timeout, o.Insecure, o.Cookie, o.Throttle)
	}
	if o.Headers.Get("X-A") != "1" || o.Headers.Get("X-B") != "2" {
		t.Errorf("--headers = %v", o.Headers)
	}
	_, err = ParseScan([]string{"-u", "example.com", "--passwords", "rockyou.txt"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "never guesses passwords") {
		t.Errorf("--passwords = %v", err)
	}
	_, err = ParseScan([]string{"-u", "example.com", "--api-token", "x"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cmsrecon update") {
		t.Errorf("--api-token = %v", err)
	}
}

func TestParseResolve(t *testing.T) {
	for _, tc := range []struct {
		target, resolve, vhost string
		want                   map[string]string
		host                   string // the target's host after --vhost
	}{
		{"https://example.com/", "10.0.0.5", "", map[string]string{"example.com": "10.0.0.5"}, "example.com"},
		{"http://example.com:8080/", "Example.com=10.0.0.5, cdn.example.com=::1", "", map[string]string{"example.com": "10.0.0.5", "cdn.example.com": "::1"}, "example.com:8080"},
		{"https://example.com/", "cdn.example.com:443:10.0.0.6", "", map[string]string{"cdn.example.com": "10.0.0.6"}, "example.com"},
		{"https://example.com/", "::1", "", map[string]string{"example.com": "::1"}, "example.com"},
		{"https://10.0.0.5:8443/", "", "www.example.com", map[string]string{"www.example.com": "10.0.0.5"}, "www.example.com:8443"},
	} {
		o, err := ParseScan([]string{"-u", tc.target, "--resolve", tc.resolve, "--vhost", tc.vhost}, io.Discard)
		if err != nil {
			t.Errorf("%s %s %s: %v", tc.target, tc.resolve, tc.vhost, err)
			continue
		}
		for k, v := range tc.want {
			if o.Resolve[k] != v {
				t.Errorf("%s %s %s: resolve = %v, want %s -> %s", tc.target, tc.resolve, tc.vhost, o.Resolve, k, v)
			}
		}
		if o.Target.Host != tc.host {
			t.Errorf("%s --vhost %s: target host = %s, want %s", tc.target, tc.vhost, o.Target.Host, tc.host)
		}
	}
}

func TestParseReport(t *testing.T) {
	o, err := ParseReport([]string{"scan.json", "-o", "scan.html"}, io.Discard)
	if err != nil || o.Input != "scan.json" || o.Format != FormatHTML {
		t.Errorf("report scan.json -o scan.html = %+v, %v", o, err)
	}
	if o, err = ParseReport([]string{"-f", "md", "scan.json"}, io.Discard); err != nil || o.Format != FormatMarkdown || o.Output != "" {
		t.Errorf("report -f md = %+v, %v", o, err)
	}
	for _, args := range [][]string{nil, {"a.json", "b.json"}, {"a.json", "-f", "pdf"}, {"a.json", "-o", "a.json"}} {
		if _, err := ParseReport(args, io.Discard); err == nil {
			t.Errorf("report %v: want an error", args)
		}
	}
}
