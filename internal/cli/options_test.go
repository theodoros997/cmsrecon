package cli

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "example.com", want: "http://example.com/"},
		{in: "https://example.com", want: "https://example.com/"},
		{in: " https://example.com/blog ", want: "https://example.com/blog/"},
		{in: "https://example.com/blog/?p=1#top", want: "https://example.com/blog/"},
		{in: "http://10.0.0.5:8080", want: "http://10.0.0.5:8080/"},
		{in: "", wantErr: "required"},
		{in: "ftp://example.com", wantErr: "unsupported URL scheme"},
		{in: "https://", wantErr: "missing host"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := normalizeTarget(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseScanDefaults(t *testing.T) {
	o, err := ParseScan([]string{"-u", "example.com"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.DetectionMode != ModeMixed || o.Format != FormatCLI || o.Threads != 5 || o.Timeout != 60*time.Second {
		t.Errorf("unexpected defaults: %+v", o)
	}
	if o.Enumerate.Plugins != ItemsVulnerable || o.Enumerate.Users == nil {
		t.Errorf("default enumeration not applied: %+v", o.Enumerate)
	}
	if o.DataDir == "" {
		t.Error("DataDir should default to the user cache dir")
	}
}

func TestParseScanOptions(t *testing.T) {
	o, err := ParseScan([]string{
		"--url", "https://example.com",
		"-H", "X-Test: one", "--header", "x-test:two",
		"--http-auth", "user:p:a:ss",
		"--proxy", "socks5h://127.0.0.1:9050",
		"--throttle", "250ms", "-t", "20",
		"--scope", "CDN.example.com, ,static.example.com",
		"--detection-mode", "Passive", "-f", "json",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := o.Headers.Values("X-Test"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("headers = %v", got)
	}
	if o.HTTPAuth.Username != "user" || o.HTTPAuth.Password != "p:a:ss" {
		t.Errorf("http auth = %+v", o.HTTPAuth)
	}
	if o.Proxy.Scheme != "socks5h" {
		t.Errorf("proxy = %v", o.Proxy)
	}
	if o.Threads != 1 {
		t.Errorf("throttle should force 1 thread, got %d", o.Threads)
	}
	if strings.Join(o.Scope, ",") != "cdn.example.com,static.example.com" {
		t.Errorf("scope = %v", o.Scope)
	}
	if o.DetectionMode != ModePassive || o.Format != FormatJSON {
		t.Errorf("mode/format = %s/%s", o.DetectionMode, o.Format)
	}
}

func TestParseScanErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing url", nil, "required"},
		{"two positionals", []string{"a.com", "b.com"}, "unexpected arguments"},
		{"bad mode", []string{"-u", "a.com", "--detection-mode", "loud"}, "--detection-mode"},
		{"bad format", []string{"-u", "a.com", "-f", "xml"}, "--format"},
		{"bad threads", []string{"-u", "a.com", "-t", "0"}, "--threads"},
		{"bad timeout", []string{"-u", "a.com", "--timeout", "0s"}, "--timeout"},
		{"bad header", []string{"-u", "a.com", "-H", "nocolon"}, "Name: value"},
		{"bad credentials", []string{"-u", "a.com", "--wp-auth", "nopassword"}, "login:password"},
		{"bad proxy scheme", []string{"-u", "a.com", "--proxy", "ftp://h:1"}, "unsupported --proxy"},
		{"unknown flag", []string{"-u", "a.com", "--password-attack"}, "not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseScan(tt.args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseScanHelp(t *testing.T) {
	var out strings.Builder
	_, err := ParseScan([]string{"--help"}, &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(out.String(), "--enumerate") {
		t.Error("help output is missing the options list")
	}
}

func TestParseUpdate(t *testing.T) {
	t.Setenv("WORDFENCE_API_KEY", " env-key ")
	o, err := ParseUpdate([]string{"--data-dir", "/tmp/x"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.DataDir != "/tmp/x" || o.WordfenceKey != "env-key" || len(o.Sources) != len(UpdateSources) || o.Timeout <= 0 {
		t.Errorf("defaults = %+v", o)
	}
	o, err = ParseUpdate([]string{"--sources", "cve, retirejs,cve", "--wordfence-key", "flag-key", "--proxy", "http://127.0.0.1:8080"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(o.Sources, ",") != "cve,retirejs" || o.WordfenceKey != "flag-key" || o.Proxy == nil {
		t.Errorf("options = %+v", o)
	}
	for _, args := range [][]string{{"--sources", "nvd"}, {"--sources", ","}, {"extra"}, {"--timeout", "0s"}, {"--proxy", "ftp://x"}} {
		if _, err := ParseUpdate(args, io.Discard); err == nil {
			t.Errorf("%v: want an error", args)
		}
	}
	var help strings.Builder
	if _, err := ParseUpdate([]string{"-h"}, &help); !errors.Is(err, flag.ErrHelp) || !strings.Contains(help.String(), "WORDFENCE_API_KEY") {
		t.Errorf("help: %v\n%s", err, help.String())
	}
}
