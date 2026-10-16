package main

import (
	"bytes"
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
		{"no args", nil, 2, nil},
		{"unknown command", []string{"bogus"}, 2, nil},
		{"version", []string{"version"}, 0, []string{"cmsrecon "}},
		{"help", []string{"--help"}, 0, []string{"Usage:"}},
		{"scan help", []string{"scan", "-h"}, 0, []string{"--enumerate"}},
		{"wpscan style dry run", []string{"-u", "example.com", "--dry-run"}, 0,
			[]string{"http://example.com/", "vulnerable", "author IDs 1-10"}},
		{"positional url before flags", []string{"scan", "https://example.com/blog", "-e", "ap,u1-3", "--dry-run"}, 0,
			[]string{"https://example.com/blog/", "Plugins:", "all", "author IDs 1-3"}},
		{"rest inventory replaces enumeration", []string{"-u", "example.com", "--wp-auth", "admin:abcd efgh", "--dry-run"}, 0,
			[]string{"REST API inventory as admin"}},
		{"scan without dry run is not implemented", []string{"-u", "example.com"}, 1, nil},
		{"conflicting enumeration", []string{"-u", "example.com", "-e", "vp,ap", "--dry-run"}, 2, nil},
		{"missing url", []string{"scan", "--dry-run"}, 2, nil},
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
