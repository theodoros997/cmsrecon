// Package buildinfo reports the version of the running binary.
package buildinfo

import (
	"fmt"
	"runtime/debug"
)

// Release builds set these with -ldflags, e.g.
//
//	go build -ldflags "-X github.com/theodoros997/cmsrecon/internal/buildinfo.Version=v0.1.0" ./cmd/cmsrecon
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String returns a one-line version banner. For plain `go build` binaries it
// falls back to the VCS details the Go toolchain embeds.
func String() string {
	commit, date := Commit, Date
	if commit == "" || date == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				switch {
				case s.Key == "vcs.revision" && commit == "":
					commit = s.Value
				case s.Key == "vcs.time" && date == "":
					date = s.Value
				}
			}
		}
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	if date == "" {
		date = "unknown"
	}
	return fmt.Sprintf("cmsrecon %s (commit %s, built %s)", Version, commit, date)
}
