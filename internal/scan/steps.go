package scan

import (
	"fmt"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/progress"
)

// The steps a scan reports, in the order they usually start.
const (
	stepData      = "Loading data"
	stepPreflight = "Pre-flight"
	stepFindings  = "Interesting findings"
	stepVersion   = "WordPress version"
	stepMainTheme = "Main theme"
	stepPlugins   = "Plugins"
	stepThemes    = "Themes"
	stepPages     = "Site pages"
	stepUsers     = "Users"
	stepJS        = "JavaScript libraries"
	stepMedia     = "Media"
	stepFolders   = "Plugin and theme folders"
	stepTimthumbs = "Timthumbs"
	stepVulns     = "Vulnerabilities"
)

func (s *Scanner) steps() progress.Reporter {
	if s.Steps == nil {
		return progress.Nop{}
	}
	return s.Steps
}

// dataSummary names the data the scan matches against.
func (s *Scanner) dataSummary() string {
	var names []string
	for _, src := range s.res.VulnerabilityData.Sources {
		name := map[string]string{"wordfence": "Wordfence", "cve": "CVE List", "wporg": "WordPress.org", "retirejs": "retire.js", "exploits": "public exploits"}[src.Name]
		if name == "" {
			name = src.Name
		}
		names = append(names, name)
	}
	if s.data.hashes != nil {
		names = append(names, "core checksums")
	}
	if len(names) == 0 {
		return "no vulnerability data: run \"cmsrecon update\""
	}
	return strings.Join(names, ", ")
}

func (s *Scanner) preflightSummary() string {
	out := "WordPress at " + s.base.String()
	if s.res.WordPress != nil && !s.res.WordPress.Detected {
		out = "not WordPress, scanning anyway (--force): " + s.base.String()
	}
	if ws := s.res.WebServer; ws != nil && ws.Header != "" {
		out += " (" + ws.Header + ")"
	}
	return out
}

func (s *Scanner) findingsSummary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.res.InterestingFindings
	if len(fs) == 0 {
		return "none"
	}
	bySev := map[string]int{}
	for _, f := range fs {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	out := fmt.Sprintf("%d found", len(fs))
	if len(parts) > 0 {
		out += " (" + strings.Join(parts, ", ") + ")"
	}
	return out
}

func versionSummary(v *Version) string {
	if v == nil || v.Number == "" {
		return "unknown"
	}
	return fmt.Sprintf("%s (confidence %d%%)", v.Number, v.Confidence)
}

func mainThemeSummary(t *Theme) string {
	if t == nil {
		return "not found"
	}
	out := t.Slug
	if t.Version != nil && t.Version.Number != "" {
		out += " " + t.Version.Number
	}
	if t.Parent != nil {
		out += ", child of " + t.Parent.Slug
	}
	return out
}

// countSummary says "3 found" or what none means.
func countSummary(n int, found, none string) string {
	if n == 0 {
		return none
	}
	return fmt.Sprintf("%d %s", n, found)
}

func (s *Scanner) vulnSummary() string {
	c := s.res.VulnerabilityCounts
	if s.data.vulns.Empty() {
		return "not matched: no vulnerability data"
	}
	var parts []string
	for _, x := range []struct {
		n    int
		what string
	}{{c.Confirmed, "confirmed"}, {c.Likely, "likely"}, {c.Possible, "possible"}} {
		if x.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", x.n, x.what))
		}
	}
	if len(parts) == 0 {
		return "none matched"
	}
	out := strings.Join(parts, ", ")
	if n := s.withExploits(); n > 0 {
		out += fmt.Sprintf("; %d with a public exploit", n)
	}
	return out
}

// withExploits counts the confirmed and likely vulnerabilities that have a
// public exploit.
func (s *Scanner) withExploits() int {
	r := s.res
	n := 0
	count := func(vs []Vulnerability) {
		for _, v := range vs {
			if v.Verdict != VerdictPossible && len(v.Exploits) > 0 {
				n++
			}
		}
	}
	count(r.CoreVulnerabilities)
	for t := r.MainTheme; t != nil; t = t.Parent {
		count(t.Vulnerabilities)
	}
	for _, t := range r.Themes {
		count(t.Vulnerabilities)
	}
	for _, p := range r.Plugins {
		count(p.Vulnerabilities)
	}
	for _, l := range r.JSLibraries {
		count(l.Vulnerabilities)
	}
	for _, t := range r.Timthumbs {
		count(t.Vulnerabilities)
	}
	return n
}
