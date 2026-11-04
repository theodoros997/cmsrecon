package scan

import (
	"fmt"
	"slices"
	"strings"
)

// maxRisks caps the summary's list.
const maxRisks = 15

// Summary is what a reader needs first: the most serious findings and
// vulnerabilities, most severe first.
type Summary struct {
	// VulnerabilitiesChecked is false when no vulnerability data was
	// available: "no vulnerability" then means "not checked".
	VulnerabilitiesChecked bool   `json:"vulnerabilities_checked"`
	Risks                  []Risk `json:"risks"`
	MoreRisks              int    `json:"more_risks"` // risks left out of the list
}

// Risk is one line of the summary: a critical, high or medium finding, or
// a confirmed or likely vulnerability.
type Risk struct {
	Severity  string   `json:"severity"`            // critical, high, medium, low or "" when unrated
	Kind      string   `json:"kind"`                // "finding" or "vulnerability"
	Title     string   `json:"title"`               // the finding or the vulnerability
	Component string   `json:"component,omitempty"` // what is vulnerable: "plugin contact-form-7 5.3.1"
	Verdict   string   `json:"verdict,omitempty"`   // confirmed or likely, for vulnerabilities
	CVE       []string `json:"cve,omitempty"`
	Exploit   bool     `json:"public_exploit,omitempty"` // a public exploit or proof of concept is linked
	URL       string   `json:"url,omitempty"`
}

// Summarize builds the summary from a result; scans fill it in, and it
// rebuilds the summary of a saved report that has none.
func Summarize(r *Result) *Summary {
	sum := &Summary{VulnerabilitiesChecked: r.VulnerabilityData != nil && len(r.VulnerabilityData.Sources) > 0 && hasVulnSource(r.VulnerabilityData)}
	var risks []Risk
	for _, f := range r.InterestingFindings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.Severity == SeverityMedium {
			risks = append(risks, Risk{Severity: f.Severity, Kind: "finding", Title: f.Title, URL: f.URL})
		}
	}
	vulns := func(component string, vs []Vulnerability) {
		for _, v := range vs {
			if v.Verdict == VerdictPossible {
				continue
			}
			risks = append(risks, Risk{Severity: v.Severity, Kind: "vulnerability", Title: v.Title, Component: component,
				Verdict: v.Verdict, CVE: v.CVE, Exploit: len(v.Exploits) > 0})
		}
	}
	if r.Version != nil {
		vulns("WordPress "+r.Version.Number, r.CoreVulnerabilities)
	}
	for t := r.MainTheme; t != nil; t = t.Parent {
		vulns(componentName("theme", t.Slug, t.Version), t.Vulnerabilities)
	}
	for _, t := range r.Themes {
		vulns(componentName("theme", t.Slug, t.Version), t.Vulnerabilities)
	}
	for _, p := range r.Plugins {
		vulns(componentName("plugin", p.Slug, p.Version), p.Vulnerabilities)
	}
	for _, l := range r.JSLibraries {
		vulns(componentName("library", l.Name, l.Version), l.Vulnerabilities)
	}
	for _, t := range r.Timthumbs {
		vulns("TimThumb "+t.URL, t.Vulnerabilities)
	}
	slices.SortStableFunc(risks, func(a, b Risk) int {
		if d := severityRank(b.Severity) - severityRank(a.Severity); d != 0 {
			return d
		}
		if a.Exploit != b.Exploit {
			if a.Exploit {
				return -1
			}
			return 1
		}
		if a.Verdict != b.Verdict {
			if a.Verdict == VerdictConfirmed {
				return -1
			}
			if b.Verdict == VerdictConfirmed {
				return 1
			}
		}
		return 0
	})
	if len(risks) > maxRisks {
		sum.MoreRisks = len(risks) - maxRisks
		risks = risks[:maxRisks]
	}
	sum.Risks = risks
	return sum
}

func hasVulnSource(d *DataInfo) bool {
	for _, s := range d.Sources {
		if s.Name == "wordfence" || s.Name == "cve" {
			return true
		}
	}
	return false
}

func componentName(kind, slug string, v *Version) string {
	out := kind + " " + slug
	if v != nil && v.Number != "" {
		out += " " + v.Number
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// Line is a risk in one line for people.
func (r Risk) Line() string {
	sev := strings.ToUpper(r.Severity)
	if sev == "" {
		sev = "UNRATED"
	}
	if r.Kind == "finding" {
		return fmt.Sprintf("%-8s %s", sev, r.Title)
	}
	parts := []string{r.Verdict}
	if len(r.CVE) > 0 {
		parts = append(parts, strings.Join(r.CVE, ", "))
	}
	if r.Exploit {
		parts = append(parts, "public exploit")
	}
	return fmt.Sprintf("%-8s %s: %s (%s)", sev, r.Component, ShortTitle(r.Title), strings.Join(parts, ", "))
}

// ShortTitle cuts a long vulnerability title (retire.js gives whole
// descriptions) to its first sentence, at most 140 characters.
func ShortTitle(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, ". "); i > 40 && i < 140 {
		t = t[:i]
	}
	if r := []rune(t); len(r) > 140 {
		t = string(r[:137]) + "..."
	}
	return t
}
