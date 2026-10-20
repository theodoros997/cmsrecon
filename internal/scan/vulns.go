package scan

import (
	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// matchVulnerabilities attaches the known vulnerabilities to every detected
// component and counts them.
func (s *Scanner) matchVulnerabilities() {
	r := s.res
	db := s.data.vulns
	if r.Version != nil {
		d := detected(r.Version)
		// Every WordPress vulnerability ever published "may" apply to an
		// unknown version, which says nothing; only a known version is
		// matched.
		if d.Version != "" {
			r.CoreVulnerabilities = toVulns(db.Match(vulndb.KindCore, vulndb.CoreSlug, d))
		} else if !db.Empty() {
			s.res.Notices = append(s.res.Notices, "The WordPress version is unknown, so core vulnerabilities were not matched.")
		}
	}
	themes := append([]*Theme{}, r.Themes...)
	for t := r.MainTheme; t != nil; t = t.Parent {
		themes = append(themes, t)
	}
	for _, t := range themes {
		t.Vulnerabilities = toVulns(db.Match(vulndb.KindTheme, t.Slug, detected(t.Version)))
	}
	for _, p := range r.Plugins {
		p.Vulnerabilities = toVulns(db.Match(vulndb.KindPlugin, p.Slug, detected(p.Version)))
	}
	for _, l := range r.JSLibraries {
		// Library vulnerabilities only apply to a known version.
		if d := detected(l.Version); d.Version != "" {
			l.Vulnerabilities = toVulns(vulndb.MatchAdvisories(s.data.js.Advisories(l.Name), d))
		}
	}

	var c VulnCounts
	count := func(vs []Vulnerability) {
		for _, v := range vs {
			switch v.Verdict {
			case VerdictConfirmed:
				c.Confirmed++
			case VerdictLikely:
				c.Likely++
			default:
				c.Possible++
			}
		}
	}
	count(r.CoreVulnerabilities)
	for _, t := range themes {
		count(t.Vulnerabilities)
	}
	for _, p := range r.Plugins {
		count(p.Vulnerabilities)
	}
	for _, l := range r.JSLibraries {
		count(l.Vulnerabilities)
	}
	r.VulnerabilityCounts = c
}

// detected turns a detected version into what the matcher needs: the
// version, its confidence, and the other candidates that reached the
// reporting threshold.
func detected(v *Version) vulndb.Detected {
	if v == nil {
		return vulndb.Detected{}
	}
	d := vulndb.Detected{Version: v.Number, Confidence: v.Confidence}
	if v.Number != "" {
		for _, c := range v.Candidates {
			if c.Number != v.Number && c.Confidence >= MinVersionConfidence {
				d.Alternatives = append(d.Alternatives, c.Number)
			}
		}
	}
	return d
}

func toVulns(ms []vulndb.Match) []Vulnerability {
	out := make([]Vulnerability, 0, len(ms))
	for _, m := range ms {
		a := m.Advisory
		v := Vulnerability{
			Title: a.Title, Verdict: m.Verdict, Severity: a.Severity, CVSS: a.CVSS, CVSSVector: a.CVSSVector,
			CVE: a.CVE, CWE: a.CWE, Affected: m.Affected, FixedIn: m.FixedIn, Unfixed: a.Unfixed && m.FixedIn == "",
			Published: a.Published, Note: m.Note, References: a.References,
		}
		for _, src := range a.Sources {
			v.Sources = append(v.Sources, src.Source)
		}
		out = append(out, v)
	}
	return out
}
