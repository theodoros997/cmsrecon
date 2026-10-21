package scan

import (
	"slices"

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
			r.CoreVulnerabilities = s.toVulns(db.Match(vulndb.KindCore, vulndb.CoreSlug, d))
		} else if !db.Empty() {
			s.res.Notices = append(s.res.Notices, "The WordPress version is unknown, so core vulnerabilities were not matched.")
		}
	}
	themes := append([]*Theme{}, r.Themes...)
	for t := r.MainTheme; t != nil; t = t.Parent {
		themes = append(themes, t)
	}
	var possible int
	for _, t := range themes {
		t.Vulnerabilities, t.Possible = s.splitPossible(db.Match(vulndb.KindTheme, t.Slug, detected(t.Version)))
		possible += t.Possible.count()
	}
	for _, p := range r.Plugins {
		p.Vulnerabilities, p.Possible = s.splitPossible(db.Match(vulndb.KindPlugin, p.Slug, detected(p.Version)))
		possible += p.Possible.count()
	}
	for _, t := range r.Timthumbs {
		t.Vulnerabilities = s.timthumbVulns(t.Version)
	}
	for _, l := range r.JSLibraries {
		// Library vulnerabilities only apply to a known version.
		if d := detected(l.Version); d.Version != "" {
			l.Vulnerabilities = s.toVulns(vulndb.MatchAdvisories(s.data.js.Advisories(l.Name), d))
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
	for _, t := range r.Timthumbs {
		count(t.Vulnerabilities)
	}
	if !s.opts.ShowPossible {
		c.Possible = possible // they are not in the lists, only summarized
	}
	r.VulnerabilityCounts = c
}

// splitPossible separates the possible matches from the others. With
// --possible they stay in the list; either way they are summarized.
func (s *Scanner) splitPossible(ms []vulndb.Match) ([]Vulnerability, *PossibleVulns) {
	var keep []vulndb.Match
	var sum *PossibleVulns
	allFixed := true
	for _, m := range ms {
		if m.Verdict != vulndb.VerdictPossible {
			keep = append(keep, m)
			continue
		}
		if s.opts.ShowPossible {
			keep = append(keep, m)
		}
		if sum == nil {
			sum = &PossibleVulns{Listed: s.opts.ShowPossible}
		}
		sum.Count++
		if len(s.exploitsFor(m.Advisory.CVE, m.Advisory.References)) > 0 {
			sum.Exploits++
		}
		switch m.Advisory.Severity {
		case SeverityCritical:
			sum.Critical++
		case SeverityHigh:
			sum.High++
		}
		// The highest fix of each advisory; the highest of those fixes all.
		top := ""
		for _, f := range m.Advisory.Fixed {
			if top == "" || vulndb.Compare(f, top) > 0 {
				top = f
			}
		}
		switch {
		case top == "":
			allFixed = false
		case sum.FixedIn == "" || vulndb.Compare(top, sum.FixedIn) > 0:
			sum.FixedIn = top
		}
	}
	if sum != nil && !allFixed {
		sum.FixedIn = ""
	}
	return s.toVulns(keep), sum
}

func (p *PossibleVulns) count() int {
	if p == nil {
		return 0
	}
	return p.Count
}

// detected turns a detected version into what the matcher needs: the
// version, its confidence, and the other candidates that reached the
// reporting threshold.
func detected(v *Version) vulndb.Detected {
	if v == nil {
		return vulndb.Detected{}
	}
	d := vulndb.Detected{Version: v.Number, Confidence: v.Confidence, Latest: v.Latest}
	if v.Number != "" {
		for _, c := range v.Candidates {
			if c.Number != v.Number && c.Confidence >= MinVersionConfidence {
				d.Alternatives = append(d.Alternatives, c.Number)
			}
		}
	}
	return d
}

// exploitsFor returns the public exploits of a vulnerability: those the
// exploit index lists for its CVEs, and its references that are exploits.
func (s *Scanner) exploitsFor(cves, refs []string) []Exploit {
	out := s.data.exploits.Lookup(cves)
	for _, ref := range refs {
		e, ok := vulndb.ExploitFromReference(ref)
		if ok && !slices.ContainsFunc(out, func(o Exploit) bool { return o.URL == e.URL }) {
			out = append(out, e)
		}
	}
	vulndb.SortExploits(out)
	return out
}

func (s *Scanner) toVulns(ms []vulndb.Match) []Vulnerability {
	out := make([]Vulnerability, 0, len(ms))
	for _, m := range ms {
		a := m.Advisory
		v := Vulnerability{
			Title: a.Title, Verdict: m.Verdict, Severity: a.Severity, CVSS: a.CVSS, CVSSVector: a.CVSSVector,
			CVE: a.CVE, CWE: a.CWE, Affected: m.Affected, FixedIn: m.FixedIn, Unfixed: a.Unfixed && m.FixedIn == "",
			Published: a.Published, Note: m.Note, References: a.References, Exploits: s.exploitsFor(a.CVE, a.References),
		}
		for _, src := range a.Sources {
			v.Sources = append(v.Sources, src.Source)
		}
		out = append(out, v)
	}
	return out
}
