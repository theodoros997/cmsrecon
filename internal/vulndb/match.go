package vulndb

import (
	"fmt"
	"sort"
	"strings"
)

// Verdicts of a match, strongest first.
const (
	// VerdictConfirmed: the detected version is inside the affected range
	// and was detected with at least ConfirmedConfidence.
	VerdictConfirmed = "confirmed"
	// VerdictLikely: the version is inside the range, but it was detected
	// with less confidence, another candidate version is outside the
	// range, or the sources disagree.
	VerdictLikely = "likely"
	// VerdictPossible: the version is unknown, or only a secondary source
	// puts it inside the range.
	VerdictPossible = "possible"
)

// ConfirmedConfidence is the version confidence a confirmed match needs.
const ConfirmedConfidence = 70

// Detected is what a scan knows about the version of a piece of software.
type Detected struct {
	Version      string   // empty when unknown
	Confidence   int      // of Version
	Alternatives []string // other candidate versions a scan could not rule out
}

// Match is an advisory that applies, or may apply, to a detected version.
type Match struct {
	Advisory *Advisory
	Verdict  string
	Affected []string // the primary source's ranges, for people
	FixedIn  string   // the first fixed version above the detected one, or the lowest fixed version
	Note     string   // how the sources disagree, if they do
}

// Match returns the advisories of a piece of software that apply to the
// detected version, strongest verdict first. With an unknown version,
// every advisory is a possible match.
func (db *DB) Match(kind, slug string, d Detected) []Match {
	return MatchAdvisories(db.Advisories(kind, slug), d)
}

// MatchAdvisories matches a list of advisories against a detected version.
func MatchAdvisories(advs []*Advisory, d Detected) []Match {
	v := Normalize(d.Version)
	var out []Match
	for _, a := range advs {
		primary := a.Sources[0]
		m := Match{Advisory: a, Affected: rangeStrings(primary.Affected), FixedIn: fixedIn(a.Fixed, v)}
		if v == "" {
			m.Verdict = VerdictPossible
			out = append(out, m)
			continue
		}
		in := AnyContains(primary.Affected, v)
		disagree := false
		for _, s := range a.Sources[1:] {
			disagree = disagree || AnyContains(s.Affected, v) != in
		}
		if !in && !disagree {
			continue
		}
		if disagree {
			var parts []string
			for _, s := range a.Sources {
				parts = append(parts, SourceLabel(s.Source)+": "+strings.Join(rangeStrings(s.Affected), ", "))
			}
			m.Note = "The sources disagree on the affected versions (" + strings.Join(parts, "; ") + ")"
		}
		switch {
		case !in:
			m.Verdict = VerdictPossible
		case d.Confidence >= ConfirmedConfidence && !disagree && alternativesAgree(primary.Affected, d.Alternatives, in):
			m.Verdict = VerdictConfirmed
		default:
			m.Verdict = VerdictLikely
			if m.Note == "" && d.Confidence >= ConfirmedConfidence {
				m.Note = "Another detected version candidate is not affected"
			}
		}
		out = append(out, m)
	}
	SortMatches(out)
	return out
}

func alternativesAgree(ranges []Range, alts []string, in bool) bool {
	for _, alt := range alts {
		if AnyContains(ranges, Normalize(alt)) != in {
			return false
		}
	}
	return true
}

func rangeStrings(rs []Range) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}

// fixedIn picks the lowest fixed version above v, or the lowest fixed
// version when v is unknown or newer than all of them.
func fixedIn(fixed []string, v string) string {
	if len(fixed) == 0 {
		return ""
	}
	sorted := append([]string(nil), fixed...)
	sort.Slice(sorted, func(i, j int) bool { return Compare(sorted[i], sorted[j]) < 0 })
	if v != "" {
		for _, f := range sorted {
			if Compare(f, v) > 0 {
				return f
			}
		}
	}
	return sorted[0]
}

var verdictRank = map[string]int{VerdictConfirmed: 0, VerdictLikely: 1, VerdictPossible: 2}

// SortMatches orders matches by verdict, then severity, then newest first.
func SortMatches(ms []Match) {
	sort.SliceStable(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if verdictRank[a.Verdict] != verdictRank[b.Verdict] {
			return verdictRank[a.Verdict] < verdictRank[b.Verdict]
		}
		if sa, sb := SeverityRank(a.Advisory.Severity), SeverityRank(b.Advisory.Severity); sa != sb {
			return sa > sb
		}
		if a.Advisory.CVSS != b.Advisory.CVSS {
			return a.Advisory.CVSS > b.Advisory.CVSS
		}
		if a.Advisory.Published != b.Advisory.Published {
			return a.Advisory.Published > b.Advisory.Published
		}
		return a.Advisory.Title < b.Advisory.Title
	})
}

// SeverityRank orders severities: critical 4, high 3, medium 2, low 1,
// unknown 0.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// String describes a match in one line, for debugging and tests.
func (m Match) String() string {
	return fmt.Sprintf("%s %s (%s)", m.Verdict, m.Advisory.Title, strings.Join(m.Affected, ", "))
}
