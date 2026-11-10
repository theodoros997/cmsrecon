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
	Latest       string   // the latest release, when known; used when Version is unknown
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
// detected version, strongest verdict first. With an unknown version, an
// advisory that affects every version up to the latest release (or every
// version, when no fix exists) is a likely match: whatever the version, it
// is affected. The other advisories are possible matches.
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
			if affectsEveryVersion(primary.Affected, Normalize(d.Latest)) {
				m.Verdict = VerdictLikely
				if d.Latest != "" && hasUpperBound(primary.Affected) {
					m.Note = "The version is unknown, but every version up to the latest (" + d.Latest + ") is affected"
				} else {
					m.Note = "The version is unknown, but every version is affected"
				}
			}
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
		case a.Guessed:
			// The record names the product, not its slug: another
			// plugin may have that slug.
			m.Verdict = VerdictLikely
			if m.Note == "" {
				m.Note = "The record names the plugin by its product name, not its slug: check that it is this plugin"
			}
		case d.Confidence >= ConfirmedConfidence && !disagree && alternativesAgree(primary.Affected, d.Alternatives, in):
			m.Verdict = VerdictConfirmed
		default:
			m.Verdict = VerdictLikely
			switch {
			case m.Note != "":
			case d.Confidence >= ConfirmedConfidence:
				m.Note = "Another detected version candidate is not affected"
			default:
				m.Note = fmt.Sprintf("The version (%s) was detected with %d%% confidence only: check it before relying on this", d.Version, d.Confidence)
			}
		}
		out = append(out, m)
	}
	SortMatches(out)
	return out
}

// affectsEveryVersion reports whether a range with no lower bound covers
// every version: it has no upper bound either, or it reaches the latest
// release.
func affectsEveryVersion(ranges []Range, latest string) bool {
	for _, r := range ranges {
		if r.From != "" {
			continue
		}
		if r.To == "" || (latest != "" && r.Contains(latest)) {
			return true
		}
	}
	return false
}

func hasUpperBound(ranges []Range) bool {
	for _, r := range ranges {
		if r.To != "" {
			return true
		}
	}
	return false
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

// CoreBackports corrects core matches for the fixes WordPress backports
// to older branches. The CVE List often gives only the first fixed
// release ("< 5.8.3"), so 5.7.5, which has the backported fix, would
// look affected. For an advisory only the CVE List has: a fixed version
// on the detected version's own branch, at or below it, means the fix is
// there (the match is dropped); a first fix on a newer branch means it
// may be there (the match becomes possible).
func CoreBackports(ms []Match, version string) []Match {
	v := Normalize(version)
	out := ms[:0]
	for _, m := range ms {
		if m.Advisory.Kind != KindCore || len(m.Advisory.Sources) == 0 || m.Advisory.Sources[0].Source != SourceCVE {
			out = append(out, m)
			continue
		}
		fixedHere := false
		for _, f := range m.Advisory.Fixed {
			if branch(f) == branch(v) && Compare(v, f) >= 0 {
				fixedHere = true
			}
		}
		if fixedHere {
			continue
		}
		if m.Verdict != VerdictPossible && m.FixedIn != "" && Compare(branch(m.FixedIn), branch(v)) > 0 {
			m.Verdict = VerdictPossible
			m.Note = "Only the CVE List has this one, and it names " + m.FixedIn + " as the fix; WordPress also backports security fixes to older branches, so " + version + " may already have it"
		}
		out = append(out, m)
	}
	SortMatches(out)
	return out
}

// branch is a WordPress release branch: 6.4 for 6.4.2.
func branch(v string) string {
	parts := strings.SplitN(Normalize(v), ".", 3)
	if len(parts) < 2 {
		return parts[0]
	}
	return parts[0] + "." + parts[1]
}
