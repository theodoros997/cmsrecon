package vulndb

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// WordfenceURL is the Wordfence Intelligence v3 production feed. It needs
// a free API key, sent as a bearer token.
const WordfenceURL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"

// wordfenceRecord is one record of the feed. Only the fields cmsrecon uses
// are decoded.
type wordfenceRecord struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Software []struct {
		Type             string `json:"type"`
		Slug             string `json:"slug"`
		AffectedVersions map[string]struct {
			FromVersion   string `json:"from_version"`
			FromInclusive bool   `json:"from_inclusive"`
			ToVersion     string `json:"to_version"`
			ToInclusive   bool   `json:"to_inclusive"`
		} `json:"affected_versions"`
		Patched         bool     `json:"patched"`
		PatchedVersions []string `json:"patched_versions"`
	} `json:"software"`
	Informational bool     `json:"informational"`
	References    []string `json:"references"`
	CWE           *struct {
		ID   flexString `json:"id"`
		Name string     `json:"name"`
	} `json:"cwe"`
	CVSS *struct {
		Vector string    `json:"vector"`
		Score  flexFloat `json:"score"`
		Rating string    `json:"rating"`
	} `json:"cvss"`
	CVE       *string `json:"cve"`
	Published string  `json:"published"`
}

// flexFloat decodes a number that may be sent as a JSON number or string.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil // an unexpected score is not worth failing the feed for
	}
	*f = flexFloat(v)
	return nil
}

// flexString decodes a value that may be a JSON string or number.
type flexString string

func (s *flexString) UnmarshalJSON(b []byte) error {
	*s = flexString(strings.Trim(string(b), `"`))
	if *s == "null" {
		*s = ""
	}
	return nil
}

// ParseWordfence reads the Wordfence Intelligence feed, a JSON object of
// records keyed by ID (a JSON array is accepted too), and returns one Vuln
// per affected piece of software. Informational records are skipped. The
// feed is decoded record by record, so its size does not matter.
func ParseWordfence(r io.Reader) ([]*Vuln, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("wordfence feed: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return nil, fmt.Errorf("wordfence feed: unexpected start %v", tok)
	}
	var out []*Vuln
	for dec.More() {
		if delim == '{' {
			if _, err := dec.Token(); err != nil { // the record ID
				return nil, fmt.Errorf("wordfence feed: %w", err)
			}
		}
		var rec wordfenceRecord
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("wordfence feed: %w", err)
		}
		out = append(out, rec.vulns()...)
	}
	return out, nil
}

func (rec *wordfenceRecord) vulns() []*Vuln {
	if rec.Informational || rec.ID == "" {
		return nil
	}
	base := Vuln{
		ID:         rec.ID,
		Title:      strings.TrimSpace(rec.Title),
		References: append([]string{"https://www.wordfence.com/threat-intel/vulnerabilities/id/" + rec.ID}, rec.References...),
		Published:  datePart(rec.Published),
	}
	if rec.CVE != nil && strings.HasPrefix(*rec.CVE, "CVE-") {
		base.CVE = []string{*rec.CVE}
	}
	if rec.CVSS != nil {
		base.CVSS = float64(rec.CVSS.Score)
		base.CVSSVector = rec.CVSS.Vector
		base.Severity = normalizeSeverity(rec.CVSS.Rating)
		if base.Severity == "" {
			base.Severity = SeverityFromScore(base.CVSS)
		}
	}
	if rec.CWE != nil && rec.CWE.ID != "" {
		base.CWE = "CWE-" + string(rec.CWE.ID)
		if rec.CWE.Name != "" {
			base.CWE += " " + rec.CWE.Name
		}
	}

	var out []*Vuln
	for _, sw := range rec.Software {
		kind := sw.Type
		switch kind {
		case KindCore:
			sw.Slug = CoreSlug
		case KindPlugin, KindTheme:
		default:
			continue
		}
		if sw.Slug == "" {
			continue
		}
		v := base
		v.Kind, v.Slug = kind, strings.ToLower(sw.Slug)
		// Map keys are range labels; sort them so the output is stable.
		labels := make([]string, 0, len(sw.AffectedVersions))
		for l := range sw.AffectedVersions {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		for _, l := range labels {
			av := sw.AffectedVersions[l]
			r := Range{FromInclusive: av.FromInclusive, ToInclusive: av.ToInclusive}
			if av.FromVersion != "*" && av.FromVersion != "" {
				r.From = Normalize(av.FromVersion)
			} else {
				r.FromInclusive = false
			}
			if av.ToVersion != "*" && av.ToVersion != "" {
				r.To = Normalize(av.ToVersion)
			} else {
				r.ToInclusive = false
			}
			v.Affected = append(v.Affected, r)
		}
		if len(v.Affected) == 0 {
			continue
		}
		for _, p := range sw.PatchedVersions {
			if p = Normalize(p); p != "" {
				v.Fixed = append(v.Fixed, p)
			}
		}
		v.Unfixed = !sw.Patched && len(v.Fixed) == 0
		out = append(out, &v)
	}
	return out
}

// datePart returns the YYYY-MM-DD part of a timestamp.
func datePart(ts string) string {
	ts = strings.TrimSpace(ts)
	if len(ts) >= 10 && ts[4] == '-' && ts[7] == '-' {
		return ts[:10]
	}
	return ""
}
