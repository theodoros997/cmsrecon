package vulndb

import (
	"regexp"
	"strings"
)

// Range is a span of affected versions. An empty From or To means the range
// is open on that side, so the zero Range covers every version.
type Range struct {
	From          string `json:"from,omitempty"`
	FromInclusive bool   `json:"from_inclusive,omitempty"`
	To            string `json:"to,omitempty"`
	ToInclusive   bool   `json:"to_inclusive,omitempty"`
}

// Contains reports whether version v is inside the range.
func (r Range) Contains(v string) bool {
	if r.From != "" {
		c := Compare(v, r.From)
		if c < 0 || (c == 0 && !r.FromInclusive) {
			return false
		}
	}
	if r.To != "" {
		c := Compare(v, r.To)
		if c > 0 || (c == 0 && !r.ToInclusive) {
			return false
		}
	}
	return true
}

// String describes the range for people: "<= 5.3.1", "4.2 - 4.2.34",
// ">= 9.0.0, < 9.1.2", "all versions".
func (r Range) String() string {
	op := func(incl bool, lt bool) string {
		switch {
		case lt && incl:
			return "<= "
		case lt:
			return "< "
		case incl:
			return ">= "
		default:
			return "> "
		}
	}
	switch {
	case r.From == "" && r.To == "":
		return "all versions"
	case r.From == "":
		return op(r.ToInclusive, true) + r.To
	case r.To == "":
		return op(r.FromInclusive, false) + r.From
	case r.From == r.To && r.FromInclusive && r.ToInclusive:
		return r.From
	case r.FromInclusive && r.ToInclusive:
		return r.From + " - " + r.To
	}
	return op(r.FromInclusive, false) + r.From + ", " + op(r.ToInclusive, true) + r.To
}

// AnyContains reports whether any of the ranges contains v.
func AnyContains(ranges []Range, v string) bool {
	for _, r := range ranges {
		if r.Contains(v) {
			return true
		}
	}
	return false
}

// openBound reports whether a version bound in a data feed means "no bound".
func openBound(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "*", "0", "n/a", "unspecified", "-", "all":
		return true
	}
	return false
}

var exprPartRe = regexp.MustCompile(`^(<=|>=|<|>|=|≤|≥)?\s*v?([0-9][0-9A-Za-z.\-_+]*)$`)

// parseRangeExpr parses expressions such as "< 5.8.3", ">= 4.2, < 4.2.34"
// or "<= 1.0" (the form GitHub's CNA writes in the version field). It
// returns false when expr is not such an expression.
func parseRangeExpr(expr string) (Range, bool) {
	var r Range
	parts := strings.Split(expr, ",")
	seenOp := false
	for _, p := range parts {
		m := exprPartRe.FindStringSubmatch(strings.TrimSpace(p))
		if m == nil {
			return Range{}, false
		}
		v := m[2]
		switch m[1] {
		case "<":
			r.To, r.ToInclusive = v, false
		case "<=", "≤":
			r.To, r.ToInclusive = v, true
		case ">":
			r.From, r.FromInclusive = v, false
		case ">=", "≥":
			r.From, r.FromInclusive = v, true
		case "=", "":
			if len(parts) > 1 {
				return Range{}, false
			}
			r = Range{From: v, FromInclusive: true, To: v, ToInclusive: true}
		}
		seenOp = seenOp || m[1] != ""
	}
	return r, seenOp
}
