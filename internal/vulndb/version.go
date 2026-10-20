package vulndb

import (
	"strings"
	"unicode"
)

// Compare compares two version numbers and returns -1, 0 or 1. It accepts
// the forms WordPress, plugins and themes use: "6.4.2", "1.2.3.4",
// "2.0-beta1", "v3.1", "4.0.0RC2". Missing numeric parts count as zero, so
// "6.4" equals "6.4.0". Pre-release words sort before the release, in the
// order PHP's version_compare uses: dev < alpha < beta < RC < release <
// patch.
func Compare(a, b string) int {
	ta, tb := tokens(a), tokens(b)
	for i := range max(len(ta), len(tb)) {
		var x, y token
		if i < len(ta) {
			x = ta[i]
		} else {
			x = token{numeric: true}
		}
		if i < len(tb) {
			y = tb[i]
		} else {
			y = token{numeric: true}
		}
		if c := x.compare(y); c != 0 {
			return c
		}
	}
	return 0
}

// Normalize trims spaces and a leading "v" from a version number.
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v
}

type token struct {
	numeric bool
	digits  string // numeric value without leading zeros ("" is zero)
	word    string // lower-case word
}

// tokens splits a version into numeric and word parts: "2.0-beta1" gives
// 2, 0, beta, 1.
func tokens(v string) []token {
	v = strings.ToLower(Normalize(v))
	var out []token
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		part := v[start:end]
		if part[0] >= '0' && part[0] <= '9' {
			out = append(out, token{numeric: true, digits: strings.TrimLeft(part, "0")})
		} else {
			out = append(out, token{word: part})
		}
		start = -1
	}
	for i, r := range v {
		isDigit := r >= '0' && r <= '9'
		isLetter := unicode.IsLetter(r)
		if !isDigit && !isLetter {
			flush(i)
			continue
		}
		if start >= 0 {
			prevDigit := v[start] >= '0' && v[start] <= '9'
			if prevDigit != isDigit {
				flush(i)
			}
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(v))
	return out
}

// rank orders a part the way PHP's version_compare does: unknown words
// first, then dev, alpha, beta, RC, numbers, and patch levels last.
func (t token) rank() int {
	if t.numeric {
		return 5
	}
	switch t.word {
	case "dev":
		return 1
	case "alpha", "a":
		return 2
	case "beta", "b":
		return 3
	case "rc", "c", "pre", "preview":
		return 4
	case "pl", "p", "patch":
		return 6
	}
	return 0
}

func (t token) compare(o token) int {
	if t.numeric && o.numeric {
		if len(t.digits) != len(o.digits) {
			return sign(len(t.digits) - len(o.digits))
		}
		return strings.Compare(t.digits, o.digits)
	}
	if r1, r2 := t.rank(), o.rank(); r1 != r2 {
		return sign(r1 - r2)
	}
	return strings.Compare(t.word, o.word)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// Valid reports whether v looks like a version number: it starts with a
// digit and has at most 40 characters of digits, letters, dots, dashes,
// underscores and plus signs.
func Valid(v string) bool {
	v = Normalize(v)
	if v == "" || len(v) > 40 || v[0] < '0' || v[0] > '9' {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '_' || r == '+') {
			return false
		}
	}
	return true
}
