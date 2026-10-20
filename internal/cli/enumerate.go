package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// DefaultEnumeration is used when -e/--enumerate is not given.
const DefaultEnumeration = "vp,vt,cb,dbe,bf,u"

// DefaultUserIDs is the author ID range checked by a bare "u".
var DefaultUserIDs = IDRange{From: 1, To: 10}

// ItemSet selects which plugin or theme slugs are brute-forced.
type ItemSet int

const (
	ItemsNone       ItemSet = iota
	ItemsVulnerable         // slugs with at least one known vulnerability
	ItemsPopular            // most installed slugs on WordPress.org
	ItemsAll                // every slug on WordPress.org
)

func (s ItemSet) String() string {
	switch s {
	case ItemsVulnerable:
		return "vulnerable"
	case ItemsPopular:
		return "popular"
	case ItemsAll:
		return "all"
	default:
		return "none"
	}
}

// IDRange is an inclusive range of numeric IDs, e.g. author IDs.
type IDRange struct {
	From, To int
}

func (r IDRange) String() string {
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// Enumeration is the parsed form of -e/--enumerate.
type Enumeration struct {
	Plugins       ItemSet
	Themes        ItemSet
	ConfigBackups bool
	DBExports     bool
	BackupFolders bool
	Users         *IDRange // nil when users are not enumerated
}

// planned lists WPScan choices that are on the roadmap but not built yet.
var planned = map[string]string{
	"m":  "media enumeration",
	"tt": "timthumb enumeration",
}

// ParseEnumeration parses a comma-separated enumeration spec such as
// "vp,vt,cb,dbe,bf,u1-20". "none" or an empty spec enumerates nothing.
func ParseEnumeration(spec string) (Enumeration, error) {
	var e Enumeration
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "none") {
		return e, nil
	}

	for _, tok := range strings.Split(spec, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch tok {
		case "":
			continue
		case "vp", "p", "ap":
			if e.Plugins != ItemsNone {
				return e, fmt.Errorf("enumerate: vp, p and ap are mutually exclusive")
			}
			e.Plugins = itemSetFor(tok)
		case "vt", "t", "at":
			if e.Themes != ItemsNone {
				return e, fmt.Errorf("enumerate: vt, t and at are mutually exclusive")
			}
			e.Themes = itemSetFor(tok)
		case "cb":
			e.ConfigBackups = true
		case "dbe":
			e.DBExports = true
		case "bf":
			e.BackupFolders = true
		default:
			if what, ok := planned[tok]; ok {
				return e, fmt.Errorf("enumerate: %q (%s) is not supported yet", tok, what)
			}
			if !strings.HasPrefix(tok, "u") {
				return e, fmt.Errorf("enumerate: unknown choice %q (valid: vp, p, ap, vt, t, at, cb, dbe, bf, u[RANGE])", tok)
			}
			r, err := parseIDRange(strings.TrimPrefix(tok, "u"))
			if err != nil {
				return e, fmt.Errorf("enumerate: users: %w", err)
			}
			e.Users = &r
		}
	}
	return e, nil
}

func itemSetFor(tok string) ItemSet {
	switch tok[0] {
	case 'v':
		return ItemsVulnerable
	case 'a':
		return ItemsAll
	default:
		return ItemsPopular
	}
}

// parseIDRange parses "", "N" or "N-M". An empty string gives DefaultUserIDs.
func parseIDRange(s string) (IDRange, error) {
	if s == "" {
		return DefaultUserIDs, nil
	}
	from, to, isRange := strings.Cut(s, "-")
	lo, err := strconv.Atoi(from)
	if err != nil {
		return IDRange{}, fmt.Errorf("invalid ID range %q", s)
	}
	hi := lo
	if isRange {
		if hi, err = strconv.Atoi(to); err != nil {
			return IDRange{}, fmt.Errorf("invalid ID range %q", s)
		}
	}
	if lo < 1 || hi < lo {
		return IDRange{}, fmt.Errorf("invalid ID range %q: IDs start at 1 and the end must not be below the start", s)
	}
	return IDRange{From: lo, To: hi}, nil
}
