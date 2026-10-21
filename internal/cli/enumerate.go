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

// MaxIDRange caps how many IDs a range may hold: each is a request.
const MaxIDRange = 100000

// DefaultMediaIDs is the attachment ID range checked by a bare "m", as in
// WPScan.
var DefaultMediaIDs = IDRange{From: 1, To: 100}

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
	Timthumbs     bool
	Users         *IDRange // nil when users are not enumerated
	Media         *IDRange // nil when media are not enumerated
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
		case "tt":
			e.Timthumbs = true
		default:
			switch {
			case strings.HasPrefix(tok, "u"):
				r, err := parseIDRange(strings.TrimPrefix(tok, "u"), DefaultUserIDs)
				if err != nil {
					return e, fmt.Errorf("enumerate: users: %w", err)
				}
				e.Users = &r
			case strings.HasPrefix(tok, "m"):
				r, err := parseIDRange(strings.TrimPrefix(tok, "m"), DefaultMediaIDs)
				if err != nil {
					return e, fmt.Errorf("enumerate: media: %w", err)
				}
				e.Media = &r
			default:
				return e, fmt.Errorf("enumerate: unknown choice %q (valid: vp, p, ap, vt, t, at, tt, cb, dbe, bf, u[RANGE], m[RANGE])", tok)
			}
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

// parseIDRange parses "", "N" or "N-M". An empty string gives def.
func parseIDRange(s string, def IDRange) (IDRange, error) {
	if s == "" {
		return def, nil
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
	if hi-lo >= MaxIDRange {
		return IDRange{}, fmt.Errorf("invalid ID range %q: at most %d IDs, one request each", s, MaxIDRange)
	}
	return IDRange{From: lo, To: hi}, nil
}
