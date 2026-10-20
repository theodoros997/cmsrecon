// Package vulndb holds the offline vulnerability data cmsrecon matches
// against: WordPress core, plugin and theme vulnerabilities from the
// Wordfence Intelligence feed and the CVE List, and JavaScript library
// vulnerabilities from the retire.js repository. "cmsrecon update" writes
// the files; a scan reads them and never contacts the data providers.
package vulndb

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/theodoros997/cmsrecon/internal/fsutil"
)

// Kinds of software a vulnerability affects.
const (
	KindCore   = "core"
	KindPlugin = "plugin"
	KindTheme  = "theme"
)

// CoreSlug is the slug core vulnerabilities are stored under.
const CoreSlug = "wordpress"

// Sources of vulnerability data, in priority order.
const (
	SourceWordfence = "wordfence"
	SourceCVE       = "cve"
)

// Files in the data directory.
const (
	WordfenceFile = "wordfence.json.gz"
	CVEFile       = "cve.json.gz"
)

// SourceLabel is the name of a source for people.
func SourceLabel(source string) string {
	switch source {
	case SourceWordfence:
		return "Wordfence"
	case SourceCVE:
		return "CVE List"
	}
	return source
}

// Vuln is one vulnerability of one piece of software, as one source
// describes it.
type Vuln struct {
	ID         string   `json:"id"` // the source's ID: a Wordfence UUID or a CVE ID
	Title      string   `json:"title"`
	Kind       string   `json:"kind"`                   // core, plugin or theme
	Slug       string   `json:"slug"`                   // "wordpress" for core
	Guessed    bool     `json:"slug_guessed,omitempty"` // the slug was derived from the product name
	Affected   []Range  `json:"affected"`
	Fixed      []string `json:"fixed,omitempty"`   // versions that fix it
	Unfixed    bool     `json:"unfixed,omitempty"` // the source says no fix exists
	CVE        []string `json:"cve,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	CVSSVector string   `json:"cvss_vector,omitempty"`
	Severity   string   `json:"severity,omitempty"` // critical, high, medium or low
	CWE        string   `json:"cwe,omitempty"`      // e.g. "CWE-79 Cross-site Scripting"
	References []string `json:"references,omitempty"`
	Published  string   `json:"published,omitempty"` // YYYY-MM-DD
}

// SourceFile is what "cmsrecon update" stores for one source.
type SourceFile struct {
	Source          string    `json:"source"`
	UpdatedAt       time.Time `json:"updated_at"`
	Release         string    `json:"release,omitempty"` // the upstream release the data came from, when it has one
	Vulnerabilities []*Vuln   `json:"vulnerabilities"`
}

// WriteSource stores f as gzipped JSON. The file is replaced atomically, so
// an interrupted update keeps the previous data.
func WriteSource(path string, f *SourceFile) error {
	return fsutil.WriteAtomic(path, func(w *os.File) error {
		gz := gzip.NewWriter(w)
		if err := json.NewEncoder(gz).Encode(f); err != nil {
			return err
		}
		return gz.Close()
	})
}

// ReadSource reads a file written by WriteSource.
func ReadSource(path string) (*SourceFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var sf SourceFile
	if err := json.NewDecoder(gz).Decode(&sf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &sf, nil
}

// Advisory is one vulnerability of one piece of software, merged across
// the sources that describe it. The first source is the primary one: its
// affected ranges decide the verdict, the others are a cross-check.
type Advisory struct {
	Title      string
	Kind       string
	Slug       string
	CVE        []string
	CVSS       float64
	CVSSVector string
	Severity   string
	CWE        string
	Fixed      []string
	Unfixed    bool
	References []string
	Published  string
	Guessed    bool // the slug was derived from a product name, not given by the source
	Sources    []SourceRanges
}

// SourceRanges is what one source says is affected.
type SourceRanges struct {
	Source   string
	ID       string
	Affected []Range
}

// SourceInfo describes a loaded source file.
type SourceInfo struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
	Entries   int       `json:"entries"`
	Release   string    `json:"release,omitempty"`
}

// DB is the merged vulnerability data for WordPress core, plugins and
// themes.
type DB struct {
	Sources []SourceInfo
	byKey   map[string][]*Advisory // kind + "/" + slug
	byCVE   map[string][]*Advisory
}

// Open loads the source files found in dir. Missing files are skipped: a
// directory without any gives an empty database. A file that cannot be
// read is reported in the error, and the other sources are still loaded.
func Open(dir string) (*DB, error) {
	var files []*SourceFile
	var errs []error
	for _, name := range []string{WordfenceFile, CVEFile} {
		f, err := ReadSource(filepath.Join(dir, name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			errs = append(errs, err)
		default:
			files = append(files, f)
		}
	}
	return New(files...), errors.Join(errs...)
}

// New merges source files into a database. Files are merged in priority
// order: Wordfence first, then the CVE List, whatever order they are given
// in.
func New(files ...*SourceFile) *DB {
	db := &DB{byKey: map[string][]*Advisory{}, byCVE: map[string][]*Advisory{}}
	files = slices.Clone(files)
	sort.SliceStable(files, func(i, j int) bool { return sourceRank(files[i].Source) < sourceRank(files[j].Source) })
	for _, f := range files {
		db.Sources = append(db.Sources, SourceInfo{Name: f.Source, UpdatedAt: f.UpdatedAt, Entries: len(f.Vulnerabilities), Release: f.Release})
		for _, v := range f.Vulnerabilities {
			db.add(f.Source, v)
		}
	}
	return db
}

func sourceRank(s string) int {
	switch s {
	case SourceWordfence:
		return 0
	case SourceCVE:
		return 1
	}
	return 2
}

func key(kind, slug string) string { return kind + "/" + strings.ToLower(slug) }

// add merges v into the database. A vulnerability whose CVE is already
// known from a higher-priority source becomes a cross-check of that
// advisory, even under another slug: the higher-priority source's slug is
// the one trusted.
func (db *DB) add(source string, v *Vuln) {
	sr := SourceRanges{Source: source, ID: v.ID, Affected: v.Affected}
	merged := false
	for _, cve := range v.CVE {
		for _, a := range db.byCVE[cve] {
			if a.Kind != v.Kind || hasSource(a, source) {
				continue
			}
			a.Sources = append(a.Sources, sr)
			a.References = appendUnique(a.References, v.References...)
			if a.CVSS == 0 && v.CVSS > 0 {
				a.CVSS, a.CVSSVector, a.Severity = v.CVSS, v.CVSSVector, v.Severity
			}
			if a.CWE == "" {
				a.CWE = v.CWE
			}
			merged = true
		}
	}
	if merged {
		return
	}
	a := &Advisory{
		Title: v.Title, Kind: v.Kind, Slug: strings.ToLower(v.Slug), CVE: v.CVE, CVSS: v.CVSS,
		CVSSVector: v.CVSSVector, Severity: v.Severity, CWE: v.CWE, Fixed: v.Fixed, Unfixed: v.Unfixed,
		References: v.References, Published: v.Published, Guessed: v.Guessed, Sources: []SourceRanges{sr},
	}
	k := key(a.Kind, a.Slug)
	db.byKey[k] = append(db.byKey[k], a)
	for _, cve := range v.CVE {
		db.byCVE[cve] = append(db.byCVE[cve], a)
	}
}

func hasSource(a *Advisory, source string) bool {
	for _, s := range a.Sources {
		if s.Source == source {
			return true
		}
	}
	return false
}

func appendUnique(list []string, more ...string) []string {
	for _, m := range more {
		if !slices.Contains(list, m) {
			list = append(list, m)
		}
	}
	return list
}

// Empty reports whether no source was loaded.
func (db *DB) Empty() bool { return db == nil || len(db.Sources) == 0 }

// Advisories returns the advisories of one piece of software.
func (db *DB) Advisories(kind, slug string) []*Advisory {
	if db == nil {
		return nil
	}
	return db.byKey[key(kind, slug)]
}

// Slugs returns the sorted slugs of the given kind that have at least one
// advisory: the "vulnerable plugins" and "vulnerable themes" lists. Slugs
// only guessed from product names are left out.
func (db *DB) Slugs(kind string) []string {
	if db == nil {
		return nil
	}
	var out []string
	prefix := kind + "/"
	for k, advs := range db.byKey {
		slug, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		for _, a := range advs {
			if !a.Guessed {
				out = append(out, slug)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// OldestUpdate returns the update time of the oldest loaded source.
func (db *DB) OldestUpdate() time.Time {
	var t time.Time
	for _, s := range db.Sources {
		if t.IsZero() || s.UpdatedAt.Before(t) {
			t = s.UpdatedAt
		}
	}
	return t
}

// SeverityFromScore maps a CVSS base score to a severity.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}

// normalizeSeverity maps the rating words sources use to cmsrecon's
// severities.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}
