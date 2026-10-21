// Package corehash tells the WordPress core version from the hashes of its
// static files. "cmsrecon update" builds the database from the checksums
// WordPress.org publishes for every release; a scan downloads a few
// scripts and stylesheets from wp-includes and wp-admin, picking at each
// step the file that best splits the versions still possible, and keeps
// the versions whose files match.
package corehash

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/theodoros997/cmsrecon/internal/fsutil"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// File is the database in the data directory.
const File = "corehashes.json.gz"

// MinVersion is the oldest release kept: older ones are rarely seen and
// WordPress.org has no checksums for some of them.
const MinVersion = "3.0"

// DB maps the static files of every release to their MD5 hashes.
type DB struct {
	UpdatedAt time.Time `json:"updated_at"`
	// Versions are sorted oldest first; Files refers to them by index.
	Versions []string `json:"versions"`
	// Files maps a path ("wp-includes/js/wp-embed.min.js") to its hashes,
	// each with the versions that ship it.
	Files map[string]map[string][]int `json:"files"`
}

var md5Re = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Static reports whether a release file can be fetched as-is from a site:
// the scripts and stylesheets of wp-includes and wp-admin, readme.html and
// license.txt. PHP files run instead of being served, and wp-content is the
// site's own.
func Static(path string) bool {
	if path == "readme.html" || path == "license.txt" {
		return true
	}
	if !strings.HasPrefix(path, "wp-includes/") && !strings.HasPrefix(path, "wp-admin/") {
		return false
	}
	if strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\ ") {
		return false
	}
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css")
}

// Builder accumulates releases before they are indexed.
type Builder struct {
	byVersion map[string]map[string]string // version -> path -> md5
}

// NewBuilder returns a builder holding the releases of db, if any, so an
// update only needs the releases that came out since.
func NewBuilder(db *DB) *Builder {
	b := &Builder{byVersion: map[string]map[string]string{}}
	if db == nil {
		return b
	}
	for path, hashes := range db.Files {
		for sum, idx := range hashes {
			for _, i := range idx {
				if i < 0 || i >= len(db.Versions) {
					continue
				}
				b.add(db.Versions[i], path, sum)
			}
		}
	}
	// A release with no static file is still known.
	for _, v := range db.Versions {
		if b.byVersion[v] == nil {
			b.byVersion[v] = map[string]string{}
		}
	}
	return b
}

func (b *Builder) add(version, path, sum string) {
	m := b.byVersion[version]
	if m == nil {
		m = map[string]string{}
		b.byVersion[version] = m
	}
	m[path] = sum
}

// Has reports whether the builder holds a release.
func (b *Builder) Has(version string) bool { return b.byVersion[version] != nil }

// Add records the checksums of one release, keeping only static files.
func (b *Builder) Add(version string, checksums map[string]string) {
	m := map[string]string{}
	for path, sum := range checksums {
		sum = strings.ToLower(sum)
		if Static(path) && md5Re.MatchString(sum) {
			m[path] = sum
		}
	}
	b.byVersion[version] = m
}

// Len is the number of releases held.
func (b *Builder) Len() int { return len(b.byVersion) }

// DB indexes the releases held.
func (b *Builder) DB() *DB {
	db := &DB{UpdatedAt: time.Now().UTC(), Files: map[string]map[string][]int{}}
	for v := range b.byVersion {
		db.Versions = append(db.Versions, v)
	}
	slices.SortFunc(db.Versions, vulndb.Compare)
	for i, v := range db.Versions {
		for path, sum := range b.byVersion[v] {
			hashes := db.Files[path]
			if hashes == nil {
				hashes = map[string][]int{}
				db.Files[path] = hashes
			}
			hashes[sum] = append(hashes[sum], i)
		}
	}
	return db
}

// ParseChecksums reads a WordPress.org core checksums answer:
// {"checksums": {"path": "md5", …}}, or the same keyed by version.
// It returns nil, without error, when WordPress.org has no checksums for
// the release ("checksums": false).
func ParseChecksums(data []byte, version string) (map[string]string, error) {
	var resp struct {
		Checksums json.RawMessage `json:"checksums"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	if len(resp.Checksums) == 0 || string(resp.Checksums) == "false" || string(resp.Checksums) == "null" {
		return nil, nil
	}
	var flat map[string]string
	if err := json.Unmarshal(resp.Checksums, &flat); err == nil {
		return flat, nil
	}
	var byVersion map[string]map[string]string
	if err := json.Unmarshal(resp.Checksums, &byVersion); err != nil {
		return nil, fmt.Errorf("unexpected checksums format: %w", err)
	}
	return byVersion[version], nil
}

// ParseReleases reads WordPress.org's stable-check list, {"6.4.2":
// "outdated", …}, and returns the releases since MinVersion, oldest first.
func ParseReleases(data []byte) ([]string, error) {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	var out []string
	for v := range m {
		if releaseRe.MatchString(v) && vulndb.Compare(v, MinVersion) >= 0 {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no releases in the list")
	}
	slices.SortFunc(out, vulndb.Compare)
	return out, nil
}

var releaseRe = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

// Write stores the database, gzipped.
func Write(path string, db *DB) error {
	return fsutil.WriteAtomic(path, func(w *os.File) error {
		gz := gzip.NewWriter(w)
		if err := json.NewEncoder(gz).Encode(db); err != nil {
			return err
		}
		return gz.Close()
	})
}

// Read reads a file written by Write.
func Read(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var db DB
	if err := json.NewDecoder(gz).Decode(&db); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &db, nil
}

// Load reads the database from the data directory; nil when there is none.
func Load(dir string) (*DB, error) {
	db, err := Read(filepath.Join(dir, File))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return db, err
}

// Picker chooses which files to download, one at a time, and narrows the
// possible versions with each hash.
type Picker struct {
	db    *DB
	cands []bool // indexed like db.Versions
	n     int    // how many are true
	tried map[string]bool
	paths []string
}

// NewPicker starts with every version possible.
func NewPicker(db *DB) *Picker {
	p := &Picker{db: db, cands: make([]bool, len(db.Versions)), n: len(db.Versions), tried: map[string]bool{}}
	for i := range p.cands {
		p.cands[i] = true
	}
	for path := range db.Files {
		p.paths = append(p.paths, path)
	}
	slices.Sort(p.paths) // ties go to the same file on every run
	return p
}

// cost is a penalty for files that tend to be large (the block editor's
// bundles, TinyMCE) or blocked (wp-admin), as a share of the candidates.
func cost(path string) float64 {
	c := 0.0
	if strings.Contains(path, "/dist/") || strings.Contains(path, "/tinymce/") || strings.Contains(path, "/codemirror/") {
		c += 0.05
	}
	if strings.HasPrefix(path, "wp-admin/") {
		c += 0.02
	}
	return c
}

// Next returns the file whose hash is expected to leave the fewest
// versions, or false when no file would narrow them down.
func (p *Picker) Next() (string, bool) {
	if p.n <= 1 {
		return "", false
	}
	best, bestScore := "", float64(p.n)
	for _, path := range p.paths {
		if p.tried[path] {
			continue
		}
		present := 0
		sumSq := 0
		for _, idx := range p.db.Files[path] {
			k := 0
			for _, i := range idx {
				if p.cands[i] {
					k++
				}
			}
			present += k
			sumSq += k * k
		}
		if present == 0 {
			continue
		}
		// A matching hash leaves its versions; no match (the file is
		// missing, blocked or modified) leaves all of them.
		n := float64(p.n)
		score := float64(sumSq)/n + float64(p.n-present)
		score += cost(path) * n
		if score < bestScore-1e-9 {
			best, bestScore = path, score
		}
	}
	return best, best != ""
}

// Observe records the hash of a downloaded file and reports whether it
// matched a release. A hash that matches no remaining version (a modified
// or minified copy) changes nothing.
func (p *Picker) Observe(path, sum string) bool {
	p.tried[path] = true
	idx, ok := p.db.Files[path][strings.ToLower(sum)]
	if !ok {
		return false
	}
	keep := make([]bool, len(p.cands))
	n := 0
	for _, i := range idx {
		if p.cands[i] {
			keep[i] = true
			n++
		}
	}
	if n == 0 {
		return false
	}
	p.cands, p.n = keep, n
	return true
}

// Skip marks a file as tried without a hash (not found, blocked).
func (p *Picker) Skip(path string) { p.tried[path] = true }

// Candidates returns the versions still possible, oldest first.
func (p *Picker) Candidates() []string {
	var out []string
	for i, ok := range p.cands {
		if ok {
			out = append(out, p.db.Versions[i])
		}
	}
	return out
}
