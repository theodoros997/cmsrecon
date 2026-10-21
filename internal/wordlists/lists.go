// Package wordlists holds the plugin and theme slugs cmsrecon brute-forces
// and the passive signatures that reveal plugins without a request. The
// built-in popular lists are used until "cmsrecon update" downloads fresh
// ones from WordPress.org into the data directory.
package wordlists

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theodoros997/cmsrecon/internal/fsutil"
)

// Kinds of lists.
const (
	Plugins = "plugin"
	Themes  = "theme"
)

// Files in the data directory, written by "cmsrecon update".
const (
	WPOrgFile      = "wordpress-org.json.gz" // popular slugs with their latest versions
	AllPluginsFile = "plugins.txt.gz"        // every plugin slug in the WordPress.org SVN
	AllThemesFile  = "themes.txt.gz"         // every theme slug in the WordPress.org SVN
)

var (
	//go:embed data/popular-plugins.txt
	builtinPopularPlugins string
	//go:embed data/premium-plugins.txt
	builtinPremiumPlugins string
	//go:embed data/popular-themes.txt
	builtinPopularThemes string
	//go:embed data/premium-themes.txt
	builtinPremiumThemes string
)

// Item is a plugin or theme in the WordPress.org directory.
type Item struct {
	Slug           string `json:"slug"`
	Name           string `json:"name,omitempty"`
	Version        string `json:"version,omitempty"` // the latest release
	ActiveInstalls int    `json:"active_installs,omitempty"`
	LastUpdated    string `json:"last_updated,omitempty"` // YYYY-MM-DD
}

// WPOrg is the WordPress.org metadata "cmsrecon update" stores.
type WPOrg struct {
	UpdatedAt  time.Time `json:"updated_at"`
	CoreLatest string    `json:"core_latest,omitempty"` // the latest WordPress release
	Plugins    []Item    `json:"plugins"`               // most installed first
	Themes     []Item    `json:"themes"`                // most popular first
}

// Lists are the slugs a scan brute-forces and what it knows about them.
type Lists struct {
	PopularPlugins []string // popular WordPress.org plugins, then premium ones
	PopularThemes  []string
	AllPlugins     []string // nil until "cmsrecon update" has run
	AllThemes      []string
	UpdatedAt      time.Time // when the WordPress.org data was downloaded; zero for the built-in lists
	CoreLatest     string    // the latest WordPress release, when downloaded

	latest  map[string]string // kind/slug -> latest version
	updated map[string]string // kind/slug -> last updated, YYYY-MM-DD
	names   map[string]string // kind/slug -> name on WordPress.org
	known   map[string]bool   // kind/slug of every listed slug
	popular map[string]bool   // kind/slug of the popular and premium slugs
}

// Builtin returns the lists compiled into cmsrecon.
func Builtin() *Lists {
	l := &Lists{latest: map[string]string{}, updated: map[string]string{}, names: map[string]string{}, known: map[string]bool{}, popular: map[string]bool{}}
	l.PopularPlugins = mergeSlugs(lines(builtinPopularPlugins), lines(builtinPremiumPlugins))
	l.PopularThemes = mergeSlugs(lines(builtinPopularThemes), lines(builtinPremiumThemes))
	l.index()
	return l
}

// Load returns the lists from dir, falling back to the built-in ones for
// whatever "cmsrecon update" has not downloaded. Premium slugs, which
// WordPress.org does not list, are always added to the popular lists.
func Load(dir string) (*Lists, error) {
	l := Builtin()
	var errs []error

	if w, err := ReadWPOrg(filepath.Join(dir, WPOrgFile)); err == nil {
		l.UpdatedAt, l.CoreLatest = w.UpdatedAt, w.CoreLatest
		if len(w.Plugins) > 0 {
			l.PopularPlugins = mergeSlugs(itemSlugs(w.Plugins), lines(builtinPremiumPlugins))
		}
		if len(w.Themes) > 0 {
			l.PopularThemes = mergeSlugs(itemSlugs(w.Themes), lines(builtinPremiumThemes))
		}
		for kind, items := range map[string][]Item{Plugins: w.Plugins, Themes: w.Themes} {
			for _, it := range items {
				k := kind + "/" + strings.ToLower(it.Slug)
				if it.Version != "" {
					l.latest[k] = it.Version
				}
				if it.LastUpdated != "" {
					l.updated[k] = it.LastUpdated
				}
				if it.Name != "" {
					l.names[k] = it.Name
				}
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	for _, f := range []struct {
		name string
		dst  *[]string
	}{{AllPluginsFile, &l.AllPlugins}, {AllThemesFile, &l.AllThemes}} {
		slugs, err := ReadSlugs(filepath.Join(dir, f.name))
		switch {
		case err == nil:
			*f.dst = slugs
		case !errors.Is(err, fs.ErrNotExist):
			errs = append(errs, err)
		}
	}
	l.index()
	return l, errors.Join(errs...)
}

func (l *Lists) index() {
	l.popular = map[string]bool{}
	for _, s := range l.PopularPlugins {
		l.known[Plugins+"/"+strings.ToLower(s)] = true
		l.popular[Plugins+"/"+strings.ToLower(s)] = true
	}
	for _, s := range l.AllPlugins {
		l.known[Plugins+"/"+strings.ToLower(s)] = true
	}
	for _, s := range l.PopularThemes {
		l.known[Themes+"/"+strings.ToLower(s)] = true
		l.popular[Themes+"/"+strings.ToLower(s)] = true
	}
	for _, s := range l.AllThemes {
		l.known[Themes+"/"+strings.ToLower(s)] = true
	}
}

// Latest returns the latest version of a plugin or theme on WordPress.org,
// or "" when it is not in the downloaded metadata.
func (l *Lists) Latest(kind, slug string) string {
	return l.latest[kind+"/"+strings.ToLower(slug)]
}

// LastUpdated returns when a plugin or theme was last updated on
// WordPress.org (YYYY-MM-DD), or "" when it is not in the downloaded data.
func (l *Lists) LastUpdated(kind, slug string) string {
	return l.updated[kind+"/"+strings.ToLower(slug)]
}

// Name returns the name WordPress.org gives a plugin or theme, or "" when
// it is not in the downloaded data.
func (l *Lists) Name(kind, slug string) string {
	return l.names[kind+"/"+strings.ToLower(slug)]
}

// Popular reports whether a slug is in the popular or premium list.
func (l *Lists) Popular(kind, slug string) bool {
	return l.popular[kind+"/"+strings.ToLower(slug)]
}

// Known reports whether a slug is in any list.
func (l *Lists) Known(kind, slug string) bool {
	return l.known[kind+"/"+strings.ToLower(slug)]
}

func itemSlugs(items []Item) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Slug)
	}
	return out
}

// mergeSlugs concatenates slug lists without duplicates, keeping the first
// spelling of each slug.
func mergeSlugs(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, s := range list {
			k := strings.ToLower(s)
			if s == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// WriteWPOrg stores WordPress.org metadata as gzipped JSON.
func WriteWPOrg(path string, w *WPOrg) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(w); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, buf.Bytes())
}

// ReadWPOrg reads a file written by WriteWPOrg.
func ReadWPOrg(path string) (*WPOrg, error) {
	r, closeFn, err := openGzip(path)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	var w WPOrg
	if err := json.NewDecoder(r).Decode(&w); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &w, nil
}

// WriteSlugs stores a slug list, one per line, gzipped.
func WriteSlugs(path string, slugs []string) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for _, s := range slugs {
		fmt.Fprintln(gz, s)
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, buf.Bytes())
}

// ReadSlugs reads a file written by WriteSlugs.
func ReadSlugs(path string) ([]string, error) {
	r, closeFn, err := openGzip(path)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func openGzip(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return gz, func() { f.Close() }, nil
}
