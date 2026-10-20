package vulndb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RetireURL is the retire.js vulnerability repository.
const RetireURL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"

// RetireFile is where "cmsrecon update" stores the retire.js repository.
const RetireFile = "jsrepository.json"

// SourceRetire names the retire.js repository as a vulnerability source.
const SourceRetire = "retirejs"

// KindJS is the advisory kind of JavaScript library vulnerabilities.
const KindJS = "js"

// versionPattern replaces retire.js's version placeholder.
const versionPattern = `[0-9][0-9.a-z_\-]+`

// JSRepo detects JavaScript libraries and their versions, and holds the
// libraries' vulnerabilities when the retire.js repository is loaded.
type JSRepo struct {
	libs      []*jsLibrary
	byName    map[string]*jsLibrary
	UpdatedAt time.Time // when the retire.js repository was downloaded; zero without it
}

type jsLibrary struct {
	name     string
	uri      []*regexp.Regexp // matched against the whole URL
	filename []*regexp.Regexp // matched against the file name
	content  []*regexp.Regexp // matched against the file
	verPath  []*regexp.Regexp // URL paths whose ?ver= is the library version
	vulns    []*Advisory
}

// JSDetection is a library found in a URL or a file.
type JSDetection struct {
	Library string
	Version string // empty when the URL names the library but not its version
	Method  string // one of the JSMethod constants
}

// How a library was detected.
const (
	JSMethodURL      = "uri" // the version is in the URL path
	JSMethodFilename = "filename"
	JSMethodContent  = "content" // a version banner in the file
	JSMethodVer      = "ver"     // ?ver= on a file named like the library
	JSMethodName     = "name"    // a file named like the library, no version
)

// retireEntry is one library of the retire.js repository.
type retireEntry struct {
	Extractors struct {
		URI         []string `json:"uri"`
		Filename    []string `json:"filename"`
		FileContent []string `json:"filecontent"`
	} `json:"extractors"`
	Vulnerabilities []struct {
		AtOrAbove   string   `json:"atOrAbove"`
		Below       string   `json:"below"`
		Severity    string   `json:"severity"`
		CWE         []string `json:"cwe"`
		Info        []string `json:"info"`
		Identifiers struct {
			Summary string   `json:"summary"`
			CVE     []string `json:"CVE"`
			GHSA    string   `json:"githubID"`
		} `json:"identifiers"`
	} `json:"vulnerabilities"`
}

// LoadJSRepo returns the built-in library patterns merged with the
// retire.js repository in dir, if "cmsrecon update" downloaded it.
func LoadJSRepo(dir string) (*JSRepo, error) {
	r := builtinJSRepo()
	p := filepath.Join(dir, RetireFile)
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err := r.addRetire(data); err != nil {
		return r, fmt.Errorf("%s: %w", p, err)
	}
	if fi, err := os.Stat(p); err == nil {
		r.UpdatedAt = fi.ModTime().UTC()
	}
	return r, nil
}

// ParseJSRepo returns the built-in patterns merged with a retire.js
// repository.
func ParseJSRepo(data []byte) (*JSRepo, error) {
	r := builtinJSRepo()
	return r, r.addRetire(data)
}

// ValidateRetire checks that data is a retire.js repository.
func ValidateRetire(data []byte) error {
	var entries map[string]retireEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("no libraries")
	}
	return nil
}

func (r *JSRepo) library(name string) *jsLibrary {
	k := strings.ToLower(name)
	if l, ok := r.byName[k]; ok {
		return l
	}
	l := &jsLibrary{name: name}
	r.byName[k] = l
	r.libs = append(r.libs, l)
	return l
}

func (r *JSRepo) addRetire(data []byte) error {
	var entries map[string]retireEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "retire-example" || name == "dont check" {
			continue
		}
		e := entries[name]
		l := r.library(name)
		l.uri = append(l.uri, compileRetire(e.Extractors.URI)...)
		l.filename = append(l.filename, compileRetire(e.Extractors.Filename)...)
		l.content = append(l.content, compileRetire(e.Extractors.FileContent)...)
		for i, v := range e.Vulnerabilities {
			a := &Advisory{
				Title:      v.Identifiers.Summary,
				Kind:       KindJS,
				Slug:       l.name,
				CVE:        v.Identifiers.CVE,
				Severity:   normalizeSeverity(v.Severity),
				References: v.Info,
				Sources: []SourceRanges{{
					Source: SourceRetire,
					ID:     name + "#" + strconv.Itoa(i),
					Affected: []Range{{
						From: v.AtOrAbove, FromInclusive: v.AtOrAbove != "",
						To: v.Below,
					}},
				}},
			}
			if len(v.CWE) > 0 {
				a.CWE = v.CWE[0]
			}
			if v.Below != "" {
				a.Fixed = []string{v.Below}
			}
			if a.Title == "" {
				switch {
				case len(v.Identifiers.CVE) > 0:
					a.Title = v.Identifiers.CVE[0] + " in " + l.name
				case v.Identifiers.GHSA != "":
					a.Title = v.Identifiers.GHSA + " in " + l.name
				default:
					a.Title = "Vulnerability in " + l.name
				}
			}
			if v.Identifiers.GHSA != "" {
				a.References = append(a.References, "https://github.com/advisories/"+v.Identifiers.GHSA)
			}
			l.vulns = append(l.vulns, a)
		}
	}
	return nil
}

var bigRepeatRe = regexp.MustCompile(`\{(\d+),(\d+)\}`)

// compileRetire compiles retire.js patterns for Go's regexp engine. Repeat
// counts above Go's limit of 1000 are opened up; patterns that still do
// not compile (backreferences, lookaround) are skipped.
func compileRetire(patterns []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range patterns {
		p = strings.ReplaceAll(p, "§§version§§", versionPattern)
		p = bigRepeatRe.ReplaceAllStringFunc(p, func(s string) string {
			m := bigRepeatRe.FindStringSubmatch(s)
			lo, _ := strconv.Atoi(m[1])
			hi, _ := strconv.Atoi(m[2])
			if hi <= 1000 {
				return s
			}
			return "{" + strconv.Itoa(min(lo, 1000)) + ",}"
		})
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

// FromURL finds libraries named in a script or stylesheet URL.
func (r *JSRepo) FromURL(u *url.URL) []JSDetection {
	full := u.String()
	file := path.Base(u.Path)
	ver := u.Query().Get("ver")
	var out []JSDetection
	for _, l := range r.libs {
		if v := firstVersion(l.uri, full); v != "" {
			out = append(out, JSDetection{l.name, v, JSMethodURL})
			continue
		}
		if v := firstVersion(l.filename, file); v != "" {
			out = append(out, JSDetection{l.name, v, JSMethodFilename})
			continue
		}
		for _, re := range l.verPath {
			if !re.MatchString(u.Path) {
				continue
			}
			if Valid(ver) && strings.Contains(ver, ".") {
				out = append(out, JSDetection{l.name, Normalize(ver), JSMethodVer})
			} else {
				out = append(out, JSDetection{l.name, "", JSMethodName})
			}
			break
		}
	}
	return out
}

// FromContent finds libraries by the version banners in a file.
func (r *JSRepo) FromContent(body []byte) []JSDetection {
	body = body[:min(len(body), 2<<20)]
	var out []JSDetection
	for _, l := range r.libs {
		for _, re := range l.content {
			m := re.FindSubmatch(body)
			if m == nil || len(m) < 2 {
				continue
			}
			if v := cleanVersion(string(m[1])); v != "" {
				out = append(out, JSDetection{l.name, v, JSMethodContent})
				break
			}
		}
	}
	return out
}

func firstVersion(res []*regexp.Regexp, s string) string {
	for _, re := range res {
		if m := re.FindStringSubmatch(s); len(m) > 1 {
			if v := cleanVersion(m[1]); v != "" {
				return v
			}
		}
	}
	return ""
}

// cleanVersion trims the trailing dots and dashes a version pattern can
// swallow ("3.6.0." in "jquery-3.6.0.min.js") and rejects versions without
// a dot.
func cleanVersion(v string) string {
	v = strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(v, ".min"), ".js"), ".-_")
	if !Valid(v) || !strings.Contains(v, ".") {
		return ""
	}
	return Normalize(v)
}

// HasVulnerabilityData reports whether the retire.js repository is loaded.
func (r *JSRepo) HasVulnerabilityData() bool { return !r.UpdatedAt.IsZero() }

// Advisories returns the known vulnerabilities of a library.
func (r *JSRepo) Advisories(library string) []*Advisory {
	if l, ok := r.byName[strings.ToLower(library)]; ok {
		return l.vulns
	}
	return nil
}
