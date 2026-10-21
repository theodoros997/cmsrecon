package corehash

import (
	"crypto/md5"
	"encoding/hex"
	"path/filepath"
	"slices"
	"testing"
)

// sample is a database of five releases and four files:
//
//	              6.3  6.4  6.4.1  6.4.2  6.5
//	a.js           h1   h2   h2     h2     h3
//	b.css          x1   x1   x2     x3     x3
//	c.js (admin)   y    y    y      y      y
//	readme.html    -    r    r      r      s
func sample() *DB {
	b := NewBuilder(nil)
	files := map[string][5]string{
		"wp-includes/js/a.js":   {"h1", "h2", "h2", "h2", "h3"},
		"wp-includes/css/b.css": {"x1", "x1", "x2", "x3", "x3"},
		"wp-admin/js/c.js":      {"y", "y", "y", "y", "y"},
		"readme.html":           {"", "r", "r", "r", "s"},
	}
	for i, v := range []string{"6.3", "6.4", "6.4.1", "6.4.2", "6.5"} {
		sums := map[string]string{"wp-includes/version.php": md5Of("php"), "wp-content/themes/x/style.css": md5Of("t")}
		for path, h := range files {
			if h[i] != "" {
				sums[path] = md5Of(h[i])
			}
		}
		b.Add(v, sums)
	}
	return b.DB()
}

func TestBuilderKeepsStaticFiles(t *testing.T) {
	db := sample()
	if !slices.Equal(db.Versions, []string{"6.3", "6.4", "6.4.1", "6.4.2", "6.5"}) {
		t.Errorf("versions = %v", db.Versions)
	}
	var paths []string
	for p := range db.Files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"readme.html", "wp-admin/js/c.js", "wp-includes/css/b.css", "wp-includes/js/a.js"}) {
		t.Errorf("paths = %v (no PHP, no wp-content)", paths)
	}

	// Write, read and rebuild: an update only adds new releases.
	file := filepath.Join(t.TempDir(), File)
	if err := Write(file, db); err != nil {
		t.Fatal(err)
	}
	back, err := Read(file)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(back)
	if !b.Has("6.4.1") || b.Has("6.6") || b.Len() != 5 {
		t.Errorf("rebuilt builder: has 6.4.1 %v, len %d", b.Has("6.4.1"), b.Len())
	}
	b.Add("6.6", map[string]string{"wp-includes/js/a.js": md5Of("h4")})
	again := b.DB()
	if len(again.Versions) != 6 || len(again.Files["wp-includes/css/b.css"]) != 3 {
		t.Errorf("after adding 6.6: %v, %v", again.Versions, again.Files["wp-includes/css/b.css"])
	}
}

func TestPickerNarrowsDown(t *testing.T) {
	db := sample()
	site := map[string]string{ // what a 6.4.2 site serves
		"wp-includes/js/a.js": md5Of("h2"), "wp-includes/css/b.css": md5Of("x3"), "wp-admin/js/c.js": md5Of("y"), "readme.html": md5Of("r"),
	}
	p := NewPicker(db)
	var asked []string
	for {
		path, ok := p.Next()
		if !ok {
			break
		}
		asked = append(asked, path)
		p.Observe(path, site[path])
	}
	if got := p.Candidates(); !slices.Equal(got, []string{"6.4.2"}) {
		t.Errorf("candidates = %v after %v", got, asked)
	}
	if len(asked) > 2 || slices.Contains(asked, "wp-admin/js/c.js") {
		t.Errorf("asked for %v: two files are enough, and c.js tells nothing", asked)
	}

	// A modified file changes nothing; a missing one is skipped.
	p = NewPicker(db)
	path, _ := p.Next()
	if p.Observe(path, md5Of("minified by a CDN")) || len(p.Candidates()) != 5 {
		t.Errorf("a modified file narrowed the versions: %v", p.Candidates())
	}
	if next, _ := p.Next(); next == path {
		t.Errorf("asked for %s twice", path)
	}
}

func TestParse(t *testing.T) {
	flat, err := ParseChecksums([]byte(`{"checksums":{"wp-includes/js/a.js":"0123456789abcdef0123456789abcdef"}}`), "6.4.2")
	if err != nil || flat["wp-includes/js/a.js"] == "" {
		t.Errorf("flat: %v %v", flat, err)
	}
	keyed, err := ParseChecksums([]byte(`{"checksums":{"6.4.2":{"readme.html":"0123456789abcdef0123456789abcdef"}}}`), "6.4.2")
	if err != nil || keyed["readme.html"] == "" {
		t.Errorf("keyed: %v %v", keyed, err)
	}
	none, err := ParseChecksums([]byte(`{"checksums":false}`), "2.0")
	if err != nil || none != nil {
		t.Errorf("false: %v %v", none, err)
	}
	rel, err := ParseReleases([]byte(`{"2.9.2":"insecure","3.0":"insecure","4.9.26":"outdated","6.4.10":"outdated","6.4.2":"insecure","6.6.2":"latest","6.7-beta1":"x"}`))
	if err != nil || !slices.Equal(rel, []string{"3.0", "4.9.26", "6.4.2", "6.4.10", "6.6.2"}) {
		t.Errorf("releases = %v %v", rel, err)
	}
}

func TestStatic(t *testing.T) {
	for p, want := range map[string]bool{
		"wp-includes/js/wp-embed.min.js": true, "wp-admin/css/login.min.css": true, "readme.html": true, "license.txt": true,
		"wp-includes/version.php": false, "wp-content/themes/twentytwenty/style.css": false, "wp-login.php": false,
		"wp-includes/../wp-config.php.js": false, "xmlrpc.php": false,
	} {
		if Static(p) != want {
			t.Errorf("Static(%q) = %v", p, !want)
		}
	}
}

func md5Of(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
