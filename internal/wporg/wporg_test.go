package wporg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
)

func TestParseVersions(t *testing.T) {
	got, err := ParseVersions([]byte(`{"name":"Akismet","version":"5.3.1","versions":{"5.3":"u","5.3.1":"u","5.10":"u","4.0-beta1":"u","trunk":"u","5.2.0":"u"}}`))
	if err != nil || !slices.Equal(got, []string{"5.10", "5.3.1", "5.3", "5.2.0"}) {
		t.Errorf("versions = %v, %v; want the stable releases, newest first", got, err)
	}
	// A plugin without tags lists none: only its current version is known.
	if got, _ = ParseVersions([]byte(`{"version":"1.4","versions":[]}`)); !slices.Equal(got, []string{"1.4"}) {
		t.Errorf("untagged plugin = %v", got)
	}
	if got, err = ParseVersions([]byte(`{"error":"Plugin not found."}`)); err != nil || got != nil {
		t.Errorf("not found = %v, %v", got, err)
	}
	if _, err = ParseVersions([]byte(`<html>`)); err == nil {
		t.Error("HTML is not an answer")
	}
}

func TestParseChecksums(t *testing.T) {
	got, err := ParseChecksums([]byte(`{"plugin":"x","version":"1.0","files":{
		"x.php":{"md5":"0cc175b9c0f1b6a831c399e269772661","sha256":"s"},
		"js/app.js":{"md5":"0CC175B9C0F1B6A831C399E269772661","sha256":"s"},
		"css/a.css":{"md5":["92eb5ffee6ae2fec3ad71c777531578f","4a8a08f09d37b73795649038408b5f33"],"sha256":["a","b"]},
		"readme.txt":{"md5":"not-a-hash"},
		"../etc/passwd.txt":{"md5":"0cc175b9c0f1b6a831c399e269772661"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !slices.Equal(got["js/app.js"], []string{"0cc175b9c0f1b6a831c399e269772661"}) || len(got["css/a.css"]) != 2 {
		t.Errorf("checksums = %v; want the static files with valid hashes", got)
	}
}

func TestClientCaches(t *testing.T) {
	var info, sums atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/info/there.json":
			info.Add(1)
			w.Write([]byte(`{"version":"1.1","versions":{"1.0":"u","1.1":"u"}}`))
		case "/sums/there/1.1.json":
			sums.Add(1)
			w.Write([]byte(`{"files":{"a.js":{"md5":"0cc175b9c0f1b6a831c399e269772661"}}}`))
		default:
			info.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	newClient := func() *Client {
		c := New(dir, nil, "test")
		c.InfoURL, c.ChecksumsURL = srv.URL+"/info/%s.json", srv.URL+"/sums/%s/%s.json"
		return c
	}
	ctx := context.Background()
	for range 3 {
		c := newClient() // a new scan each time: the cache is on disk
		if v, err := c.Versions(ctx, "There"); err != nil || !slices.Equal(v, []string{"1.1", "1.0"}) {
			t.Fatalf("versions = %v, %v", v, err)
		}
		if s, err := c.Checksums(ctx, "there", "1.1"); err != nil || len(s["a.js"]) != 1 {
			t.Fatalf("checksums = %v, %v", s, err)
		}
		if _, err := c.Versions(ctx, "premium-plugin"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a plugin WordPress.org does not host: %v", err)
		}
		if _, err := c.Checksums(ctx, "there", "9.9"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a release without checksums: %v", err)
		}
	}
	// One request for the plugin, one for the unknown plugin, one for the
	// release, one for the unknown release (counted with info).
	if info.Load() != 3 || sums.Load() != 1 {
		t.Errorf("%d information and %d checksum requests for three scans; the answers are cached", info.Load(), sums.Load())
	}
	for _, bad := range []string{"../x", "a b", ""} {
		if _, err := newClient().Versions(ctx, bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("slug %q: %v", bad, err)
		}
	}
}

func TestStatic(t *testing.T) {
	for path, want := range map[string]bool{
		"assets/app.js": true, "css/a.min.css": true, "readme.txt": true, "languages/x.pot": true,
		"plugin.php": false, "img/a.png": false, "../a.js": false, "/abs.js": false, "a b.js": false,
	} {
		if Static(path) != want {
			t.Errorf("Static(%q) = %v", path, !want)
		}
	}
}
