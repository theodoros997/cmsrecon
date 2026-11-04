package httpclient

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestResolveConnectsToTheGivenAddress checks --resolve and --vhost: the
// request goes to the given address, with the site's name as Host.
func TestResolveConnectsToTheGivenAddress(t *testing.T) {
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	// site.invalid never resolves: only the --resolve entry can reach it.
	o := options(t, "http://site.invalid:"+port+"/")
	o.Resolve = map[string]string{"site.invalid": "127.0.0.1"}
	c := newClient(t, o)
	res, err := c.Get(context.Background(), "http://site.invalid:"+port+"/")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || host != "site.invalid:"+port {
		t.Errorf("status %d, Host %q", res.StatusCode, host)
	}
}

func TestLogRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	log := filepath.Join(t.TempDir(), "requests.tsv")
	o := options(t, srv.URL)
	o.LogRequests = log
	c := newClient(t, o)
	for _, p := range []string{"/", "/missing"} {
		if _, err := c.Get(context.Background(), srv.URL+p); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("log =\n%s", data)
	}
	for i, want := range [][]string{{"GET", "200", "5", srv.URL + "/"}, {"GET", "404", "", srv.URL + "/missing"}} {
		f := strings.Split(lines[i], "\t")
		if len(f) != 7 || f[1] != want[0] || f[2] != want[1] || f[5] != want[3] || want[2] != "" && f[3] != want[2] {
			t.Errorf("log line %d = %q, want %v", i, lines[i], want)
		}
	}
	if info, err := os.Stat(log); err == nil && info.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Errorf("the request log should be private, mode %v", info.Mode().Perm())
	}
	// Close is safe to call twice.
	if err := c.Close(); err != nil {
		t.Error(err)
	}
}
