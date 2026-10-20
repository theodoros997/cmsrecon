package update

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

const wordfenceFeed = `{"a1": {"id": "a1", "title": "Contact Form 7 <= 5.3.1 - Unrestricted File Upload",
 "software": [{"type": "plugin", "slug": "contact-form-7", "affected_versions": {"* - 5.3.1": {"from_version": "*", "from_inclusive": true, "to_version": "5.3.1", "to_inclusive": true}}, "patched": true, "patched_versions": ["5.3.2"]}],
 "informational": false, "references": [], "cve": "CVE-2020-35489", "cvss": {"score": 10, "rating": "Critical"}, "published": "2020-12-17 00:00:00"}}`

const cveRecord = `{"cveMetadata": {"cveId": "CVE-2020-11738", "state": "PUBLISHED"},
 "containers": {"cna": {"descriptions": [{"lang": "en", "value": "The Duplicator plugin before 1.3.28 for WordPress allows Directory Traversal."}],
  "affected": [{"product": "Duplicator", "vendor": "Snap Creek", "versions": [{"version": "0", "lessThan": "1.3.28", "status": "affected"}]}],
  "references": [{"url": "https://wordpress.org/plugins/duplicator/"}]}}}`

const retireRepo = `{"jquery": {"extractors": {"filename": ["jquery-(§§version§§)(\\.min)?\\.js"]},
 "vulnerabilities": [{"below": "3.5.0", "severity": "medium", "identifiers": {"summary": "XSS", "CVE": ["CVE-2020-11022"]}}]}}`

// upstream fakes every data source.
type upstream struct {
	srv        *httptest.Server
	cveZip     []byte
	cveFetches atomic.Int32
	fail       map[string]bool // paths that answer 500
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{fail: map[string]bool{}}
	var inner bytes.Buffer
	zw := zip.NewWriter(&inner)
	w, _ := zw.Create("cves/2020/11xxx/CVE-2020-11738.json")
	w.Write([]byte(cveRecord))
	zw.Close()
	var outer bytes.Buffer
	zw = zip.NewWriter(&outer)
	w, _ = zw.Create("cves.zip")
	w.Write(inner.Bytes())
	zw.Close()
	u.cveZip = outer.Bytes()

	mux := http.NewServeMux()
	mux.HandleFunc("/wordfence", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good-key" {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, wordfenceFeed)
	})
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name": "cve_2026-10-20_0000Z", "assets": [
		 {"name": "2026-10-20_delta_CVEs_at_0000Z.zip", "browser_download_url": "%[1]s/delta.zip", "size": 10},
		 {"name": "2026-10-20_all_CVEs_at_midnight.zip.zip", "browser_download_url": "%[1]s/all.zip", "size": %[2]d}]}`, u.srv.URL, len(u.cveZip))
	})
	mux.HandleFunc("/all.zip", func(w http.ResponseWriter, r *http.Request) {
		u.cveFetches.Add(1)
		w.Write(u.cveZip)
	})
	mux.HandleFunc("/plugins-api", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "query_plugins" || r.URL.Query().Get("request[browse]") != "popular" {
			http.Error(w, "bad request", 400)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("request[page]"))
		fmt.Fprintf(w, `{"info": {"page": %d, "pages": 2, "results": 3}, "plugins": [`, page)
		if page == 1 {
			fmt.Fprint(w, `{"slug": "akismet", "name": "Akismet", "version": "5.3", "active_installs": 5000000, "last_updated": "2026-09-30 3:04pm GMT"}, {"slug": "contact-form-7", "name": "Contact Form 7", "version": "6.1"}`)
		} else {
			fmt.Fprint(w, `{"slug": "duplicator", "version": "1.5.7"}`)
		}
		fmt.Fprint(w, `]}`)
	})
	mux.HandleFunc("/core-api", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"offers": [{"response": "upgrade", "current": "6.6.2", "version": "6.6.2"}], "translations": []}`)
	})
	mux.HandleFunc("/themes-api", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"info": {"page": 1, "pages": 1}, "themes": [{"slug": "astra", "name": "Astra", "version": "4.8.3"}]}`)
	})
	mux.HandleFunc("/plugins-svn/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><h2>Revision 1: /</h2><ul><li><a href="../">..</a></li><li><a href="akismet/">akismet/</a></li><li><a href="contact-form-7/">contact-form-7/</a></li><li><a href="zzz-obscure/">zzz-obscure/</a></li></ul></body></html>`)
	})
	mux.HandleFunc("/themes-svn/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<ul><li><a href="astra/">astra/</a></li><li><a href="twentytwenty/">twentytwenty/</a></li></ul>`)
	})
	mux.HandleFunc("/retire.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, retireRepo)
	})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u.fail[r.URL.Path] {
			http.Error(w, "upstream down", 500)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) endpoints() Endpoints {
	return Endpoints{
		Wordfence: u.srv.URL + "/wordfence", CVERelease: u.srv.URL + "/release",
		CoreAPI: u.srv.URL + "/core-api", PluginsAPI: u.srv.URL + "/plugins-api", ThemesAPI: u.srv.URL + "/themes-api",
		PluginsSVN: u.srv.URL + "/plugins-svn/", ThemesSVN: u.srv.URL + "/themes-svn/",
		RetireJS: u.srv.URL + "/retire.json", PopularPlugins: 10, PopularThemes: 10,
	}
}

func TestSourcesMatchTheCommandLine(t *testing.T) {
	if !slices.Equal(AllSources, cli.UpdateSources) {
		t.Errorf("update sources %v differ from the CLI's %v", AllSources, cli.UpdateSources)
	}
}

func TestRunDownloadsEverySource(t *testing.T) {
	up := newUpstream(t)
	dir := t.TempDir()
	var log bytes.Buffer
	o := Options{DataDir: dir, Sources: AllSources, WordfenceKey: "good-key", Endpoints: up.endpoints(), Log: &log}
	results, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v\n%+v", err, results)
	}
	if len(results) != 4 {
		t.Fatalf("results = %+v", results)
	}
	for _, r := range results {
		if r.Err != nil || r.Skipped || r.Summary == "" {
			t.Errorf("%s: %+v", r.Source, r)
		}
	}

	db, err := vulndb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Sources) != 2 {
		t.Fatalf("sources = %+v", db.Sources)
	}
	if ms := db.Match(vulndb.KindPlugin, "contact-form-7", vulndb.Detected{Version: "5.3.1", Confidence: 90}); len(ms) != 1 {
		t.Errorf("contact-form-7 matches = %v", ms)
	}
	if ms := db.Match(vulndb.KindPlugin, "duplicator", vulndb.Detected{Version: "1.3.26", Confidence: 90}); len(ms) != 1 {
		t.Errorf("duplicator matches = %v", ms)
	}

	lists, err := wordlists.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if lists.PopularPlugins[0] != "akismet" || lists.Latest(wordlists.Plugins, "duplicator") != "1.5.7" || lists.Latest(wordlists.Themes, "astra") != "4.8.3" {
		t.Errorf("popular = %v, duplicator latest %q", lists.PopularPlugins[:3], lists.Latest(wordlists.Plugins, "duplicator"))
	}
	if lists.LastUpdated(wordlists.Plugins, "akismet") != "2026-09-30" || lists.LastUpdated(wordlists.Plugins, "contact-form-7") != "" {
		t.Errorf("last updated = %q", lists.LastUpdated(wordlists.Plugins, "akismet"))
	}
	if lists.CoreLatest != "6.6.2" {
		t.Errorf("core latest = %q", lists.CoreLatest)
	}
	if !slices.Equal(lists.AllPlugins, []string{"akismet", "contact-form-7", "zzz-obscure"}) || len(lists.AllThemes) != 2 {
		t.Errorf("all plugins = %v, themes = %v", lists.AllPlugins, lists.AllThemes)
	}

	js, err := vulndb.LoadJSRepo(dir)
	if err != nil || !js.HasVulnerabilityData() || len(js.Advisories("jquery")) != 1 {
		t.Errorf("retire.js: %v", err)
	}

	// A second run reuses the CVE List release it already has.
	results, err = Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceCVE}, Endpoints: up.endpoints()})
	if err != nil || !strings.Contains(results[0].Summary, "already up to date") || up.cveFetches.Load() != 1 {
		t.Errorf("second run: %v %+v, %d downloads", err, results, up.cveFetches.Load())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestRunReportsEachSource(t *testing.T) {
	up := newUpstream(t)
	dir := t.TempDir()

	results, err := Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceWordfence, SourceRetire}, Endpoints: up.endpoints()})
	if err != nil || !results[0].Skipped || !strings.Contains(results[0].Summary, "WORDFENCE_API_KEY") || results[1].Err != nil {
		t.Errorf("no key: %v %+v", err, results)
	}

	results, err = Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceWordfence}, WordfenceKey: "bad", Endpoints: up.endpoints()})
	if err == nil || results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "rejected") {
		t.Errorf("bad key: %v %+v", err, results)
	}

	// A failing source does not stop the others, and keeps no partial file.
	up.fail["/themes-svn/"] = true
	results, err = Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceWPOrg, SourceRetire}, Endpoints: up.endpoints()})
	if err == nil || results[0].Err == nil || results[1].Err != nil {
		t.Errorf("partial failure: %v %+v", err, results)
	}
	if _, err := os.Stat(filepath.Join(dir, wordlists.AllThemesFile)); !os.IsNotExist(err) {
		t.Errorf("themes list written despite the failure: %v", err)
	}
}
