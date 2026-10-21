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
	"github.com/theodoros997/cmsrecon/internal/corehash"
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

const exploitDBCSV = "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n" +
	`49294,exploits/php/webapps/49294.py,"WordPress Plugin Contact Form 7 5.3.1 - Unrestricted File Upload",2020-12-21,x,webapps,php,,2020-12-21,2020-12-21,1,CVE-2020-35489,,,,,` + "\n" +
	`50000,exploits/php/webapps/50000.txt,"Something without a CVE",2021-01-01,x,webapps,php,,2021-01-01,2021-01-01,0,OSVDB-1,,,,,` + "\n"

const metasploitJSON = `{"exploit_multi/http/wp_cf7": {"name": "CF7 upload", "fullname": "exploit/multi/http/wp_cf7", "type": "exploit",
 "path": "/modules/exploits/multi/http/wp_cf7.rb", "references": ["CVE-2020-35489", "URL-https://example.com"]},
 "post_x": {"name": "Post module", "fullname": "post/x", "type": "post", "path": "/modules/post/x.rb", "references": ["CVE-2020-35489"]}}`

const nucleiJSON = `{"ID":"CVE-2020-35489","Info":{"Name":"Contact Form 7 - Unrestricted File Upload","Severity":"critical"},"file_path":"http/cves/2020/CVE-2020-35489.yaml"}
not json
`

const pocReadme = "# PoC in GitHub\n\n## 2020\n### CVE-2020-35489 (2020-12-17)\n\n<code>The contact-form-7 plugin...\n</code>\n\n" +
	"- [someone/CVE-2020-35489](https://github.com/someone/CVE-2020-35489)\n- [bad](https://github.com/x/y/../../z)\n\n### CVE-2021-0001 (2021-01-01)\n- [a/b](https://github.com/a/b)\n"

// upstream fakes every data source.
type upstream struct {
	srv          *httptest.Server
	cveZip       []byte
	cveFetches   atomic.Int32
	checksumAsks atomic.Int32
	fail         map[string]bool // paths that answer 500
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
	mux.HandleFunc("/edb.csv", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, exploitDBCSV) })
	mux.HandleFunc("/msf.json", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, metasploitJSON) })
	mux.HandleFunc("/nuclei.json", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, nucleiJSON) })
	mux.HandleFunc("/poc.md", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, pocReadme) })
	mux.HandleFunc("/stable-check", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"2.9.2": "insecure", "3.0": "insecure", "6.4.2": "insecure", "6.6.2": "latest"}`)
	})
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, r *http.Request) {
		u.checksumAsks.Add(1)
		if r.URL.Query().Get("locale") != "en_US" {
			http.Error(w, "locale", 400)
			return
		}
		switch r.URL.Query().Get("version") {
		case "3.0":
			fmt.Fprint(w, `{"checksums": false}`)
		case "6.4.2":
			fmt.Fprint(w, `{"checksums": {"wp-includes/js/wp-embed.min.js": "11111111111111111111111111111111", "wp-includes/version.php": "22222222222222222222222222222222"}}`)
		case "6.6.2":
			fmt.Fprint(w, `{"checksums": {"wp-includes/js/wp-embed.min.js": "33333333333333333333333333333333", "readme.html": "44444444444444444444444444444444"}}`)
		default:
			http.Error(w, "unknown version", 404)
		}
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
		ExploitDB: u.srv.URL + "/edb.csv", Metasploit: u.srv.URL + "/msf.json", Nuclei: u.srv.URL + "/nuclei.json", PoCInGitHub: u.srv.URL + "/poc.md",
		CoreStable: u.srv.URL + "/stable-check", CoreChecksums: u.srv.URL + "/checksums",
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
	if len(results) != len(AllSources) {
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

	x, err := vulndb.LoadExploits(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range x.Lookup([]string{"CVE-2020-35489"}) {
		got = append(got, e.Source+" "+e.URL)
	}
	want := []string{
		"metasploit https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/wp_cf7.rb",
		"exploitdb https://www.exploit-db.com/exploits/49294",
		"nuclei https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35489.yaml",
		"github https://github.com/someone/CVE-2020-35489",
	}
	if !slices.Equal(got, want) {
		t.Errorf("exploits = %q\nwant %q", got, want)
	}
	if es := x.Lookup([]string{"CVE-2020-35489"}); !es[1].Verified || es[0].Ref != "exploit/multi/http/wp_cf7" {
		t.Errorf("exploit details = %+v", es)
	}

	hashes, err := corehash.Load(dir)
	if err != nil || hashes == nil {
		t.Fatalf("core hashes: %v", err)
	}
	if !slices.Equal(hashes.Versions, []string{"3.0", "6.4.2", "6.6.2"}) || len(hashes.Files) != 2 || len(hashes.Files["wp-includes/js/wp-embed.min.js"]) != 2 {
		t.Errorf("core hashes = %v %v", hashes.Versions, hashes.Files)
	}
	asks := up.checksumAsks.Load()

	// A second run reuses the CVE List release it already has.
	results, err = Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceCVE}, Endpoints: up.endpoints()})
	if err != nil || !strings.Contains(results[0].Summary, "already up to date") || up.cveFetches.Load() != 1 {
		t.Errorf("second run: %v %+v, %d downloads", err, results, up.cveFetches.Load())
	}
	// ... and only asks for the checksums of new releases.
	results, err = Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceCoreHash}, Endpoints: up.endpoints()})
	if err != nil || !strings.Contains(results[0].Summary, "already up to date (3 releases)") || up.checksumAsks.Load() != asks {
		t.Errorf("second core hashes run: %v %+v, %d asks", err, results, up.checksumAsks.Load()-asks)
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

func TestExploitsKeepFailedParts(t *testing.T) {
	up := newUpstream(t)
	dir := t.TempDir()
	if _, err := Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceExploits}, Endpoints: up.endpoints()}); err != nil {
		t.Fatal(err)
	}
	up.fail["/poc.md"] = true
	results, err := Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceExploits}, Endpoints: up.endpoints()})
	if err == nil || results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "PoC-in-GitHub") || results[0].Summary == "" {
		t.Errorf("partial failure: %v %+v", err, results)
	}
	x, err := vulndb.LoadExploits(dir)
	if err != nil {
		t.Fatal(err)
	}
	if es := x.Lookup([]string{"CVE-2021-0001"}); len(es) != 1 || es[0].Source != vulndb.ExploitGitHub {
		t.Errorf("the GitHub entries of the previous index are kept: %+v", es)
	}

	// Every part failing keeps the previous file untouched.
	for _, p := range []string{"/edb.csv", "/msf.json", "/nuclei.json"} {
		up.fail[p] = true
	}
	if results, err := Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceExploits}, Endpoints: up.endpoints()}); err == nil || results[0].Summary != "" {
		t.Errorf("total failure: %v %+v", err, results)
	}
	if x, _ := vulndb.LoadExploits(dir); len(x.Lookup([]string{"CVE-2020-35489"})) == 0 {
		t.Error("the previous index was lost")
	}
}

func TestCoreHashesRetryFailedReleases(t *testing.T) {
	up := newUpstream(t)
	dir := t.TempDir()
	up.fail["/checksums"] = true
	results, err := Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceCoreHash}, Endpoints: up.endpoints()})
	if err == nil || results[0].Err == nil {
		t.Errorf("every release failing: %v %+v", err, results)
	}
	delete(up.fail, "/checksums")
	results, err = Run(context.Background(), Options{DataDir: dir, Sources: []string{SourceCoreHash}, Endpoints: up.endpoints()})
	if err != nil || !strings.Contains(results[0].Summary, "3 releases") {
		t.Errorf("retry: %v %+v", err, results)
	}
}
