package scan

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/corehash"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// writeCoreHashes stores checksums of three releases whose two static
// files tell them apart, as "cmsrecon update" would.
func writeCoreHashes(t *testing.T, dir string) {
	t.Helper()
	b := corehash.NewBuilder(nil)
	b.Add("6.4.1", map[string]string{"wp-includes/js/wp-embed.min.js": md5Hex("embed-a"), "wp-includes/css/dashicons.min.css": md5Hex("dash-a")})
	b.Add("6.4.2", map[string]string{"wp-includes/js/wp-embed.min.js": md5Hex("embed-a"), "wp-includes/css/dashicons.min.css": md5Hex("dash-b")})
	b.Add("6.5", map[string]string{"wp-includes/js/wp-embed.min.js": md5Hex("embed-b"), "wp-includes/css/dashicons.min.css": md5Hex("dash-b")})
	if err := corehash.Write(filepath.Join(dir, corehash.File), b.DB()); err != nil {
		t.Fatal(err)
	}
}

func TestCoreVersionFromFileHashes(t *testing.T) {
	f := newFakeWP(t).addBaseSite() // its pages say 6.4.2
	f.routes["/wp-includes/js/wp-embed.min.js"] = respond(200, "application/javascript", "embed-a")
	f.routes["/wp-includes/css/dashicons.min.css"] = respond(200, "text/css", "dash-b")
	o := options(f.URL(), cli.ModeMixed)
	o.DataDir = t.TempDir()
	writeCoreHashes(t, o.DataDir)
	r := runScan(t, o)

	if r.Version.Number != "6.4.2" || r.Version.Confidence != 100 {
		t.Errorf("version = %s (%d%%)", r.Version.Number, r.Version.Confidence)
	}
	if !slices.Contains(methods(r.Version.Evidence), "File hashes") {
		t.Errorf("evidence = %v", methods(r.Version.Evidence))
	}
	var hashed int
	for _, req := range f.requested() {
		if strings.Contains(req, "wp-embed.min.js") || strings.Contains(req, "dashicons.min.css") {
			hashed++
		}
	}
	if hashed != 2 {
		t.Errorf("%d core files downloaded, want 2", hashed)
	}

	t.Run("passive mode downloads nothing", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		o := options(f.URL(), cli.ModePassive)
		o.DataDir = t.TempDir()
		writeCoreHashes(t, o.DataDir)
		runScan(t, o)
		for _, req := range f.requested() {
			if strings.Contains(req, "wp-embed") || strings.Contains(req, "dashicons") {
				t.Errorf("passive mode requested %s", req)
			}
		}
	})

	t.Run("blocked files give up quickly", func(t *testing.T) {
		f := newFakeWP(t).addBaseSite()
		f.routes["/wp-includes/js/wp-embed.min.js"] = respond(403, "text/html", "<h1>Forbidden</h1>")
		f.routes["/wp-includes/css/dashicons.min.css"] = respond(200, "text/css", "/* minified by a CDN */")
		o := options(f.URL(), cli.ModeMixed)
		o.DataDir = t.TempDir()
		writeCoreHashes(t, o.DataDir)
		r := runScan(t, o)
		if slices.Contains(methods(r.Version.Evidence), "File hashes") || r.Version.Number != "6.4.2" {
			t.Errorf("version = %+v", r.Version)
		}
	})
}

func TestHashEvidence(t *testing.T) {
	found := &Version{Number: "6.4.2", Confidence: 92}
	one := hashEvidence([]string{"6.4.2"}, "u", found)
	if len(one) != 1 || one[0].Confidence != 100 {
		t.Errorf("one release: %+v", one)
	}
	confirms := hashEvidence([]string{"6.4.2", "6.4.3"}, "u", found)
	if len(confirms) != 1 || confirms[0].Value != "6.4.2" || confirms[0].Confidence != 90 {
		t.Errorf("two releases, one of them found: %+v", confirms)
	}
	few := hashEvidence([]string{"6.4.2", "6.4.3"}, "u", &Version{})
	if len(few) != 2 || few[0].Confidence != 50 {
		t.Errorf("two releases, nothing found: %+v", few)
	}
	if v := combineVersions(few); v.Number == "" {
		t.Errorf("two candidates at 50%% still give a version: %+v", v)
	}
	if hashEvidence([]string{"1", "2", "3", "4", "5"}, "u", found) != nil {
		t.Error("five releases are too vague")
	}
}

const timthumbError = `<pre><h1>A TimThumb error has occured</h1>The following error(s) occured:<br /><ul><li>No image specified</li></ul><br /><br />Query String : <br />TimThumb version : %s</pre>`

func TestTimthumbs(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	f.routes["/wp-content/themes/twentytwenty/timthumb.php"] = respond(400, "text/html", fmt.Sprintf(timthumbError, "1.33"))
	f.routes["/wp-content/plugins/contact-form-7/lib/timthumb.php"] = respond(400, "text/html", fmt.Sprintf(timthumbError, "2.8.13"))
	f.routes["/wp-content/plugins/wordpress-seo/thumb.php"] = respond(400, "text/html", fmt.Sprintf(timthumbError, "2.8.14"))
	f.routes["/timthumb.php"] = respond(200, "text/html", "<html><body>Welcome to the lab</body></html>") // a catch-all page
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = cli.Enumeration{Timthumbs: true}
	o.DataDir = writeData(t)
	r := runScan(t, o)

	byURL := map[string]*Timthumb{}
	for _, tt := range r.Timthumbs {
		byURL[strings.TrimPrefix(tt.URL, f.URL())] = tt
	}
	if len(byURL) != 3 {
		t.Fatalf("timthumbs = %v", byURL)
	}
	verdicts := func(tt *Timthumb) []string {
		var out []string
		for _, v := range tt.Vulnerabilities {
			out = append(out, v.CVE[0]+" "+v.Verdict)
		}
		return out
	}
	if v := verdicts(byURL["wp-content/themes/twentytwenty/timthumb.php"]); !slices.Equal(v, []string{"CVE-2011-4106 confirmed"}) {
		t.Errorf("1.33: %v", v)
	}
	if v := verdicts(byURL["wp-content/plugins/contact-form-7/lib/timthumb.php"]); !slices.Equal(v, []string{"CVE-2014-4663 likely"}) {
		t.Errorf("2.8.13: %v (WebShot is off by default)", v)
	}
	if v := verdicts(byURL["wp-content/plugins/wordpress-seo/thumb.php"]); len(v) != 0 {
		t.Errorf("2.8.14: %v", v)
	}
	if r.VulnerabilityCounts.Confirmed < 1 || r.VulnerabilityCounts.Likely < 1 {
		t.Errorf("timthumb vulnerabilities are counted: %+v", r.VulnerabilityCounts)
	}

	t.Run("off by default", func(t *testing.T) {
		f := newFakeWP(t).addComponentSite()
		runScan(t, options(f.URL(), cli.ModeMixed))
		for _, req := range f.requested() {
			if strings.Contains(req, "thumb.php") {
				t.Errorf("requested %s without -e tt", req)
			}
		}
	})
}

func TestMedia(t *testing.T) {
	t.Run("REST API", func(t *testing.T) {
		f := newFakeWP(t).addComponentSite()
		f.routes["/wp-json/wp/v2/media"] = respond(200, "application/json", `[
 {"id": 12, "source_url": "{{URL}}wp-content/uploads/2026/10/report.pdf", "mime_type": "application/pdf", "link": "{{URL}}report/", "title": {"rendered": "Q3 report &amp; notes"}},
 {"id": 7, "source_url": "{{URL}}wp-content/uploads/2026/09/photo.jpg", "mime_type": "image/jpeg", "link": "{{URL}}photo/", "title": {"rendered": "photo"}},
 {"id": 8, "source_url": "javascript:alert(1)", "mime_type": "image/png", "title": {"rendered": "odd"}}]`, "X-WP-TotalPages", "1")
		o := options(f.URL(), cli.ModeMixed)
		o.Enumerate = cli.Enumeration{Media: &cli.IDRange{From: 1, To: 20}}
		r := runScan(t, o)
		if len(r.Media) != 2 || r.Media[0].ID != 7 || r.Media[1].Title != "Q3 report & notes" || r.Media[1].MimeType != "application/pdf" {
			t.Fatalf("media = %+v (sorted by ID, without the entry that has no http link)", r.Media)
		}
		for _, req := range f.requested() {
			if strings.Contains(req, "attachment_id") {
				t.Errorf("the REST API listed the media, yet %s was requested", req)
			}
		}
	})

	t.Run("attachment IDs", func(t *testing.T) {
		f := newFakeWP(t).addComponentSite()
		f.routes["/wp-json/wp/v2/media"] = respond(401, "application/json", `{"code":"rest_forbidden"}`)
		f.routes["/?attachment_id=2"] = redirect(301, "{{URL}}wp-content/uploads/2026/10/report.pdf")
		f.routes["/?attachment_id=3"] = respond(200, "text/html", `<html><body class="attachment attachment-template-default single single-attachment postid-3 attachmentid-3 attachment-png">
<p class="attachment"><a href="{{URL}}wp-content/uploads/2026/10/diagram.png"><img src="{{URL}}wp-content/uploads/2026/10/diagram-300x200.png" /></a></p></body></html>`)
		f.routes["/?attachment_id=4"] = redirect(302, "{{URL}}")
		f.routes["/?attachment_id=5"] = respond(200, "text/html", `<html><body class="home blog">Home</body></html>`)
		o := options(f.URL(), cli.ModeMixed)
		o.Enumerate = cli.Enumeration{Media: &cli.IDRange{From: 1, To: 6}}
		r := runScan(t, o)
		if len(r.Media) != 2 {
			t.Fatalf("media = %+v", r.Media)
		}
		if m := r.Media[0]; m.ID != 2 || m.URL != f.URL()+"wp-content/uploads/2026/10/report.pdf" || m.PageURL != "" {
			t.Errorf("redirect to the file: %+v", m)
		}
		if m := r.Media[1]; m.ID != 3 || m.URL != f.URL()+"wp-content/uploads/2026/10/diagram.png" || m.PageURL == "" {
			t.Errorf("attachment page: %+v", m)
		}
	})
}

func TestExploitsAttachedToVulnerabilities(t *testing.T) {
	f := newFakeWP(t).addComponentSite()
	o := options(f.URL(), cli.ModeMixed)
	o.DataDir = writeData(t)
	x := vulndb.NewExploitIndex()
	x.Add("CVE-2020-35489", vulndb.Exploit{Source: vulndb.ExploitGitHub, URL: "https://github.com/a/poc", Title: "a/poc"})
	x.Add("CVE-2020-35489", vulndb.Exploit{Source: vulndb.ExploitMetasploit, URL: "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/x.rb", Ref: "exploit/x"})
	x.Add("CVE-2020-11022", vulndb.Exploit{Source: vulndb.ExploitDB, URL: "https://www.exploit-db.com/exploits/49766"})
	if err := vulndb.WriteExploits(filepath.Join(o.DataDir, vulndb.ExploitsFile), x); err != nil {
		t.Fatal(err)
	}
	r := runScan(t, o)

	cf7 := pluginBySlug(r, "contact-form-7")
	if cf7 == nil || len(cf7.Vulnerabilities) != 1 {
		t.Fatalf("contact-form-7 = %+v", cf7)
	}
	es := cf7.Vulnerabilities[0].Exploits
	if len(es) != 2 || es[0].Source != vulndb.ExploitMetasploit || es[1].Source != vulndb.ExploitGitHub {
		t.Errorf("exploits = %+v (Metasploit first)", es)
	}
	if !slices.ContainsFunc(r.VulnerabilityData.Sources, func(s DataSource) bool { return s.Name == "exploits" && s.Entries == 2 }) {
		t.Errorf("data sources = %+v", r.VulnerabilityData.Sources)
	}
}
