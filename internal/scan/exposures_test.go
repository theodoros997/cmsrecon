package scan

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

// found returns the finding with an ID, or an empty one.
func found(r *Result, id string) Finding {
	if f := findingByID(r, id); f != nil {
		return *f
	}
	return Finding{}
}

const plainHome = `<html><head><meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="{{URL}}wp-content/themes/lab-child/style.css" /></head><body></body></html>`

func TestPassiveFindings(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", plainHome, "X-Powered-By", "PHP/7.4.33", "X-Content-Type-Options", "nosniff",
		"Content-Security-Policy", "frame-ancestors 'self'")
	r := runScan(t, options(f.URL(), cli.ModePassive))

	sh := found(r, idSecurityHeaders)
	if sh.Severity != SeverityInfo || !slices.Equal(sh.Data["missing"].([]string), []string{"Referrer-Policy"}) {
		// HSTS only counts over HTTPS; frame-ancestors stands for X-Frame-Options.
		t.Errorf("security headers = %+v", sh)
	}
	php := found(r, idPHPEndOfLife)
	if php.Severity != SeverityMedium || php.Title != "PHP 7.4 is end of life" || !strings.Contains(php.Entries[0], "ended on 2022-11-28") {
		t.Errorf("PHP end of life = %+v", php)
	}
	if php.Data["version"] != "7.4.33" || php.Evidence[0].Mode != modePassive {
		t.Errorf("PHP data = %v, evidence %+v", php.Data, php.Evidence)
	}

	// A supported branch, a branch newer than the table and a header
	// without a version are no finding.
	for _, header := range []string{"PHP/9.9.1", "PleskLin", "PHP"} {
		f := newFakeWP(t).addBaseSite()
		f.routes["/"] = respond(200, "text/html", plainHome, "X-Powered-By", header)
		if got := found(runScan(t, options(f.URL(), cli.ModePassive)), idPHPEndOfLife); got.ID != "" {
			t.Errorf("X-Powered-By: %s gave %+v", header, got)
		}
	}
}

func TestDisplayedErrors(t *testing.T) {
	page := func(body string) string {
		return `<html><head><meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="{{URL}}wp-content/themes/lab-child/style.css" /></head><body>` + body + `</body></html>`
	}
	f := newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", page("<br />\n<b>Warning</b>:  Undefined variable $x in <b>/var/www/html/wp-content/themes/lab-child/header.php</b> on line <b>12</b><br />\n"+
		`<div id="error"><p class="wpdberror"><strong>WordPress database error:</strong> [Table 'wp.wp_x' doesn't exist]</p></div>`))
	got := found(runScan(t, options(f.URL(), cli.ModePassive)), idDisplayedErrors)
	if got.Severity != SeverityMedium || len(got.Entries) != 2 || !strings.Contains(strings.Join(got.Entries, "\n"), "Warning in /var/www/html/wp-content/themes/lab-child/header.php") {
		t.Errorf("displayed errors = %+v", got)
	}

	// A post that writes about PHP errors has them escaped: no finding.
	f = newFakeWP(t).addBaseSite()
	f.routes["/"] = respond(200, "text/html", page("<pre>&lt;b&gt;Warning&lt;/b&gt;:  Undefined variable in &lt;b&gt;/var/www/x.php&lt;/b&gt; on line &lt;b&gt;12&lt;/b&gt;</pre><p>Warning: this plugin is in /var/www/x.php on line 3</p>"))
	if got := found(runScan(t, options(f.URL(), cli.ModePassive)), idDisplayedErrors); got.ID != "" {
		t.Errorf("a tutorial gave %+v", got)
	}
}

func TestSensitiveFiles(t *testing.T) {
	secret := "s3cr3t-value-never-shown"
	exposed := func(t *testing.T) *fakeWP {
		f := newFakeWP(t).addBaseSite()
		f.routes["/.git/HEAD"] = respond(200, "text/plain", "ref: refs/heads/production\n")
		f.routes["/.env"] = respond(200, "text/plain", "APP_ENV=production\nDB_HOST=localhost\nDB_PASSWORD="+secret+"\nexport MAIL_KEY = "+secret+"\n")
		f.routes["/info.php"] = respond(200, "text/html", `<html><head><title>PHP 8.1.2 - phpinfo()</title></head><body><h1 class="p">PHP Version 8.1.2</h1></body></html>`)
		f.routes["/error_log"] = respond(200, "text/plain", "[20-Oct-2026 10:00:00 UTC] PHP Warning:  Undefined variable in /home/site/public_html/wp-content/plugins/a/a.php on line 3\n")
		f.routes["/wp-admin/maint/repair.php"] = respond(200, "text/html", `<html><body><p class="step"><a class="button button-large" href="repair.php?repair=1">Repair Database</a></p></body></html>`)
		f.routes["/.svn/wc.db"] = respond(200, "application/octet-stream", "SQLite format 3\x00binary")
		f.routes["/.DS_Store"] = respond(200, "application/octet-stream", "\x00\x00\x00\x01Bud1\x00\x00")
		f.routes["/.htpasswd"] = respond(200, "text/plain", "admin:$apr1$abcdefgh$"+secret+"\nbob:{SHA}"+secret+"\n")
		f.routes["/adminer.php"] = respond(200, "text/html", `<html><head><title>Login - Adminer</title></head><body></body></html>`)
		f.routes["/.vscode/sftp.json"] = respond(200, "application/json", `{"name":"prod","host":"203.0.113.9","username":"deploy","password":"`+secret+`","remotePath":"/var/www"}`)
		f.routes["/backup.zip"] = respond(200, "application/zip", "PK\x03\x04"+strings.Repeat("x", 100))
		return f
	}

	f := exposed(t)
	r := runScan(t, options(f.URL(), cli.ModeMixed))
	for id, sev := range map[string]string{
		idGitRepository: SeverityHigh, idEnvFile: SeverityCritical, idPHPInfo: SeverityMedium,
		idPHPErrorLog: SeverityMedium, idDBRepair: SeverityMedium,
	} {
		if got := found(r, id); got.Severity != sev {
			t.Errorf("%s = %+v, want severity %s", id, got, sev)
		}
	}
	if git := found(r, idGitRepository); !slices.Contains(git.Entries, "Branch: production") {
		t.Errorf("git = %+v", git)
	}
	if env := found(r, idEnvFile); !strings.Contains(env.Entries[0], "DB_PASSWORD") || !strings.Contains(env.Entries[0], "MAIL_KEY") {
		t.Errorf("env = %+v", env)
	}
	// The rarer files are only tried with --aggressive.
	for _, id := range []string{idSVNRepository, idDSStore, idHtpasswd, idAdminer, idDeployConfig, idSiteArchive} {
		if got := found(r, id); got.ID != "" {
			t.Errorf("a default scan reported %s", id)
		}
	}
	for _, req := range f.requested() {
		if strings.Contains(req, ".svn") || strings.Contains(req, "adminer") || strings.Contains(req, "backup.zip") {
			t.Errorf("a default scan requested %s", req)
		}
	}

	f = exposed(t)
	o := options(f.URL(), cli.ModeMixed)
	o.Thorough = true
	r = runScan(t, o)
	for id, sev := range map[string]string{
		idSVNRepository: SeverityHigh, idDSStore: SeverityLow, idHtpasswd: SeverityHigh,
		idAdminer: SeverityMedium, idDeployConfig: SeverityHigh, idSiteArchive: SeverityHigh, idEnvFile: SeverityCritical,
	} {
		if got := found(r, id); got.Severity != sev {
			t.Errorf("--aggressive: %s = %+v, want severity %s", id, got, sev)
		}
	}
	// No secret value may reach the report, in any field.
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), "203.0.113.9") {
		t.Errorf("the report holds a value from an exposed file")
	}

	// A site that answers every path with a page has none of them.
	f = newFakeWP(t).addBaseSite()
	f.fallback = respond(200, "text/html", `<html><head><title>Welcome</title></head><body>DB_PASSWORD=x APP_KEY=y ref: refs/heads/main phpinfo() Adminer repair.php?repair=1</body></html>`)
	o = options(f.URL(), cli.ModeMixed)
	o.Thorough = true
	r = runScan(t, o)
	for _, id := range []string{idGitRepository, idEnvFile, idPHPInfo, idPHPErrorLog, idSVNRepository, idDSStore, idHtpasswd, idDeployConfig, idSiteArchive} {
		if got := found(r, id); got.ID != "" {
			t.Errorf("a catch-all page was reported as %s: %+v", id, got)
		}
	}
}
