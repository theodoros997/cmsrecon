package scan

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// Finding IDs of the checks in this file. They are part of the JSON
// format.
const (
	idSecurityHeaders = "security-headers"
	idPHPEndOfLife    = "php-end-of-life"
	idDisplayedErrors = "displayed-errors"
	idGitRepository   = "git-repository"
	idEnvFile         = "env-file"
	idPHPInfo         = "phpinfo"
	idPHPErrorLog     = "php-error-log"
	idDBRepair        = "db-repair-page"
	idSVNRepository   = "svn-repository"
	idDSStore         = "ds-store"
	idHtpasswd        = "htpasswd"
	idAdminer         = "adminer"
	idDeployConfig    = "deploy-config"
	idSiteArchive     = "site-archive"
)

// securityHeader is a response header browsers act on.
type securityHeader struct {
	name, why string
}

var securityHeaders = []securityHeader{
	{"Strict-Transport-Security", "browsers may still load the site over plain HTTP"},
	{"X-Frame-Options", "other sites can show the pages in a frame (clickjacking)"},
	{"X-Content-Type-Options", "browsers may guess the type of uploaded files (MIME sniffing)"},
	{"Content-Security-Policy", "nothing limits which scripts an injected page can load"},
	{"Referrer-Policy", "full URLs are sent to other sites as the referrer"},
}

// checkSecurityHeaders lists the security headers the homepage does not
// send. It reads the answer the scan already has.
func (s *Scanner) checkSecurityHeaders(context.Context) []Finding {
	if !s.passive() {
		return nil
	}
	h := s.home.resp.Header
	var missing, entries []string
	for _, sh := range securityHeaders {
		switch {
		case h.Get(sh.name) != "":
			continue
		case sh.name == "Strict-Transport-Security" && s.base.Scheme != "https":
			continue // it only means something over HTTPS
		case sh.name == "X-Frame-Options" && strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors"):
			continue // the modern way to say the same
		}
		missing = append(missing, sh.name)
		entries = append(entries, sh.name+": "+sh.why)
	}
	if len(missing) == 0 {
		return nil
	}
	ev := Evidence{Method: "Homepage response headers", Mode: modePassive, URL: s.base.String(), Confidence: 100}
	f := finding(idSecurityHeaders, "Security headers are missing", SeverityInfo, s.base.String(), ev, entries...)
	f[0].Data = map[string]any{"missing": missing}
	return f
}

// phpEndOfLife is the day security support of each PHP branch ended or
// ends, from php.net's supported versions page. Branches older than the
// first are long past theirs.
var phpEndOfLife = map[string]string{
	"5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30",
	"7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31",
	"8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31", "8.5": "2029-12-31",
}

var phpPoweredByRe = regexp.MustCompile(`(?i)\bPHP/(\d+)\.(\d+)(?:\.(\d+))?`)

// checkPHPVersion reports a PHP branch that no longer gets security
// fixes, from the X-Powered-By header of the homepage.
func (s *Scanner) checkPHPVersion(context.Context) []Finding {
	if !s.passive() {
		return nil
	}
	var m []string
	for _, v := range s.home.resp.Header.Values("X-Powered-By") {
		if m = phpPoweredByRe.FindStringSubmatch(v); m != nil {
			break
		}
	}
	if m == nil {
		return nil
	}
	branch := m[1] + "." + m[2]
	full := branch
	if m[3] != "" {
		full += "." + m[3]
	}
	eol, known := phpEndOfLife[branch]
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	switch {
	case known:
	case major < 5 || (major == 5 && minor < 6):
		eol = "2017-01-01" // 5.5 and older: before that
	default:
		return nil // a branch newer than this table
	}
	end, err := time.Parse("2006-01-02", eol)
	if err != nil || time.Now().Before(end) {
		return nil
	}
	when := "ended on " + eol
	if !known {
		when = "ended years ago"
	}
	ev := Evidence{Method: "X-Powered-By header", Mode: modePassive, URL: s.base.String(), Value: full, Confidence: 80}
	f := finding(idPHPEndOfLife, "PHP "+branch+" is end of life", SeverityMedium, s.base.String(), ev,
		"PHP "+full+", from the X-Powered-By header; security support for "+branch+" "+when,
		"Some systems (Debian, Ubuntu, RHEL) keep fixing their own PHP packages after that date: check how this one is maintained")
	f[0].Data = map[string]any{"version": full, "branch": branch, "end_of_life": eol}
	return f
}

var (
	// phpHTMLErrorRe matches an error PHP printed into a page with
	// html_errors on: <b>Warning</b>: … in <b>/path/file.php</b> on line
	// <b>12</b>. A page that only writes about such errors has the markup
	// escaped, so it does not match.
	phpHTMLErrorRe = regexp.MustCompile(`(?is)<b>(Fatal error|Parse error|Warning|Notice|Deprecated|Strict Standards)</b>:\s.{0,400}? in <b>((?:/|[a-z]:[\\/])[^<>]{1,300})</b> on line <b>\d+</b>`)
	wpdbErrorRe    = regexp.MustCompile(`(?i)<p class=["']wpdberror["']>|<strong>WordPress database error:</strong>`)
)

// checkDisplayedErrors reports PHP or database errors printed into the
// pages the scan read: display_errors (or WP_DEBUG_DISPLAY) is on, which
// tells visitors the paths and code of the site.
func (s *Scanner) checkDisplayedErrors(ctx context.Context) []Finding {
	seen := map[string]bool{}
	var entries []string
	var first Evidence
	for _, p := range s.discoveryPages(ctx) {
		if p.resp == nil {
			continue
		}
		u := p.resp.URL.String()
		for _, m := range phpHTMLErrorRe.FindAllSubmatch(p.resp.Body, 5) {
			entry := fmt.Sprintf("%s in %s", m[1], m[2])
			if !seen[entry] {
				seen[entry] = true
				entries = append(entries, entry)
			}
			if first.URL == "" {
				first = Evidence{Method: "PHP error in the " + p.label, Mode: p.mode, URL: u, Value: string(m[1]), Confidence: 100}
			}
		}
		if wpdbErrorRe.Match(p.resp.Body) && !seen["wpdb"] {
			seen["wpdb"] = true
			entries = append(entries, "A WordPress database error is printed in the "+p.label)
			if first.URL == "" {
				first = Evidence{Method: "Database error in the " + p.label, Mode: p.mode, URL: u, Confidence: 100}
			}
		}
	}
	if len(entries) == 0 {
		return nil
	}
	sort.Strings(entries)
	if len(entries) > 8 {
		entries = append(entries[:8], fmt.Sprintf("and %d more", len(entries)-8))
	}
	return finding(idDisplayedErrors, "PHP errors are displayed to visitors", SeverityMedium, first.URL, first, entries...)
}

// exposure is a file that should never be served, how to recognize it and
// what to report. The check answers with the entries of the finding;
// values of secrets are never among them.
type exposure struct {
	id, title, severity string
	paths               []string
	maxBody             int64
	thorough            bool // only with --aggressive: rarer, so not worth a request on every scan
	check               func(res *httpclient.Response) (entries []string, ok bool)
}

var (
	gitHeadRe      = regexp.MustCompile(`^(?:ref: refs/heads/(\S{1,100})|[0-9a-f]{40})\s*$`)
	envLineRe      = regexp.MustCompile(`(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,60})\s*=`)
	envSecretRe    = regexp.MustCompile(`PASS|SECRET|TOKEN|KEY|CREDENTIAL|AUTH`)
	phpInfoRe      = regexp.MustCompile(`(?i)<title>\s*(?:phpinfo\(\)|PHP [\d.]+ - phpinfo\(\))\s*</title>|<h1 class="p">PHP Version`)
	phpInfoVerRe   = regexp.MustCompile(`(?i)PHP Version\s*(?:</td><td class="v">)?\s*(\d+\.\d+\.\d+)`)
	phpLogLineRe   = regexp.MustCompile(`(?m)^\[\d{2}-[A-Z][a-z]{2}-\d{4} [\d:]{8}[^\]]*\] PHP (?:Warning|Notice|Fatal error|Parse error|Deprecated)`)
	htpasswdLineRe = regexp.MustCompile(`(?m)^[A-Za-z0-9._@-]{1,64}:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$1\$|\$5\$|\$6\$)\S+\s*$`)
	adminerRe      = regexp.MustCompile(`(?i)<title>[^<]*\bAdminer\b`)
	deployKeysRe   = regexp.MustCompile(`"(host|username|user|password|remotePath|remote_path|privateKeyPath|passphrase)"\s*:`)
)

var exposures = []exposure{
	{
		id: idGitRepository, title: "Git repository exposed", severity: SeverityHigh,
		paths: []string{".git/HEAD"}, maxBody: 1 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			m := gitHeadRe.FindSubmatch(bytes.TrimSpace(res.Body))
			if m == nil {
				return nil, false
			}
			entries := []string{"The site's source code and its history can be downloaded from .git/"}
			if len(m[1]) > 0 {
				entries = append(entries, "Branch: "+string(m[1]))
			}
			return entries, true
		},
	},
	{
		id: idEnvFile, title: "Environment file exposed", severity: SeverityHigh,
		paths: []string{".env"}, maxBody: 64 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			if isHTML(res.Body) {
				return nil, false
			}
			var names []string
			seen := map[string]bool{}
			for _, m := range envLineRe.FindAllSubmatch(res.Body, 200) {
				if n := string(m[1]); !seen[n] {
					seen[n] = true
					names = append(names, n)
				}
			}
			if len(names) < 2 {
				return nil, false
			}
			sort.Strings(names)
			if len(names) > 20 {
				names = append(names[:20], fmt.Sprintf("and %d more", len(names)-20))
			}
			return []string{"Defines " + strings.Join(names, ", ") + " (values not shown in this report)"}, true
		},
	},
	{
		id: idPHPInfo, title: "phpinfo() page exposed", severity: SeverityMedium,
		paths: []string{"phpinfo.php", "info.php"}, maxBody: 64 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			if !phpInfoRe.Match(res.Body) {
				return nil, false
			}
			entries := []string{"It shows the PHP configuration, the loaded modules, the server's paths and environment variables"}
			if m := phpInfoVerRe.FindSubmatch(res.Body); m != nil {
				entries = append(entries, "PHP "+string(m[1]))
			}
			return entries, true
		},
	},
	{
		id: idPHPErrorLog, title: "PHP error log exposed", severity: SeverityMedium,
		paths: []string{"error_log"}, maxBody: 64 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			if isHTML(res.Body) || !phpLogLineRe.Match(res.Body) {
				return nil, false
			}
			return nonEmpty("PHP errors with the paths of the site's files", sizeEntry(res)), true
		},
	},
	{
		id: idSVNRepository, title: "Subversion metadata exposed", severity: SeverityHigh, thorough: true,
		paths: []string{".svn/wc.db", ".svn/entries"}, maxBody: 1 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			body := bytes.TrimSpace(res.Body)
			if !bytes.HasPrefix(body, []byte("SQLite format 3")) && !svnEntriesRe.Match(body) {
				return nil, false
			}
			return []string{"The site's source code can be downloaded from .svn/"}, true
		},
	},
	{
		id: idDSStore, title: ".DS_Store file exposed", severity: SeverityLow, thorough: true,
		paths: []string{".DS_Store"}, maxBody: 1 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			if !bytes.HasPrefix(res.Body, []byte("\x00\x00\x00\x01Bud1")) {
				return nil, false
			}
			return []string{"It lists the names of the files and folders next to it"}, true
		},
	},
	{
		id: idHtpasswd, title: "Password file exposed", severity: SeverityHigh, thorough: true,
		paths: []string{".htpasswd"}, maxBody: 16 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			n := len(htpasswdLineRe.FindAll(res.Body, 100))
			if n == 0 || isHTML(res.Body) {
				return nil, false
			}
			return []string{plural(n, "account") + " with a password hash (not shown in this report)"}, true
		},
	},
	{
		id: idAdminer, title: "Adminer database tool exposed", severity: SeverityMedium, thorough: true,
		paths: []string{"adminer.php"}, maxBody: 64 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			if !adminerRe.Match(res.Body) {
				return nil, false
			}
			return []string{"Anyone can try to log in to the database from this page"}, true
		},
	},
	{
		id: idDeployConfig, title: "Deployment settings exposed", severity: SeverityHigh, thorough: true,
		paths: []string{".vscode/sftp.json", "sftp-config.json", ".ftpconfig"}, maxBody: 16 << 10,
		check: func(res *httpclient.Response) ([]string, bool) {
			if isHTML(res.Body) {
				return nil, false
			}
			var keys []string
			seen := map[string]bool{}
			for _, m := range deployKeysRe.FindAllSubmatch(res.Body, 50) {
				if k := string(m[1]); !seen[k] {
					seen[k] = true
					keys = append(keys, k)
				}
			}
			if !seen["host"] || len(keys) < 2 {
				return nil, false
			}
			sort.Strings(keys)
			return []string{"An editor's upload settings: " + strings.Join(keys, ", ") + " (values not shown in this report)"}, true
		},
	},
}

var svnEntriesRe = regexp.MustCompile(`^\d{1,2}\s*\n`)

// siteArchiveNames are the names people give an archive of the whole site
// before a migration; names from the domain are added to them.
var siteArchiveNames = []string{"backup", "wordpress", "site", "www", "public_html", "html", "web", "wp"}

func sizeEntry(res *httpclient.Response) string {
	if n := exportSize(res); n > 0 {
		return "Size: " + plural(int(n), "byte")
	}
	return ""
}

// checkSensitiveFiles looks for files that should never be served: a Git
// repository, an environment file, a phpinfo() page, a PHP error log, the
// database repair page, and with --aggressive the rarer ones. It reports
// what a file is and which settings it names, never their values.
func (s *Scanner) checkSensitiveFiles(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	type probe struct {
		e *exposure
		u string
	}
	var probes []probe
	for i := range exposures {
		e := &exposures[i]
		if e.thorough && !s.thorough() {
			continue
		}
		for _, p := range e.paths {
			probes = append(probes, probe{e, s.url(p)})
		}
	}
	var mu sync.Mutex
	var out []Finding
	found := map[string]bool{}
	s.parallel(ctx, len(probes), func(i int) {
		p := probes[i]
		res := s.do(ctx, httpclient.Request{URL: p.u, MaxBody: p.e.maxBody})
		if res == nil || res.StatusCode != http.StatusOK || res.Blocked != "" {
			return
		}
		entries, ok := p.e.check(res)
		if !ok {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if found[p.e.id] {
			return // one finding per kind: .svn/wc.db and .svn/entries are the same exposure
		}
		found[p.e.id] = true
		sev := p.e.severity
		if p.e.id == idEnvFile && envSecretRe.MatchString(strings.Join(entries, " ")) {
			sev = SeverityCritical
		}
		out = append(out, finding(p.e.id, p.e.title, sev, p.u, direct(p.u, 100), entries...)...)
	})
	out = append(out, s.checkDBRepair(ctx)...)
	if s.thorough() {
		out = append(out, s.checkSiteArchives(ctx)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

var repairButtonRe = regexp.MustCompile(`(?i)repair\.php\?repair=1`)

// checkDBRepair reports wp-admin/maint/repair.php when WP_ALLOW_REPAIR is
// on: the page then repairs the database for anyone, with no login.
func (s *Scanner) checkDBRepair(ctx context.Context) []Finding {
	u := s.coreURL("wp-admin/maint/repair.php")
	res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 32 << 10})
	if res == nil || res.StatusCode != http.StatusOK || !repairButtonRe.Match(res.Body) {
		return nil
	}
	return finding(idDBRepair, "Database repair page is open to anyone", SeverityMedium, u, direct(u, 100),
		"WP_ALLOW_REPAIR is on: the page repairs and optimizes the database with no login, which can load the server",
		"Remove the WP_ALLOW_REPAIR line from wp-config.php when the repair is done")
}

// checkSiteArchives looks for an archive of the whole site in its root.
// Only the first bytes of each file are requested.
func (s *Scanner) checkSiteArchives(ctx context.Context) []Finding {
	var paths []string
	for _, n := range siteArchiveNames {
		paths = append(paths, n+".zip", n+".tar.gz")
	}
	var mu sync.Mutex
	var out []Finding
	s.parallel(ctx, len(paths), func(i int) {
		u := s.url(paths[i])
		res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 1 << 10, Header: http.Header{"Range": {"bytes=0-1023"}}})
		if res == nil || (res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent) {
			return
		}
		if !bytes.HasPrefix(res.Body, gzipMagic) && !bytes.HasPrefix(res.Body, zipMagic) {
			return
		}
		f := finding(idSiteArchive, "Archive in the site's root", SeverityHigh, u, direct(u, 90),
			nonEmpty("A compressed archive, likely a copy of the site with wp-config.php; its contents were not inspected", sizeEntry(res))...)
		mu.Lock()
		out = append(out, f...)
		mu.Unlock()
	})
	return out
}
