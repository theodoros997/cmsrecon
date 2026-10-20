package scan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// Finding IDs, in report order. They are part of the JSON format.
const (
	idUnfinishedInstall = "unfinished-install"
	idHeaders           = "headers"
	idRobots            = "robots-txt"
	idXMLRPC            = "xmlrpc"
	idReadme            = "readme"
	idDebugLog          = "debug-log"
	idFullPath          = "full-path-disclosure"
	idBackupDB          = "backup-db"
	idDuplicatorLog     = "duplicator-installer-log"
	idMultisite         = "multisite"
	idMuPlugins         = "mu-plugins"
	idRegistration      = "registration"
	idUploadListing     = "upload-directory-listing"
	idTmmDBMigrate      = "tmm-db-migrate"
	idUploadSQLDump     = "upload-sql-dump"
	idEmergencyScript   = "emergency-password-reset"
	idWPCron            = "wp-cron"
	idPHPDisabled       = "php-disabled"
	idFantastico        = "fantastico-fileslist"
	idSearchReplaceDB   = "search-replace-db2"
)

var findingOrder = []string{
	idUnfinishedInstall, idHeaders, idRobots, idXMLRPC, idReadme, idDebugLog, idFullPath,
	idBackupDB, idDuplicatorLog, idMultisite, idMuPlugins, idRegistration, idUploadListing,
	idTmmDBMigrate, idUploadSQLDump, idEmergencyScript, idWPCron, idPHPDisabled, idFantastico,
	idSearchReplaceDB,
}

func findingRank(id string) int {
	for i, v := range findingOrder {
		if v == id {
			return i
		}
	}
	return len(findingOrder)
}

// finding builds a single-evidence finding.
func finding(id, title, severity, u string, ev Evidence, entries ...string) []Finding {
	return []Finding{{
		ID: id, Title: title, Severity: severity, URL: u, Confidence: ev.Confidence,
		Entries: entries, Evidence: []Evidence{ev},
	}}
}

func direct(u string, confidence int) Evidence {
	return Evidence{Method: "Direct access", Mode: modeAggressive, URL: u, Confidence: confidence}
}

// boringHeaders are response headers that say nothing about the stack.
var boringHeaders = map[string]bool{
	"accept-ranges": true, "age": true, "alt-svc": true, "cache-control": true, "connection": true,
	"content-encoding": true, "content-language": true, "content-length": true,
	"content-security-policy": true, "content-security-policy-report-only": true, "content-type": true,
	"cross-origin-embedder-policy": true, "cross-origin-opener-policy": true,
	"cross-origin-resource-policy": true, "date": true, "etag": true, "expires": true,
	"feature-policy": true, "keep-alive": true, "last-modified": true, "link": true, "nel": true,
	"permissions-policy": true, "pragma": true, "referrer-policy": true, "report-to": true,
	"reporting-endpoints": true, "server-timing": true, "set-cookie": true,
	"strict-transport-security": true, "transfer-encoding": true, "vary": true, "x-content-type-options": true,
	"x-frame-options": true, "x-pingback": true, "x-ua-compatible": true, "x-xss-protection": true,
}

func (s *Scanner) checkHeaders(context.Context) []Finding {
	if !s.passive() {
		return nil
	}
	var entries []string
	for name, values := range s.home.resp.Header {
		if boringHeaders[strings.ToLower(name)] {
			continue
		}
		for _, v := range values {
			entries = append(entries, name+": "+v)
		}
	}
	if len(entries) == 0 {
		return nil
	}
	sort.Strings(entries)
	ev := Evidence{Method: "Homepage response headers", Mode: modePassive, URL: s.base.String(), Confidence: 100}
	return finding(idHeaders, "Interesting response headers", SeverityInfo, s.base.String(), ev, entries...)
}

// wpRobotsDefaults are the rules WordPress writes itself.
var wpRobotsDefaults = map[string]bool{"/wp-admin/": true, "/wp-admin/admin-ajax.php": true}

func (s *Scanner) checkRobots(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	ref := s.base.ResolveReference(&url.URL{Path: "/robots.txt"})
	res := s.get(ctx, ref.String())
	if res == nil || res.StatusCode != 200 || s.isNotFound(ctx, ref, res) {
		return nil
	}
	var entries []string
	isRobots := false
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(res.Body))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		key, val, ok := strings.Cut(line, ":")
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)
		if !ok {
			continue
		}
		switch key {
		case "user-agent", "crawl-delay", "host":
			isRobots = true
		case "allow", "disallow", "sitemap":
			isRobots = true
			entry := strings.ToUpper(key[:1]) + key[1:] + ": " + val
			if val != "" && !wpRobotsDefaults[val] && !seen[entry] {
				seen[entry] = true
				entries = append(entries, entry)
			}
		}
	}
	if !isRobots {
		return nil
	}
	return finding(idRobots, "robots.txt found", SeverityInfo, ref.String(), direct(ref.String(), 100), entries...)
}

func (s *Scanner) checkReadme(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	var found []string
	for _, name := range []string{"readme.html", "olvasdel.html", "lisenssi.html", "liesmich.html"} {
		u := s.url(name)
		res := s.get(ctx, u)
		if res == nil || res.StatusCode != 200 || !bytes.Contains(bytes.ToLower(res.Body), []byte("wordpress")) {
			continue
		}
		if ref, _ := url.Parse(u); s.isNotFound(ctx, ref, res) {
			continue
		}
		found = append(found, u)
	}
	if len(found) == 0 {
		return nil
	}
	var entries []string
	for _, u := range found[1:] {
		entries = append(entries, "Also found: "+u)
	}
	return finding(idReadme, "WordPress readme file found", SeverityInfo, found[0], direct(found[0], 100), entries...)
}

// debugLogRe matches PHP error log lines and the database errors WordPress
// writes to debug.log.
var debugLogRe = regexp.MustCompile(`(?m)^\[[^\]\n]{5,60}\] (?:PHP |WordPress database error)`)

func (s *Scanner) checkDebugLog(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.contentURL("debug.log")
	res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 64 << 10})
	if res == nil || res.StatusCode != 200 || !debugLogRe.Match(res.Body) {
		return nil
	}
	var entries []string
	if n, err := strconv.ParseInt(res.Header.Get("Content-Length"), 10, 64); err == nil {
		entries = append(entries, fmt.Sprintf("Size: %d bytes", n))
	}
	return finding(idDebugLog, "Debug log exposed", SeverityHigh, u, direct(u, 100), entries...)
}

// fullPathRe matches a PHP error naming the file it happened in, in HTML or
// plain text, e.g. "Fatal error</b>: ... in <b>/var/www/x.php</b> on line".
var fullPathRe = regexp.MustCompile(`(?is)\b(?:fatal error|warning|notice|parse error|deprecated|uncaught)\b.{0,500}? in (?:<b>)?((?:/|[a-z]:[\\/])[^<>"'\s:]*?\.php)(?:</b>)?(?:\s+on line|:\d+)`)

func (s *Scanner) checkFullPathDisclosure(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("wp-includes/rss-functions.php")
	res := s.get(ctx, u)
	if res == nil {
		return nil
	}
	m := fullPathRe.FindSubmatch(res.Body)
	if m == nil {
		return nil
	}
	f := finding(idFullPath, "Full path disclosure", SeverityLow, u, direct(u, 100), "Disclosed path: "+string(m[1]))
	f[0].Data = map[string]any{"path": string(m[1])}
	f[0].References = []string{"https://owasp.org/www-community/attacks/Full_Path_Disclosure"}
	return f
}

func (s *Scanner) checkBackupDB(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.contentURL("backup-db/")
	res := s.get(ctx, u)
	if res == nil || (res.StatusCode != 200 && res.StatusCode != 403) {
		return nil
	}
	ref, _ := url.Parse(u)
	if s.isNotFound(ctx, ref, res) {
		return nil
	}
	if files, ok := s.dirListing(res); ok {
		return finding(idBackupDB, "Backup DB folder with directory listing", SeverityHigh, u, direct(u, 100), files...)
	}
	confidence := 70
	if res.StatusCode == 403 {
		confidence = 60
	}
	return finding(idBackupDB, "Backup DB folder found", SeverityMedium, u, direct(u, confidence),
		fmt.Sprintf("HTTP %d: the folder exists; database backups may be stored there", res.StatusCode))
}

var duplicatorRe = regexp.MustCompile(`(?i)\bDUPLICATOR\b[^\n]{0,40}\bLOG\b`)

func (s *Scanner) checkDuplicatorLog(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("installer-log.txt")
	res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 16 << 10})
	if res == nil || res.StatusCode != 200 || !duplicatorRe.Match(res.Body) {
		return nil
	}
	return finding(idDuplicatorLog, "Duplicator installer log exposed", SeverityMedium, u, direct(u, 100),
		"The log can disclose server paths, database names and the site's migration history")
}

var signupFormRe = regexp.MustCompile(`(?i)<form[^>]+(?:id|name)=["']setupform["']|wp-signup\.php`)

func (s *Scanner) checkMultisite(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("wp-signup.php")
	res := s.get(ctx, u)
	if res == nil {
		return nil
	}
	ref, _ := url.Parse(u)
	switch {
	case res.IsRedirect():
		// A single site sends wp-signup.php to wp-login.php?action=register;
		// a network sends sub-sites to the main site's wp-signup.php.
		loc, err := res.Location()
		if err != nil || !strings.HasSuffix(loc.Path, "/wp-signup.php") {
			return nil
		}
		ev := direct(u, 100)
		ev.Value = "redirects to " + loc.String()
		return finding(idMultisite, "WordPress multisite (network) install", SeverityInfo, u, ev)
	case res.StatusCode == 200 && signupFormRe.Match(res.Body) && !s.isNotFound(ctx, ref, res):
		return finding(idMultisite, "WordPress multisite (network) install", SeverityInfo, u, direct(u, 100))
	}
	return nil
}

func (s *Scanner) checkMuPlugins(ctx context.Context) []Finding {
	f := Finding{ID: idMuPlugins, Title: "Must-use plugins folder found", Severity: SeverityInfo, URL: s.contentURL("mu-plugins/")}
	if s.passive() {
		for _, p := range s.pages() {
			for _, u := range s.scopedURLs(p.page) {
				if strings.Contains(u.Path, "/mu-plugins/") {
					f.Evidence = append(f.Evidence, Evidence{
						Method: "URLs in the " + p.label, Mode: modePassive, URL: p.resp.URL.String(), Value: u.String(), Confidence: 80,
					})
					break
				}
			}
		}
	}
	if s.aggressive() {
		res := s.get(ctx, f.URL)
		ref, _ := url.Parse(f.URL)
		if res != nil && (res.StatusCode == 200 || res.StatusCode == 403) && !s.isNotFound(ctx, ref, res) {
			ev := direct(f.URL, 70)
			if files, ok := s.dirListing(res); ok {
				ev.Confidence = 100
				f.Title = "Must-use plugins folder with directory listing"
				f.Severity = SeverityLow
				f.Entries = files
			}
			f.Evidence = append(f.Evidence, ev)
		}
	}
	if len(f.Evidence) == 0 {
		return nil
	}
	f.Confidence = combine(f.Evidence)
	sortEvidence(f.Evidence)
	return []Finding{f}
}

var registerFormRe = regexp.MustCompile(`(?i)<form[^>]+(?:id|name)=["'](?:registerform|setupform)["']`)

func (s *Scanner) checkRegistration(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.urlWithQuery("wp-login.php", "action=register")
	// A network redirects registration to wp-signup.php; follow a few
	// in-scope redirects to see the form.
	cur := u
	for range 3 {
		res := s.get(ctx, cur)
		if res == nil {
			return nil
		}
		if !res.IsRedirect() {
			if res.StatusCode == 200 && registerFormRe.Match(res.Body) {
				return finding(idRegistration, "User registration is enabled", SeverityLow, cur, direct(cur, 100),
					"Anyone can create an account (with the default role, usually Subscriber)")
			}
			return nil
		}
		loc, err := res.Location()
		if err != nil || !s.client.InScope(loc) || strings.Contains(loc.RawQuery, "registration=disabled") {
			return nil
		}
		cur = loc.String()
	}
	return nil
}

func (s *Scanner) checkUploadListing(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.contentURL("uploads/")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 {
		return nil
	}
	files, ok := s.dirListing(res)
	if !ok {
		return nil
	}
	return finding(idUploadListing, "Directory listing is enabled on the uploads folder", SeverityMedium, u, direct(u, 100), files...)
}

func (s *Scanner) checkTmmDBMigrate(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.contentURL("uploads/tmm_db_migrate/tmm_db_migrate.zip")
	res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 512})
	if res == nil || res.StatusCode != 200 {
		return nil
	}
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	looksHTML := bytes.Contains(bytes.ToLower(res.Body), []byte("<html"))
	if !bytes.HasPrefix(res.Body, []byte("PK\x03\x04")) && (!strings.Contains(ct, "zip") || looksHTML) {
		return nil
	}
	return finding(idTmmDBMigrate, "TMM DB Migrate database export exposed", SeverityHigh, u, direct(u, 100),
		"The archive contains a database export")
}

// sqlRe matches the start of an SQL dump.
var sqlRe = regexp.MustCompile(`(?im)^\s*(?:--\s*(?:MySQL|MariaDB|phpMyAdmin|PostgreSQL|Host:|Server version|Dump)|/\*!\d{5}|(?:CREATE|DROP|ALTER|LOCK)\s+TABLES?\b|INSERT\s+INTO\b|SET\s+(?:NAMES|SQL_MODE|FOREIGN_KEY_CHECKS|time_zone)\b)`)

func (s *Scanner) checkSQLDump(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.contentURL("uploads/dump.sql")
	res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 3 << 10, Header: http.Header{"Range": {"bytes=0-3071"}}})
	if res == nil || (res.StatusCode != 200 && res.StatusCode != 206) || !sqlRe.Match(res.Body) {
		return nil
	}
	return finding(idUploadSQLDump, "SQL dump exposed in the uploads folder", SeverityHigh, u, direct(u, 100))
}

// presentFile is the check for files without a reliable signature: a 200
// that is neither the homepage nor the site's not-found answer. A match on
// contentRe raises the confidence from 60 to 100.
func (s *Scanner) presentFile(ctx context.Context, u string, contentRe *regexp.Regexp) (*httpclient.Response, int) {
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 {
		return nil, 0
	}
	if ref, _ := url.Parse(u); s.isNotFound(ctx, ref, res) {
		return nil, 0
	}
	if contentRe != nil && contentRe.Match(res.Body) {
		return res, 100
	}
	return res, 60
}

var emergencyRe = regexp.MustCompile(`(?i)emergency|password`)

func (s *Scanner) checkEmergencyScript(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("emergency.php")
	if res, c := s.presentFile(ctx, u, emergencyRe); res != nil {
		return finding(idEmergencyScript, "Emergency password reset script found", SeverityHigh, u, direct(u, c),
			"The script resets the administrator password without logging in")
	}
	return nil
}

func (s *Scanner) checkWPCron(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("wp-cron.php")
	if res, _ := s.presentFile(ctx, u, nil); res != nil {
		f := finding(idWPCron, "The external WP-Cron seems to be enabled", SeverityInfo, u, direct(u, 60),
			"Anyone can trigger scheduled tasks; repeated requests can load the server")
		f[0].References = []string{"https://developer.wordpress.org/plugins/cron/"}
		return f
	}
	return nil
}

var wpVersionVarRe = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)

func (s *Scanner) checkPHPDisabled(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("wp-includes/version.php")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 || !bytes.Contains(res.Body, []byte("<?php")) {
		return nil
	}
	m := wpVersionVarRe.FindSubmatch(res.Body)
	if m == nil {
		return nil
	}
	f := finding(idPHPDisabled, "PHP is not executed: source code is served", SeverityHigh, u, direct(u, 100),
		"PHP files are returned as source code, which would include wp-config.php and its database credentials")
	f[0].Data = map[string]any{"wp_version": string(m[1])}
	return f
}

func (s *Scanner) checkFantastico(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("fantastico_fileslist.txt")
	res := s.get(ctx, u)
	if res == nil || res.StatusCode != 200 || !strings.HasPrefix(strings.ToLower(res.Header.Get("Content-Type")), "text/plain") {
		return nil
	}
	if ref, _ := url.Parse(u); len(bytes.TrimSpace(res.Body)) == 0 || s.isNotFound(ctx, ref, res) {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(res.Body)), "\n")
	entries := []string{fmt.Sprintf("%d files listed", len(lines))}
	for _, l := range lines[:min(len(lines), 10)] {
		entries = append(entries, strings.TrimSpace(l))
	}
	return finding(idFantastico, "Fantastico file list exposed", SeverityMedium, u, direct(u, 100), entries...)
}

var searchReplaceRe = regexp.MustCompile(`(?i)search\s*(?:and|&|&amp;)?\s*replace|interconnect`)

func (s *Scanner) checkSearchReplaceDB(ctx context.Context) []Finding {
	if !s.aggressive() {
		return nil
	}
	u := s.url("searchreplacedb2.php")
	if res, c := s.presentFile(ctx, u, searchReplaceRe); res != nil {
		return finding(idSearchReplaceDB, "Search Replace DB script found", SeverityHigh, u, direct(u, c),
			"The script can read and rewrite the whole database without logging in")
	}
	return nil
}
