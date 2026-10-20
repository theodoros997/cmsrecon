package scan

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// Finding IDs of the -e cb, dbe and bf enumerations.
const (
	idConfigBackup = "config-backup"
	idDBExport     = "db-export"
	idBackupFolder = "backup-folder"
)

// configBackupNames are copies of wp-config.php that editors, admins and
// deployment tools leave behind, and that the server returns as text
// instead of running them. This list is cmsrecon's own.
var configBackupNames = []string{
	"wp-config.php.bak", "wp-config.php.bk", "wp-config.php.bkp", "wp-config.php.backup",
	"wp-config.php.old", "wp-config.php.orig", "wp-config.php.original", "wp-config.php.save",
	"wp-config.php.saved", "wp-config.php.swp", "wp-config.php.swo", "wp-config.php~",
	"wp-config.php.txt", "wp-config.php.tmp", "wp-config.php.temp", "wp-config.php.dist",
	"wp-config.php.inc", "wp-config.php.copy", "wp-config.php.1", "wp-config.php.2",
	"wp-config.php_bak", "wp-config.php_old", "wp-config.php_orig", "wp-config.php-bak",
	"wp-config.php-old", "wp-config.php-backup", "wp-config.php.new", "wp-config.php.prod",
	"wp-config.php.dev", "wp-config.php.html", "wp-config.bak", "wp-config.old", "wp-config.txt",
	"wp-config.orig", "wp-config.save", "wp-config.backup", ".wp-config.php.swp", "#wp-config.php#",
}

var (
	// configDefineRe matches the constants of a wp-config.php.
	configDefineRe = regexp.MustCompile(`(?i)define\s*\(\s*['"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|WP_DEBUG)['"]`)
	tablePrefixRe  = regexp.MustCompile(`\$table_prefix\s*=`)
)

// checkConfigBackups looks for readable copies of wp-config.php (-e cb).
// It reports which settings a copy exposes, never their values.
func (s *Scanner) checkConfigBackups(ctx context.Context) []Finding {
	if !s.aggressive() || !s.opts.Enumerate.ConfigBackups {
		return nil
	}
	var mu sync.Mutex
	var out []Finding
	s.parallel(ctx, len(configBackupNames), func(i int) {
		u := s.url(configBackupNames[i])
		res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 256 << 10})
		// A real copy starts with PHP code; an HTML page that shows
		// define() calls (a catch-all site, a tutorial) is not one.
		if res == nil || res.StatusCode != http.StatusOK || (isHTML(res.Body) && !bytes.Contains(res.Body, []byte("<?php"))) {
			return
		}
		var consts []string
		for _, m := range configDefineRe.FindAllSubmatch(res.Body, -1) {
			if c := strings.ToUpper(string(m[1])); !slices.Contains(consts, c) {
				consts = append(consts, c)
			}
		}
		if len(consts) == 0 || (len(consts) == 1 && !tablePrefixRe.Match(res.Body)) {
			return
		}
		sort.Strings(consts)
		sev := SeverityHigh
		if slices.Contains(consts, "DB_PASSWORD") {
			sev = SeverityCritical
		}
		f := finding(idConfigBackup, "wp-config.php backup exposed", sev, u, direct(u, 100),
			"Defines "+strings.Join(consts, ", ")+" (values not shown in this report)",
			"The file holds the database credentials and the keys that sign login cookies")
		f[0].Data = map[string]any{"constants": consts}
		mu.Lock()
		out = append(out, f...)
		mu.Unlock()
	})
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// dbExportPaths returns the database export paths to try: generic names
// and names derived from the host, at the site root, in wp-content and in
// backup folders. The uploads folder's dump.sql has its own finding.
func (s *Scanner) dbExportPaths() []string {
	host := strings.ToLower(s.base.Hostname())
	bare := strings.TrimPrefix(host, "www.")
	label, _, _ := strings.Cut(bare, ".")
	domainNames := uniqueStrings([]string{host, bare, label, strings.ReplaceAll(bare, ".", "_")})
	generic := []string{"wordpress", "wp", "backup", "database", "db", "dump", "data", "mysql", "site", "db_backup", "backup_db", "sql", "export", "localhost"}

	var paths []string
	for _, n := range append(append([]string{}, domainNames...), generic...) {
		paths = append(paths, n+".sql", n+".sql.gz")
	}
	for _, n := range domainNames {
		paths = append(paths, n+".zip", n+".tar.gz")
	}
	contentRel := strings.TrimPrefix(s.content.Path, s.base.Path)
	for _, n := range append(append([]string{}, domainNames...), generic...) {
		paths = append(paths, contentRel+n+".sql")
	}
	for _, dir := range []string{"backup/", "backups/", contentRel + "backup/", contentRel + "backups/"} {
		for _, n := range []string{"backup", "db", "database", "dump", "wordpress", bare} {
			paths = append(paths, dir+n+".sql")
		}
	}
	return uniqueStrings(paths)
}

func uniqueStrings(list []string) []string {
	seen := map[string]bool{}
	out := list[:0:0]
	for _, s := range list {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

var (
	gzipMagic = []byte{0x1f, 0x8b}
	zipMagic  = []byte("PK\x03\x04")
)

// checkDBExports looks for database exports (-e dbe). Only the first 3 KB
// of each file is requested: enough to recognize SQL or an archive.
func (s *Scanner) checkDBExports(ctx context.Context) []Finding {
	if !s.aggressive() || !s.opts.Enumerate.DBExports {
		return nil
	}
	paths := s.dbExportPaths()
	var mu sync.Mutex
	var out []Finding
	s.parallel(ctx, len(paths), func(i int) {
		u := s.url(paths[i])
		res := s.do(ctx, httpclient.Request{URL: u, MaxBody: 3 << 10, Header: http.Header{"Range": {"bytes=0-3071"}}})
		if res == nil || (res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent) {
			return
		}
		size := ""
		if n := exportSize(res); n > 0 {
			size = "Size: " + plural(int(n), "byte")
		}
		var f []Finding
		switch {
		case sqlRe.Match(res.Body) && !isHTML(res.Body):
			f = finding(idDBExport, "Database export exposed", SeverityHigh, u, direct(u, 100),
				nonEmpty("SQL statements in the first 3 KB", size)...)
		case (bytes.HasPrefix(res.Body, gzipMagic) || bytes.HasPrefix(res.Body, zipMagic)) && !strings.HasSuffix(u, ".sql"):
			f = finding(idDBExport, "Archive at a database export path", SeverityMedium, u, direct(u, 90),
				nonEmpty("A compressed archive; its contents were not inspected", size)...)
		default:
			return
		}
		mu.Lock()
		out = append(out, f...)
		mu.Unlock()
	})
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// exportSize reads the full size of a file from Content-Range (a partial
// answer) or Content-Length.
func exportSize(res *httpclient.Response) int64 {
	if cr := res.Header.Get("Content-Range"); cr != "" {
		if _, total, ok := strings.Cut(cr, "/"); ok {
			if n, err := strconv.ParseInt(total, 10, 64); err == nil {
				return n
			}
		}
	}
	if res.StatusCode == http.StatusOK {
		if n, err := strconv.ParseInt(res.Header.Get("Content-Length"), 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func nonEmpty(list ...string) []string {
	var out []string
	for _, s := range list {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// backupFolders are folders where backup plugins store their archives,
// relative to wp-content. backup-db/ has its own finding.
var backupFolders = []string{
	"updraft/", "backups/", "backup/", "ai1wm-backups/", "backups-dup-lite/", "backups-dup-pro/",
	"wp-snapshots/", "wpvividbackups/", "ebwp-backups/", "wp-clone/", "uploads/backup-guard/",
	"uploads/wp-clone/", "uploads/wpbackitup_backups/", "uploads/backupbuddy_backups/",
	"uploads/pb_backupbuddy/", "uploads/snapshots/", "uploads/ithemes-security/backups/",
	"uploads/wp-migrate-db/", "uploads/db-backup/", "uploads/backup/", "uploads/backups/",
	"uploads/wp-backup/", "uploads/wpvividbackups/",
}

// checkBackupFolders looks for backup plugin folders with directory
// listing (-e bf): only a listing shows that the backups can be
// downloaded.
func (s *Scanner) checkBackupFolders(ctx context.Context) []Finding {
	if !s.aggressive() || !s.opts.Enumerate.BackupFolders {
		return nil
	}
	var mu sync.Mutex
	var out []Finding
	s.parallel(ctx, len(backupFolders), func(i int) {
		u := s.contentURL(backupFolders[i])
		res := s.get(ctx, u)
		files, ok := s.dirListing(res)
		if !ok {
			return
		}
		entries := files
		if len(files) == 0 {
			entries = []string{"The folder is empty"}
		}
		f := finding(idBackupFolder, "Backup folder with directory listing", SeverityHigh, u, direct(u, 100), entries...)
		if len(files) == 0 {
			f[0].Severity = SeverityLow
		}
		mu.Lock()
		out = append(out, f...)
		mu.Unlock()
	})
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}
