package scan

import (
	"fmt"
	"time"

	"github.com/theodoros997/cmsrecon/internal/vulndb"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// staleAfter is the age at which the scan suggests refreshing the data.
const staleAfter = 7 * 24 * time.Hour

// scanData is what a scan matches against: vulnerabilities, JavaScript
// library patterns and the slug lists. It is read once, before the checks.
type scanData struct {
	vulns *vulndb.DB
	js    *vulndb.JSRepo
	lists *wordlists.Lists
}

// loadData reads the data directory. Missing data is not an error: the
// built-in lists and patterns are used, and a notice says what is missing.
func (s *Scanner) loadData() {
	d := &scanData{}
	dir := s.opts.DataDir
	if dir == "" {
		// Without a data directory (no user cache directory), only the
		// built-in lists and patterns are available.
		d.vulns, d.lists = vulndb.New(), wordlists.Builtin()
		d.js, _ = vulndb.ParseJSRepo([]byte("{}"))
	} else {
		var err error
		if d.vulns, err = vulndb.Open(dir); err != nil {
			s.notice("Some vulnerability data could not be read: %v", err)
		}
		if d.js, err = vulndb.LoadJSRepo(dir); err != nil {
			s.notice("The retire.js data could not be read: %v", err)
		}
		if d.lists, err = wordlists.Load(dir); err != nil {
			s.notice("Some WordPress.org data could not be read: %v", err)
		}
	}
	s.data = d

	info := &DataInfo{Directory: dir}
	for _, src := range d.vulns.Sources {
		info.Sources = append(info.Sources, DataSource{Name: src.Name, UpdatedAt: src.UpdatedAt, Entries: src.Entries})
	}
	if !d.lists.UpdatedAt.IsZero() {
		info.Sources = append(info.Sources, DataSource{Name: "wporg", UpdatedAt: d.lists.UpdatedAt, Entries: len(d.lists.PopularPlugins) + len(d.lists.PopularThemes)})
	}
	if d.js.HasVulnerabilityData() {
		info.Sources = append(info.Sources, DataSource{Name: vulndb.SourceRetire, UpdatedAt: d.js.UpdatedAt, Entries: len(d.js.Libraries())})
	}
	s.res.VulnerabilityData = info

	switch {
	case d.vulns.Empty():
		s.notice("No vulnerability data in %s: run \"cmsrecon update\" to match vulnerabilities. Plugins, themes and versions are still detected.", dirLabel(dir))
	case !hasSource(d.vulns, vulndb.SourceWordfence):
		s.notice("The vulnerability data comes from the CVE List only. Run \"cmsrecon update\" with a free Wordfence Intelligence API key for more complete data.")
	}
	oldest := d.vulns.OldestUpdate()
	if t := d.lists.UpdatedAt; !t.IsZero() && (oldest.IsZero() || t.Before(oldest)) {
		oldest = t
	}
	if !oldest.IsZero() && time.Since(oldest) > staleAfter {
		s.notice("The vulnerability data is %d days old: run \"cmsrecon update\" to refresh it.", int(time.Since(oldest).Hours()/24))
	}
}

func hasSource(db *vulndb.DB, name string) bool {
	for _, src := range db.Sources {
		if src.Name == name {
			return true
		}
	}
	return false
}

func dirLabel(dir string) string {
	if dir == "" {
		return "the data directory"
	}
	return dir
}

// notice adds a notice to the result.
func (s *Scanner) notice(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res.Notices = append(s.res.Notices, fmt.Sprintf(format, args...))
}
