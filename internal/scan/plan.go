package scan

import (
	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
)

// Plan is what --dry-run shows before a scan: the data it would use and
// about how many requests it would send.
type Plan struct {
	Data    *DataInfo
	Notices []string // about the data: missing or old
	// Requests is an estimate before anything is found: each plugin or
	// theme the scan finds adds about PerComponent more.
	Requests          int
	PerComponent      int
	PluginsBruteForce int // slugs checked one by one; 0 when none
	ThemesBruteForce  int
}

// Request counts measured on a test site with nothing to find (see
// TestPlanEstimate). Each pair is a default scan, which tries the
// likeliest names, and --aggressive, which tries them all.
var (
	planBase          = [2]int{45, 73} // pre-flight, homepage, 404 baselines, discovery, version checks and the single-path findings
	planConfigBackups = [2]int{likelyConfigBackups, len(configBackupNames)}
	planDBExports     = [2]int{21, 81}
	planBackupFolders = [2]int{likelyBackupFolders, len(backupFolders)}
)

const (
	planUsers     = 6  // plus one per author ID
	planMedia     = 2  // plus one per attachment ID when the REST API is closed
	planTimthumbs = 39 // grows with the themes and plugins found
	perComponent  = 4  // a readme, a changelog or a file to hash, and a check of the folder
)

// PlanScan reads the data directory and estimates what a scan with these
// options would do. It sends no request.
func PlanScan(o *cli.ScanOptions) *Plan {
	s := New(o, nil)
	s.res = &Result{}
	s.loadData()
	p := &Plan{Data: s.res.VulnerabilityData, Notices: s.res.Notices, PerComponent: perComponent}
	if !s.aggressive() {
		p.Requests = 5 // the homepage, the 404 page and the feeds they link to
		return p
	}

	e := o.Enumerate
	tier := 0
	if s.thorough() {
		tier = 1
	}
	p.Requests = planBase[tier] + o.CrawlPages
	if e.ConfigBackups {
		p.Requests += planConfigBackups[tier]
	}
	if e.DBExports {
		p.Requests += planDBExports[tier]
	}
	if e.BackupFolders {
		p.Requests += planBackupFolders[tier]
	}
	if r := e.Users; r != nil {
		p.Requests += planUsers + r.To - r.From + 1
	}
	if r := e.Media; r != nil {
		p.Requests += planMedia + r.To - r.From + 1
	}
	if e.Timthumbs {
		p.Requests += planTimthumbs
	}
	if o.WPAuth == nil {
		p.PluginsBruteForce = s.planBrute(wordlists.Plugins, o.PluginsDetection, e.Plugins, o.PluginsList)
		p.ThemesBruteForce = s.planBrute(wordlists.Themes, o.ThemesDetection, e.Themes, o.ThemesList)
	}
	p.Requests += p.PluginsBruteForce + p.ThemesBruteForce
	return p
}

// planBrute counts the slugs a scan would check one by one.
func (s *Scanner) planBrute(kind string, mode cli.DetectionMode, set cli.ItemSet, named []string) int {
	switch {
	case len(named) > 0:
		return len(named)
	case !mode.BruteForce() || set == cli.ItemsNone:
		return 0
	}
	before := len(s.res.Notices)
	n := len(s.bruteList(kind, set))
	s.res.Notices = s.res.Notices[:before] // they describe a scan that ran
	return n
}
