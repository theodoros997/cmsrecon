package scan

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// TimThumb is an image resizing script many themes and plugins bundled
// until 2014. Its old versions let anyone run code on the server.

// timthumbPaths are where themes and plugins commonly keep it, relative to
// their folder. This is cmsrecon's own list.
var timthumbPaths = []string{
	"timthumb.php", "thumb.php",
	"lib/timthumb.php", "lib/thumb.php", "library/timthumb.php", "libs/timthumb.php",
	"includes/timthumb.php", "inc/timthumb.php", "inc/thumb.php",
	"scripts/timthumb.php", "js/timthumb.php", "php/timthumb.php",
	"functions/timthumb.php", "functions/thumb.php", "framework/timthumb.php",
	"tools/timthumb.php", "timthumb/timthumb.php", "modules/timthumb.php",
}

var (
	// TimThumb answers a request without an image with an error page that
	// ends with its version ("TimThumb version : 2.8.14").
	timthumbVersionRe = regexp.MustCompile(`(?i)TimThumb version\s*:\s*(\d+\.\d+(?:\.\d+)*)`)
	timthumbErrorRe   = regexp.MustCompile(`(?i)A TimThumb error has occ?urr?ed|<h1>TimThumb`)
)

// timthumbAdvisory is a known TimThumb vulnerability, described in
// cmsrecon's own words.
type timthumbAdvisory struct {
	from     string // the first affected version; empty for all before below
	below    string // fixed in this version
	vuln     Vulnerability
	optional string // a configuration it needs, which lowers the verdict to likely
}

var timthumbAdvisories = []timthumbAdvisory{{
	below: "2.0",
	vuln: Vulnerability{
		Title: "TimThumb < 2.0 - Remote Code Execution", Severity: SeverityCritical, CVE: []string{"CVE-2011-4106"},
		Affected: []string{"< 2.0"}, FixedIn: "2.0",
		References: []string{"https://www.cve.org/CVERecord?id=CVE-2011-4106"},
	},
}, {
	// WebShot came with the 2.x rewrite.
	from: "2.0", below: "2.8.14",
	vuln: Vulnerability{
		Title: "TimThumb <= 2.8.13 - Remote Command Execution via WebShot", Severity: SeverityHigh, CVE: []string{"CVE-2014-4663"},
		Affected: []string{">= 2.0, <= 2.8.13"}, FixedIn: "2.8.14",
		References: []string{"https://www.cve.org/CVERecord?id=CVE-2014-4663"},
	},
	optional: "Only when its WebShot feature is enabled, which it is not by default",
}}

// enumerateTimthumbs looks for TimThumb in the folder of every theme and
// plugin found, plus the site root and wp-content (-e tt). Each answer is
// checked for TimThumb's own error page, so a catch-all site reports
// nothing.
func (s *Scanner) enumerateTimthumbs(ctx context.Context) []*Timthumb {
	if !s.opts.Enumerate.Timthumbs || !s.aggressive() {
		return nil
	}
	var folders []string
	for t := s.res.MainTheme; t != nil; t = t.Parent {
		folders = append(folders, t.Location)
	}
	for _, t := range s.res.Themes {
		folders = append(folders, t.Location)
	}
	for _, p := range s.res.Plugins {
		folders = append(folders, p.Location)
	}
	var urls []string
	for _, f := range folders {
		if f == "" {
			continue
		}
		for _, p := range timthumbPaths {
			urls = append(urls, strings.TrimSuffix(f, "/")+"/"+p)
		}
	}
	urls = append(urls, s.url("timthumb.php"), s.url("thumb.php"), s.contentURL("timthumb.php"))
	urls = uniqueStrings(urls)

	found := make([]*Timthumb, len(urls))
	var checked atomic.Int32
	s.parallel(ctx, len(urls), func(i int) {
		defer func() { s.steps().Update(stepTimthumbs, fmt.Sprintf("%d/%d paths", checked.Add(1), len(urls))) }()
		res := s.do(ctx, httpclient.Request{URL: urls[i], MaxBody: 16 << 10})
		if res == nil || res.IsRedirect() {
			return
		}
		m := timthumbVersionRe.FindSubmatch(res.Body)
		if m == nil && !timthumbErrorRe.Match(res.Body) {
			return
		}
		t := &Timthumb{URL: urls[i], Version: &Version{}}
		t.Evidence = []Evidence{{Method: "TimThumb error page", Mode: modeAggressive, URL: urls[i], Confidence: 100}}
		if m != nil {
			t.Version = combineVersions([]Evidence{{Method: "TimThumb error page", Mode: modeAggressive, URL: urls[i], Value: string(m[1]), Confidence: 100}})
		}
		found[i] = t
	})
	var out []*Timthumb
	for _, t := range found {
		if t != nil {
			out = append(out, t)
		}
	}
	return out
}

// timthumbVulns matches a TimThumb version against the known
// vulnerabilities. An unknown version may have any of them.
func (s *Scanner) timthumbVulns(v *Version) []Vulnerability {
	var out []Vulnerability
	for _, a := range timthumbAdvisories {
		vuln := a.vuln
		vuln.CVE, vuln.Affected, vuln.References = slices.Clone(vuln.CVE), slices.Clone(vuln.Affected), slices.Clone(vuln.References)
		vuln.Sources = []string{"cmsrecon"}
		switch {
		case v == nil || v.Number == "":
			vuln.Verdict, vuln.Note = VerdictPossible, "The TimThumb version is unknown"
		case vulndb.Compare(v.Number, a.below) >= 0, a.from != "" && vulndb.Compare(v.Number, a.from) < 0:
			continue
		case a.optional != "":
			vuln.Verdict, vuln.Note = VerdictLikely, a.optional
		default:
			vuln.Verdict = VerdictConfirmed
		}
		vuln.Exploits = s.exploitsFor(vuln.CVE, nil)
		out = append(out, vuln)
	}
	return out
}
