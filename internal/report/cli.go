package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/theodoros997/cmsrecon/internal/scan"
)

// Options controls the CLI report.
type Options struct {
	Color   bool // use ANSI colours
	Verbose bool // show how each finding was detected
}

// ANSI styles.
const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
)

var severityStyle = map[string]string{
	scan.SeverityCritical: bold + magenta,
	scan.SeverityHigh:     bold + red,
	scan.SeverityMedium:   yellow,
	scan.SeverityLow:      cyan,
	scan.SeverityInfo:     blue,
}

type printer struct {
	w   io.Writer
	o   Options
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

func (p *printer) style(style, s string) string {
	if !p.o.Color || style == "" {
		return s
	}
	return style + s + reset
}

func (p *printer) good(format string, args ...any) {
	p.printf("%s %s\n", p.style(green, "[+]"), fmt.Sprintf(format, args...))
}

func (p *printer) info(format string, args ...any) {
	p.printf("%s %s\n", p.style(blue, "[i]"), fmt.Sprintf(format, args...))
}

func (p *printer) bad(format string, args ...any) {
	p.printf("%s %s\n", p.style(red, "[!]"), fmt.Sprintf(format, args...))
}

// detail prints an indented line under an item.
func (p *printer) detail(format string, args ...any) {
	p.printf("    %s %s\n", p.style(dim, "|"), fmt.Sprintf(format, args...))
}

func (p *printer) heading(s string) {
	p.printf("\n%s\n", p.style(bold, s))
}

// WriteCLI writes a human-readable report.
func WriteCLI(w io.Writer, r *scan.Result, o Options) error {
	p := &printer{w: w, o: o}

	p.printf("%s %s - WordPress reconnaissance for authorized security assessments\n\n", p.style(bold, r.Tool.Name), r.Tool.Version)
	p.good("URL: %s", r.Target.URL)
	if r.Target.EffectiveURL != r.Target.URL {
		p.good("Effective URL: %s", r.Target.EffectiveURL)
	}
	p.good("Started: %s", r.StartedAt.Format("2006-01-02 15:04:05 MST"))
	p.good("Detection mode: %s", r.DetectionMode)
	for _, red := range r.Target.Redirects {
		p.info("Redirect: %s -> %s (HTTP %d, %s)", red.From, red.To, red.Status, redirectState(red))
	}
	if r.WebServer != nil && r.WebServer.Header != "" {
		p.good("Web server: %s", r.WebServer.Header)
	}
	if wp := r.WordPress; wp != nil {
		switch {
		case wp.Detected:
			p.good("WordPress detected")
		case r.Stop == nil:
			// Only --force lets a scan go on without WordPress; when it
			// stops, the stop message says why.
			p.bad("WordPress not detected; scanning anyway because of --force")
		}
		if o.Verbose {
			p.evidence("Found by", "", wp.Evidence)
			if wp.ContentURL != "" {
				p.detail("Content directory: %s", wp.ContentURL)
			}
		}
	}
	for _, n := range r.Notices {
		p.info("%s", n)
	}

	if r.Stop != nil {
		p.printf("\n")
		p.bad("%s %s", p.style(bold+red, "Scan stopped:"), r.Stop.Message)
		if r.Stop.Hint != "" {
			p.detail("%s", r.Stop.Hint)
		}
	}

	completed := r.Status == scan.StatusCompleted
	if len(r.InterestingFindings) > 0 || completed {
		p.findings(r.InterestingFindings)
	}
	if r.Version != nil {
		p.version(r.Version, r.CoreVulnerabilities)
	}
	if completed || r.MainTheme != nil {
		p.theme(r)
	}
	if completed || len(r.Themes) > 0 {
		p.themes(r.Themes)
	}
	if completed || len(r.Plugins) > 0 {
		p.plugins(r.Plugins)
	}
	if completed || len(r.JSLibraries) > 0 {
		p.jsLibraries(r.JSLibraries)
	}
	if len(r.Users) > 0 {
		p.users(r.Users)
	}
	if completed || r.Status == scan.StatusInterrupted {
		p.vulnSummary(r)
	}
	p.errors(r.Errors)

	p.printf("\n")
	if r.Status == scan.StatusInterrupted {
		p.bad("Scan interrupted: the results above are partial")
	}
	p.good("Finished in %s: %s, %s sent, %s received",
		formatSeconds(r.Stats.ElapsedSeconds), plural(int(r.Stats.Requests), "request"),
		formatBytes(r.Stats.BytesSent), formatBytes(r.Stats.BytesReceived))
	return p.err
}

func redirectState(r scan.Redirect) string {
	switch r.Reason {
	case scan.RedirectInScope:
		return "followed: in scope"
	case scan.RedirectFollowFlag:
		return "followed: --follow-redirect"
	case scan.RedirectOutOfScope:
		return "not followed: out of scope"
	}
	if r.Followed {
		return "followed"
	}
	return "not followed"
}

func (p *printer) findings(fs []scan.Finding) {
	p.heading(fmt.Sprintf("Interesting findings (%d)", len(fs)))
	if len(fs) == 0 {
		p.info("None")
		return
	}
	for i, f := range fs {
		if i > 0 {
			p.printf("\n")
		}
		label := p.style(severityStyle[f.Severity], fmt.Sprintf("%-8s", strings.ToUpper(f.Severity)))
		switch f.Severity {
		case scan.SeverityMedium, scan.SeverityHigh, scan.SeverityCritical:
			p.bad("%s %s", label, f.Title)
		default:
			p.good("%s %s", label, f.Title)
		}
		if f.URL != "" {
			p.detail("%s", f.URL)
		}
		for _, e := range f.Entries {
			p.detail("%s", e)
		}
		if f.Confidence < 100 {
			p.detail("Confidence: %d%%", f.Confidence)
		}
		if p.o.Verbose {
			for _, ref := range f.References {
				p.detail("Reference: %s", ref)
			}
			p.evidence("Found by", "", f.Evidence)
		}
	}
}

// evidence lists how something was detected (verbose mode) under a label
// such as "Found by", indented by indent.
func (p *printer) evidence(label, indent string, ev []scan.Evidence) {
	if len(ev) == 0 {
		return
	}
	p.detail("%s%s:", indent, label)
	for _, e := range ev {
		line := fmt.Sprintf("%s  - %s (%s, %d%%)", indent, e.Method, e.Mode, e.Confidence)
		if e.Value != "" {
			line += ": " + e.Value
		}
		p.detail("%s", line)
		if e.URL != "" && e.URL != e.Value {
			p.detail("%s    at %s", indent, p.style(dim, e.URL))
		}
	}
}

func (p *printer) version(v *scan.Version, vulns []scan.Vulnerability) {
	p.heading("WordPress version")
	switch {
	case v.Number != "" && hasStrongVulns(vulns):
		p.bad("%s (confidence %d%%)", p.style(bold, v.Number), v.Confidence)
	case v.Number != "":
		p.good("%s (confidence %d%%)", p.style(bold, v.Number), v.Confidence)
	case len(v.Candidates) > 0:
		c := v.Candidates[0]
		p.info("Unknown: the best guess, %s, has only %d%% confidence (below %d%%)", c.Number, c.Confidence, scan.MinVersionConfidence)
	default:
		p.info("Unknown: no version signal found")
	}
	if l := latestText(v); l != "" {
		p.detail("%s", l)
	}
	p.vulns(vulns, nil, nil, "")
	if p.o.Verbose {
		if len(v.Candidates) > 1 {
			var others []string
			for _, c := range v.Candidates[1:] {
				others = append(others, fmt.Sprintf("%s (%d%%)", c.Number, c.Confidence))
			}
			p.detail("Other candidates: %s", strings.Join(others, ", "))
		}
		p.evidence("Found by", "", v.Evidence)
	}
}

func (p *printer) theme(r *scan.Result) {
	p.heading("Main theme")
	t := r.MainTheme
	if t == nil {
		if r.DetectionMode == "aggressive" {
			p.info("Not detected: the main theme is found passively, and aggressive mode skips passive checks")
		} else {
			p.info("Not detected")
		}
		return
	}
	p.componentLine(t.Slug, t.Confidence, t.Vulnerabilities)
	p.themeDetails(t, "")
	if t.Parent != nil {
		p.detail("Parent theme: %s", t.Parent.Slug)
		p.themeDetails(t.Parent, "  ")
	}
}

func (p *printer) themes(ts []*scan.Theme) {
	p.heading(fmt.Sprintf("Other themes (%d)", len(ts)))
	if len(ts) == 0 {
		p.info("None found")
		return
	}
	for i, t := range ts {
		if i > 0 {
			p.printf("\n")
		}
		p.componentLine(t.Slug, t.Confidence, t.Vulnerabilities)
		p.themeDetails(t, "")
	}
}

func (p *printer) plugins(ps []*scan.Plugin) {
	p.heading(fmt.Sprintf("Plugins (%d)", len(ps)))
	if len(ps) == 0 {
		p.info("None found")
		return
	}
	for i, pl := range ps {
		if i > 0 {
			p.printf("\n")
		}
		p.componentLine(pl.Slug, pl.Confidence, pl.Vulnerabilities)
		p.detail("Location: %s", pl.Location)
		if pl.Name != "" {
			p.detail("Name: %s", pl.Name)
		}
		p.detail("Version: %s", versionText(pl.Version))
		p.itemNotes(pl.LastUpdated, pl.Warnings, "")
		if p.o.Verbose {
			if pl.ReadmeURL != "" {
				p.detail("Readme: %s", pl.ReadmeURL)
			}
			p.evidence("Found by", "", pl.Evidence)
			if pl.Version != nil {
				p.evidence("Version found by", "", pl.Version.Evidence)
			}
		}
		p.vulns(pl.Vulnerabilities, pl.Possible, pl.Version, "")
	}
}

func (p *printer) jsLibraries(libs []*scan.JSLibrary) {
	p.heading(fmt.Sprintf("JavaScript libraries (%d)", len(libs)))
	if len(libs) == 0 {
		p.info("None found")
		return
	}
	for i, l := range libs {
		if i > 0 {
			p.printf("\n")
		}
		name := l.Name
		if l.Version != nil && l.Version.Number != "" {
			name += " " + l.Version.Number
		}
		switch {
		case hasStrongVulns(l.Vulnerabilities):
			p.bad("%s", p.style(bold, name))
		default:
			p.good("%s", p.style(bold, name))
		}
		if l.Version == nil || l.Version.Number == "" {
			p.detail("Version: unknown")
		} else if l.Version.Confidence < 100 {
			p.detail("Version confidence: %d%%", l.Version.Confidence)
		}
		urls := l.URLs
		if !p.o.Verbose && len(urls) > 1 {
			urls = urls[:1]
		}
		for _, u := range urls {
			p.detail("%s", u)
		}
		if p.o.Verbose && l.Version != nil {
			p.evidence("Version found by", "", l.Version.Evidence)
		}
		p.vulns(l.Vulnerabilities, nil, nil, "")
	}
}

func (p *printer) users(us []*scan.User) {
	p.heading(fmt.Sprintf("Users (%d)", len(us)))
	for i, u := range us {
		if i > 0 {
			p.printf("\n")
		}
		label := u.Username
		if label == "" {
			label = fmt.Sprintf("%q (display name only; not a username)", u.DisplayName)
		}
		if u.ID != 0 {
			label += fmt.Sprintf(" (ID %d)", u.ID)
		}
		p.good("%s", p.style(bold, label))
		if u.Username != "" && u.DisplayName != "" && u.DisplayName != u.Username {
			p.detail("Display name: %s", u.DisplayName)
		}
		if u.Confidence < 100 {
			p.detail("Confidence: %d%%", u.Confidence)
		}
		if p.o.Verbose {
			p.evidence("Found by", "", u.Evidence)
		}
	}
}

// componentLine prints the first line of a theme or plugin: a warning
// when a confirmed or likely vulnerability applies.
func (p *printer) componentLine(slug string, confidence int, vulns []scan.Vulnerability) {
	if hasStrongVulns(vulns) {
		p.bad("%s (confidence %d%%)", p.style(bold, slug), confidence)
	} else {
		p.good("%s (confidence %d%%)", p.style(bold, slug), confidence)
	}
}

func hasStrongVulns(vs []scan.Vulnerability) bool {
	for _, v := range vs {
		if v.Verdict != scan.VerdictPossible {
			return true
		}
	}
	return false
}

// versionText describes a component version and how it compares with the
// latest release.
func versionText(v *scan.Version) string {
	if v == nil || v.Number == "" {
		if v != nil && v.Latest != "" {
			return "unknown (the latest is " + v.Latest + ")"
		}
		return "unknown"
	}
	s := fmt.Sprintf("%s (confidence %d%%)", v.Number, v.Confidence)
	if l := latestText(v); l != "" {
		s += "; " + strings.ToLower(l[:1]) + l[1:]
	}
	return s
}

func latestText(v *scan.Version) string {
	switch {
	case v.Latest == "" || v.Number == "":
		return ""
	case v.Outdated:
		return "Outdated: the latest is " + v.Latest
	case v.Number == v.Latest:
		return "The latest release"
	}
	return ""
}

var verdictStyle = map[string]string{
	scan.VerdictConfirmed: bold,
	scan.VerdictLikely:    "",
	scan.VerdictPossible:  dim,
}

// vulns lists the vulnerabilities of a component. The possible ones are
// summed up in one line, unless the scan listed them (--possible).
func (p *printer) vulns(vs []scan.Vulnerability, possible *scan.PossibleVulns, v *scan.Version, indent string) {
	if len(vs) == 0 && possible == nil {
		return
	}
	var c scan.VulnCounts
	for _, v := range vs {
		switch v.Verdict {
		case scan.VerdictConfirmed:
			c.Confirmed++
		case scan.VerdictLikely:
			c.Likely++
		default:
			c.Possible++
		}
	}
	if len(vs) > 0 {
		p.detail("%s%s: %s", indent, p.style(bold, "Vulnerabilities"), countsText(c))
		for _, v := range vs {
			p.vuln(v, indent+"  ")
		}
	}
	if possible != nil && !possible.Listed {
		p.detail("%s%s", indent, possibleText(possible, v))
	}
}

// possibleText sums up, in one line, the vulnerabilities that only may
// apply: the version is unknown, or only a secondary source puts it in the
// affected range.
func possibleText(ps *scan.PossibleVulns, v *scan.Version) string {
	s := fmt.Sprintf("Possible vulnerabilities: %d", ps.Count)
	if sev := severityCounts(ps); sev != "" {
		s += " (" + sev + ")"
	}
	them := "them"
	if ps.Count == 1 {
		them = "it"
	}
	if ps.FixedIn != "" {
		all := "all fixed"
		if ps.Count == 1 {
			all = "fixed"
		}
		s += fmt.Sprintf(", %s in %s", all, ps.FixedIn)
	}
	why := "the version is unknown"
	if v != nil && v.Number != "" {
		why = "only a secondary source says " + v.Number + " is affected"
	}
	return s + " (not listed: " + why + "; --possible lists " + them + ")"
}

func severityCounts(ps *scan.PossibleVulns) string {
	var parts []string
	if ps.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", ps.Critical))
	}
	if ps.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", ps.High))
	}
	return strings.Join(parts, ", ")
}

func (p *printer) vuln(v scan.Vulnerability, indent string) {
	sev := strings.ToUpper(v.Severity)
	if sev == "" {
		sev = "UNRATED"
	}
	p.detail("%s%s %s", indent, p.style(severityStyle[v.Severity], "["+sev+"]"), v.Title)
	parts := []string{p.style(verdictStyle[v.Verdict], v.Verdict)}
	if len(v.CVE) > 0 {
		parts = append(parts, strings.Join(v.CVE, ", "))
	}
	if v.CVSS > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", v.CVSS))
	}
	switch {
	case v.FixedIn != "":
		parts = append(parts, "fixed in "+v.FixedIn)
	case v.Unfixed:
		parts = append(parts, "no fix available")
	}
	p.detail("%s  %s", indent, strings.Join(parts, " - "))
	if v.Note != "" {
		p.detail("%s  %s", indent, v.Note)
	}
	if p.o.Verbose {
		p.detail("%s  Affected: %s (%s)", indent, strings.Join(v.Affected, ", "), strings.Join(v.Sources, ", "))
		if v.CWE != "" {
			p.detail("%s  %s", indent, v.CWE)
		}
		for _, ref := range v.References {
			p.detail("%s  %s", indent, p.style(dim, ref))
		}
	} else if len(v.References) > 0 {
		p.detail("%s  %s", indent, p.style(dim, v.References[0]))
	}
}

func countsText(c scan.VulnCounts) string {
	var parts []string
	for _, x := range []struct {
		n    int
		what string
	}{{c.Confirmed, "confirmed"}, {c.Likely, "likely"}, {c.Possible, "possible"}} {
		if x.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", x.n, x.what))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

var sourceNames = map[string]string{
	"wordfence": "Wordfence", "cve": "CVE List", "wporg": "WordPress.org", "retirejs": "retire.js",
}

// listedPossible reports whether the scan listed the possible
// vulnerabilities (--possible).
func listedPossible(r *scan.Result) bool {
	for _, pl := range r.Plugins {
		if pl.Possible != nil {
			return pl.Possible.Listed
		}
	}
	for t := r.MainTheme; t != nil; t = t.Parent {
		if t.Possible != nil {
			return t.Possible.Listed
		}
	}
	for _, t := range r.Themes {
		if t.Possible != nil {
			return t.Possible.Listed
		}
	}
	return false
}

func (p *printer) vulnSummary(r *scan.Result) {
	p.heading("Vulnerabilities")
	c := r.VulnerabilityCounts
	text := countsText(c)
	if c.Possible > 0 && !listedPossible(r) {
		text += " (the possible ones are counted, not listed: --possible lists them)"
	}
	switch {
	case c.Confirmed+c.Likely > 0:
		p.bad("%s", text)
	case c.Possible > 0:
		p.info("%s", text)
	default:
		p.good("None matched")
	}
	if d := r.VulnerabilityData; d != nil && len(d.Sources) > 0 {
		var parts []string
		for _, s := range d.Sources {
			name := sourceNames[s.Name]
			if name == "" {
				name = s.Name
			}
			parts = append(parts, fmt.Sprintf("%s (%s)", name, s.UpdatedAt.Format("2006-01-02")))
		}
		p.detail("Data: %s", strings.Join(parts, ", "))
	} else {
		p.detail("No vulnerability data: run \"cmsrecon update\" to match vulnerabilities")
	}
}

// itemNotes prints when WordPress.org last saw an update of a plugin or
// theme, and what its folder exposes.
func (p *printer) itemNotes(updated string, warnings []string, indent string) {
	if updated != "" {
		p.detail("%sLast updated: %s (on WordPress.org)", indent, updated)
	}
	for _, w := range warnings {
		p.detail("%s%s %s", indent, p.style(yellow, "[!]"), w)
	}
}

func (p *printer) themeDetails(t *scan.Theme, indent string) {
	p.detail("%sLocation: %s", indent, t.Location)
	if t.Name != "" {
		p.detail("%sName: %s", indent, t.Name)
	}
	if t.Author != "" {
		author := t.Author
		if t.AuthorURI != "" {
			author += " (" + t.AuthorURI + ")"
		}
		p.detail("%sAuthor: %s", indent, author)
	}
	p.detail("%sVersion: %s", indent, versionText(t.Version))
	p.itemNotes(t.LastUpdated, t.Warnings, indent)
	if p.o.Verbose {
		p.evidence("Found by", indent, t.Evidence)
		if t.Version != nil {
			p.evidence("Version found by", indent, t.Version.Evidence)
		}
	}
	p.vulns(t.Vulnerabilities, t.Possible, t.Version, indent)
}

func (p *printer) errors(errs []scan.RequestError) {
	if len(errs) == 0 {
		return
	}
	p.printf("\n")
	if !p.o.Verbose {
		p.bad("%s failed; the checks that needed them reported nothing (use -v to list them)", plural(len(errs), "request"))
		return
	}
	p.bad("%s failed; the checks that needed them reported nothing:", plural(len(errs), "request"))
	for _, e := range errs {
		p.detail("%s: %s", e.URL, e.Error)
	}
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatSeconds(s float64) string {
	d := time.Duration(s * float64(time.Second))
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
