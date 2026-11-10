package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/scan"
)

// WriteMarkdown writes the report as Markdown (GitHub flavour), for a
// ticket, a wiki or a pull request. Values from the target are escaped, so
// a page title cannot add links, images or HTML to the report.
func WriteMarkdown(w io.Writer, r *scan.Result) error {
	if r.Summary == nil {
		r.Summary = scan.Summarize(r)
	}
	m := &mdWriter{w: w}
	m.line("# WordPress scan report")
	m.line("")
	m.line("%s · %s · %s · %s %s", md(r.Target.EffectiveURL), r.StartedAt.Format("2006-01-02 15:04 UTC"), md(statusText(r)), md(r.Tool.Name), md(r.Tool.Version))

	m.heading("Summary")
	if len(r.Summary.Risks) > 0 {
		m.line("| Severity | What | Details |")
		m.line("|---|---|---|")
		for _, k := range r.Summary.Risks {
			what := md(k.Title)
			if k.Kind != "finding" {
				what = md(k.Component) + ": " + md(scan.ShortTitle(k.Title))
			}
			var details []string
			if k.Verdict != "" {
				details = append(details, k.Verdict)
			}
			if len(k.CVE) > 0 {
				details = append(details, md(strings.Join(k.CVE, ", ")))
			}
			if k.Exploit {
				details = append(details, "**public exploit**")
			}
			if k.URL != "" {
				details = append(details, mdURL(k.URL))
			}
			m.line("| %s | %s | %s |", severityLabel(k.Severity), what, strings.Join(details, " · "))
		}
		if r.Summary.MoreRisks > 0 {
			m.line("")
			m.line("%d more below.", r.Summary.MoreRisks)
		}
	} else if r.Summary.VulnerabilitiesChecked {
		m.line("No critical, high or medium finding, and no confirmed or likely vulnerability.")
	} else {
		m.line("No critical, high or medium finding; vulnerabilities were **not checked** (no vulnerability data: run `cmsrecon update`).")
	}
	if r.Stop != nil {
		m.line("")
		m.line("**Scan stopped:** %s %s", md(r.Stop.Message), md(r.Stop.Hint))
	}
	if len(r.Notices) > 0 {
		m.line("")
		for _, n := range r.Notices {
			m.line("- %s", md(n))
		}
	}

	m.heading(fmt.Sprintf("Interesting findings (%d)", len(r.InterestingFindings)))
	if len(r.InterestingFindings) == 0 {
		m.line("None.")
	}
	for _, f := range r.InterestingFindings {
		m.line("- %s %s", severityLabel(f.Severity), md(f.Title))
		if f.URL != "" {
			m.line("  - %s", mdURL(f.URL))
		}
		for _, e := range f.Entries {
			m.line("  - %s", md(e))
		}
	}

	m.heading("WordPress")
	if r.Version != nil {
		m.line("Version: **%s**", md(versionText(r.Version)))
		m.vulns(r.CoreVulnerabilities, r.CorePossible, r.Version)
	} else {
		m.line("Version not detected.")
	}

	m.heading("Themes")
	themes := themeList(r)
	if len(themes) == 0 {
		m.line("None found.")
	}
	for _, t := range themes {
		m.subheading(fmt.Sprintf("%s (%s)", t.Slug, themeRole(r, t)))
		if t.Name != "" {
			m.line("- Name: %s", md(t.Name))
		}
		m.line("- Version: %s", md(versionText(t.Version)))
		if src := versionSource(t.Version); src != "" {
			m.line("- Version from: %s", md(src))
		}
		if t.StyleURL != "" {
			m.line("- Style: %s", mdURL(t.StyleURL))
		} else if found := foundBy(t.Evidence); found != "" {
			m.line("- Found by: %s", md(found))
		}
		if t.LastUpdated != "" {
			m.line("- Last updated: %s (on WordPress.org)", md(t.LastUpdated))
		}
		for _, w := range t.Warnings {
			m.line("- **%s**", md(w))
		}
		m.vulns(t.Vulnerabilities, t.Possible, t.Version)
	}

	m.heading(fmt.Sprintf("Plugins (%d)", len(r.Plugins)))
	if len(r.Plugins) == 0 {
		m.line("None found.")
	}
	for _, p := range r.Plugins {
		title := p.Slug
		if p.Name != "" {
			title += " (" + p.Name + ")"
		}
		m.subheading(title)
		m.line("- Version: %s", md(versionText(p.Version)))
		if src := versionSource(p.Version); src != "" {
			m.line("- Version from: %s", md(src))
		}
		if found := foundBy(p.Evidence); found != "" {
			m.line("- Found by: %s", md(found))
		}
		if p.LastUpdated != "" {
			m.line("- Last updated: %s (on WordPress.org)", md(p.LastUpdated))
		}
		m.line("- Confidence: %d%%", p.Confidence)
		for _, w := range p.Warnings {
			m.line("- **%s**", md(w))
		}
		m.vulns(p.Vulnerabilities, p.Possible, p.Version)
		if len(p.Exploits) > 0 {
			m.line("")
			m.line("Exploits that name this plugin but no CVE (check that they apply):")
			m.line("")
			for _, e := range p.Exploits {
				m.line("- %s", mdExploit(e))
			}
		}
	}

	m.heading(fmt.Sprintf("JavaScript libraries (%d)", len(r.JSLibraries)))
	if len(r.JSLibraries) == 0 {
		m.line("None found.")
	}
	for _, l := range r.JSLibraries {
		title := l.Name
		if l.Version != nil && l.Version.Number != "" {
			title += " " + l.Version.Number
		}
		m.subheading(title)
		if l.Bundled {
			m.line("The copy WordPress ships in wp-includes: it is updated with WordPress.")
			m.line("")
		}
		for _, u := range l.URLs {
			m.line("- %s", mdURL(u))
		}
		m.vulns(l.Vulnerabilities, nil, l.Version)
	}

	if len(r.Users) > 0 {
		m.heading(fmt.Sprintf("Users (%d)", len(r.Users)))
		m.line("| ID | Username | Display name | Confidence |")
		m.line("|---|---|---|---|")
		for _, u := range r.Users {
			id := ""
			if u.ID != 0 {
				id = fmt.Sprint(u.ID)
			}
			name := md(u.Username)
			if name == "" {
				name = "*(display name only)*"
			}
			m.line("| %s | %s | %s | %d%% |", id, name, md(u.DisplayName), u.Confidence)
		}
	}

	if len(r.Timthumbs) > 0 {
		m.heading(fmt.Sprintf("Timthumbs (%d)", len(r.Timthumbs)))
		for _, t := range r.Timthumbs {
			m.subheading(t.URL)
			m.line("- Version: %s", md(versionText(t.Version)))
			m.vulns(t.Vulnerabilities, nil, t.Version)
		}
	}

	if len(r.Media) > 0 {
		m.heading(fmt.Sprintf("Media (%d)", len(r.Media)))
		m.line("| ID | File | Kind |")
		m.line("|---|---|---|")
		for i, x := range r.Media {
			if i == 100 {
				m.line("")
				m.line("%d more in the JSON report.", len(r.Media)-100)
				break
			}
			file := mdURL(x.URL)
			if x.URL == "" {
				file = mdURL(x.PageURL) + " (attachment page)"
			}
			m.line("| %d | %s | %s |", x.ID, file, md(scan.MediaKind(x)))
		}
	}

	m.heading("Scan")
	target := mdURL(r.Target.URL)
	if r.Target.EffectiveURL != r.Target.URL {
		target += " → " + mdURL(r.Target.EffectiveURL)
	}
	m.line("- Target: %s", target)
	m.line("- Started: %s, finished: %s", r.StartedAt.Format("2006-01-02 15:04:05 UTC"), r.FinishedAt.Format("2006-01-02 15:04:05 UTC"))
	mode := r.DetectionMode
	if o := r.Options; o != nil && o.Enumerate != "" {
		mode += fmt.Sprintf("; plugins %s, themes %s; -e %s; %d threads", o.PluginsDetection, o.ThemesDetection, o.Enumerate, o.Threads)
	}
	m.line("- Detection mode: %s", md(mode))
	req := fmt.Sprintf("%d (%s sent, %s received) in %s", r.Stats.Requests, formatBytes(r.Stats.BytesSent), formatBytes(r.Stats.BytesReceived), formatSeconds(r.Stats.ElapsedSeconds))
	if r.Stats.FailedRequests > 0 {
		req += fmt.Sprintf("; %d failed", r.Stats.FailedRequests)
	}
	if r.Stats.Blocked > 0 {
		req += fmt.Sprintf("; %d refused (rate limit, firewall)", r.Stats.Blocked)
	}
	m.line("- Requests: %s", req)
	m.line("- User-Agent: %s", md(r.Tool.UserAgent))
	m.line("- Vulnerability data: %s", md(sourcesText(r.VulnerabilityData)))
	m.line("- Vulnerabilities: %s", countsText(r.VulnerabilityCounts))
	m.line("")
	m.line("*Exploit links point to public code that cmsrecon never downloads or runs; review any code before running it, and only against systems you are authorized to test.*")
	return m.err
}

type mdWriter struct {
	w     io.Writer
	err   error
	blank bool // the last line was empty
}

func (m *mdWriter) line(format string, args ...any) {
	if format == "" && m.blank || m.err != nil {
		return
	}
	m.blank = format == ""
	_, m.err = fmt.Fprintf(m.w, format+"\n", args...)
}

func (m *mdWriter) heading(s string) {
	m.line("")
	m.line("## %s", md(s))
	m.line("")
}

func (m *mdWriter) subheading(s string) {
	m.line("")
	m.line("### %s", md(s))
	m.line("")
}

func (m *mdWriter) vulns(vs []scan.Vulnerability, possible *scan.PossibleVulns, v *scan.Version) {
	if len(vs) > 0 {
		m.line("")
		m.line("| Severity | Vulnerability | Details |")
		m.line("|---|---|---|")
		for _, x := range vs {
			details := []string{x.Verdict}
			if x.Verdict == scan.VerdictConfirmed {
				details[0] = "**confirmed**"
			}
			if len(x.CVE) > 0 {
				details = append(details, md(strings.Join(x.CVE, ", ")))
			}
			if x.CVSS > 0 {
				details = append(details, fmt.Sprintf("CVSS %.1f", x.CVSS))
			}
			switch {
			case x.FixedIn != "":
				details = append(details, "fixed in "+md(x.FixedIn))
			case x.Unfixed:
				details = append(details, "no fix available")
			}
			if len(x.Exploits) > 0 {
				details = append(details, "public exploits: "+exploitCounts(x.Exploits))
				for _, e := range x.Exploits {
					details = append(details, mdExploit(e))
				}
			}
			if len(x.References) > 0 {
				details = append(details, mdURL(x.References[0]))
			}
			title := md(scan.ShortTitle(x.Title))
			if x.Note != "" {
				title += "<br>*" + md(x.Note) + "*"
			}
			m.line("| %s | %s | %s |", severityLabel(x.Severity), title, strings.Join(details, "<br>"))
		}
	}
	if possible != nil && !possible.Listed {
		m.line("")
		m.line("%s", md(possibleText(possible, v)))
	}
}

func severityLabel(s string) string {
	if s == "" {
		return "UNRATED"
	}
	return "**" + strings.ToUpper(s) + "**"
}

// mdEscaper escapes what Markdown or HTML would read as markup, and keeps
// each value on one line (tables need it).
var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"<", `\<`, ">", `\>`, "|", `\|`, "#", `\#`, "~", `\~`, "!", `\!`, "&", `&amp;`,
	"\r\n", " ", "\n", " ", "\r", " ",
)

// mdURL writes a link as an autolink, which Markdown leaves as it is;
// anything else is escaped as text.
func mdURL(u string) string {
	if (strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) && !strings.ContainsAny(u, " <>|`\\\"'\t\r\n") {
		return "<" + u + ">"
	}
	return md(u)
}

// mdExploit is exploitLine with its link as an autolink.
func mdExploit(e scan.Exploit) string {
	line := exploitLine(e)
	if text, ok := strings.CutSuffix(line, e.URL); ok && e.URL != "" {
		return md(text) + mdURL(e.URL)
	}
	return md(line)
}

// md escapes a value from the target for Markdown.
func md(s string) string {
	return mdEscaper.Replace(s)
}
