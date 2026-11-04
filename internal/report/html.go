package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/scan"
)

// WriteHTML writes the report as one self-contained HTML page: no
// script, no external file, readable offline and printable. Every value
// from the target is escaped.
func WriteHTML(w io.Writer, r *scan.Result) error {
	if r.Summary == nil {
		r.Summary = scan.Summarize(r)
	}
	return htmlTemplate.Execute(w, r)
}

var htmlFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"join":  strings.Join,
	"short": scan.ShortTitle,
	"sev": func(s string) string {
		if s == "" {
			return "unrated"
		}
		return s
	},
	"version":    versionText,
	"exploits":   exploitCounts,
	"exploitRow": exploitLine,
	"possible":   possibleText,
	"themes":     themeList,
	"role":       themeRole,
	"bytes":      formatBytes,
	"seconds":    formatSeconds,
	"counts":     countsText,
	"status":     statusText,
	"first":      func(n int, ms []*scan.Media) []*scan.Media { return ms[:min(n, len(ms))] },
	"minus":      func(a, b int) int { return a - b },
	"kind":       scan.MediaKind,
	"sources":    sourcesText,
}

// statusText says how the scan ended, for the reports.
func statusText(r *scan.Result) string {
	switch r.Status {
	case scan.StatusCompleted:
		return "completed"
	case scan.StatusStopped:
		return "stopped at pre-flight"
	case scan.StatusInterrupted:
		return "interrupted: the results are partial"
	case scan.StatusTimedOut:
		return "stopped at --max-scan-duration: the results are partial"
	case scan.StatusBlocked:
		return "stopped because the target kept failing or refusing requests: the results are partial"
	}
	return r.Status
}

// sourcesText lists the vulnerability data the scan used, with its dates.
func sourcesText(d *scan.DataInfo) string {
	if d == nil || len(d.Sources) == 0 {
		return "none: run \"cmsrecon update\""
	}
	var parts []string
	for _, s := range d.Sources {
		name := sourceNames[s.Name]
		if name == "" {
			name = s.Name
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", name, s.UpdatedAt.Format("2006-01-02")))
	}
	return strings.Join(parts, ", ")
}

// themeList is the main theme, its parents, then the other themes.
func themeList(r *scan.Result) []*scan.Theme {
	var out []*scan.Theme
	for t := r.MainTheme; t != nil; t = t.Parent {
		out = append(out, t)
	}
	return append(out, r.Themes...)
}

// themeRole says what a theme from themeList is.
func themeRole(r *scan.Result, t *scan.Theme) string {
	switch {
	case t == r.MainTheme:
		return "main theme"
	case r.MainTheme != nil && t == r.MainTheme.Parent:
		return "parent theme"
	}
	return "installed"
}

var htmlTemplate = template.Must(template.New("report").Funcs(htmlFuncs).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WordPress scan: {{.Target.EffectiveURL}}</title>
<style>
:root { --fg: #1d2330; --muted: #5d6577; --line: #d9dde5; --bg: #ffffff; --panel: #f5f7fa;
  --critical: #a1131f; --high: #c2410c; --medium: #a16207; --low: #2563eb; --info: #4b5563; --ok: #15803d; }
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px 48px; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--fg); background: var(--bg); }
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 2px solid var(--line); }
h3 { font-size: 16px; margin: 20px 0 6px; }
.meta { color: var(--muted); margin: 0 0 16px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; table-layout: auto; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
th { background: var(--panel); font-weight: 600; }
table tr:first-child th { white-space: nowrap; } td:first-child { white-space: nowrap; }
.badge { display: inline-block; min-width: 72px; text-align: center; padding: 1px 6px; border-radius: 4px; color: #fff; font-size: 12px; font-weight: 700; text-transform: uppercase; }
.critical { background: var(--critical); } .high { background: var(--high); } .medium { background: var(--medium); }
.low { background: var(--low); } .info, .unrated { background: var(--info); }
.verdict-confirmed { font-weight: 700; } .muted { color: var(--muted); }
.card { border: 1px solid var(--line); border-radius: 6px; padding: 10px 14px; margin: 10px 0; }
.card h3 { margin-top: 0; } ul { margin: 4px 0; padding-left: 20px; }
.ok { color: var(--ok); font-weight: 600; } .warn { color: var(--high); font-weight: 600; }
code { font-size: 13px; background: var(--panel); padding: 0 3px; border-radius: 3px; }
@media print { body { padding: 0; } h2 { break-after: avoid; } .card, tr { break-inside: avoid; } }
</style>
</head>
<body>
<main>
<h1>WordPress scan report</h1>
<p class="meta">{{.Target.EffectiveURL}} · {{.StartedAt.Format "2006-01-02 15:04 UTC"}} · {{status .}} · {{.Tool.Name}} {{.Tool.Version}}</p>

<h2>Summary</h2>
{{if .Summary.Risks}}
<table>
<tr><th>Severity</th><th>What</th><th>Details</th></tr>
{{range .Summary.Risks}}<tr><td><span class="badge {{sev .Severity}}">{{sev .Severity}}</span></td>
<td>{{if eq .Kind "finding"}}{{.Title}}{{if .URL}}<br><span class="muted">{{.URL}}</span>{{end}}{{else}}{{.Component}}: {{short .Title}}{{end}}</td>
<td>{{if .Verdict}}{{.Verdict}}{{end}}{{if .CVE}} · {{join .CVE ", "}}{{end}}{{if .Exploit}} · <span class="warn">public exploit</span>{{end}}</td></tr>
{{end}}</table>
{{if .Summary.MoreRisks}}<p class="muted">{{.Summary.MoreRisks}} more below.</p>{{end}}
{{else}}<p class="ok">No critical, high or medium finding{{if .Summary.VulnerabilitiesChecked}}, and no confirmed or likely vulnerability{{else}}; vulnerabilities were not checked (no vulnerability data){{end}}.</p>{{end}}
{{if .Stop}}<p class="warn">Scan stopped: {{.Stop.Message}} {{.Stop.Hint}}</p>{{end}}
{{if .Notices}}<h3>Notices</h3><ul>{{range .Notices}}<li>{{.}}</li>{{end}}</ul>{{end}}

<h2>Interesting findings ({{len .InterestingFindings}})</h2>
{{if .InterestingFindings}}<table>
<tr><th>Severity</th><th>Finding</th><th>Details</th></tr>
{{range .InterestingFindings}}<tr><td><span class="badge {{sev .Severity}}">{{sev .Severity}}</span></td><td>{{.Title}}{{if .URL}}<br><span class="muted">{{.URL}}</span>{{end}}</td>
<td>{{if .Entries}}<ul>{{range .Entries}}<li>{{.}}</li>{{end}}</ul>{{end}}</td></tr>
{{end}}</table>{{else}}<p class="muted">None.</p>{{end}}

<h2>WordPress</h2>
{{if .Version}}<p>Version: <strong>{{version .Version}}</strong></p>
{{template "vulns" .CoreVulnerabilities}}{{if .CorePossible}}<p class="muted">{{possible .CorePossible .Version}}</p>{{end}}{{else}}<p class="muted">Not detected.</p>{{end}}

<h2>Themes</h2>
{{$r := .}}{{range themes .}}<div class="card"><h3>{{.Slug}} <span class="muted">({{role $r .}})</span></h3>
<table>{{if .Name}}<tr><th>Name</th><td>{{.Name}}</td></tr>{{end}}<tr><th>Version</th><td>{{version .Version}}</td></tr><tr><th>Location</th><td>{{.Location}}</td></tr>
{{if .LastUpdated}}<tr><th>Last updated</th><td>{{.LastUpdated}} (on WordPress.org)</td></tr>{{end}}</table>
{{range .Warnings}}<p class="warn">{{.}}</p>{{end}}
{{template "vulns" .Vulnerabilities}}{{if .Possible}}<p class="muted">{{possible .Possible .Version}}</p>{{end}}</div>
{{else}}<p class="muted">None found.</p>{{end}}

<h2>Plugins ({{len .Plugins}})</h2>
{{range .Plugins}}<div class="card"><h3>{{.Slug}}{{if .Name}} <span class="muted">({{.Name}})</span>{{end}}</h3>
<table><tr><th>Version</th><td>{{version .Version}}</td></tr>{{if .Location}}<tr><th>Location</th><td>{{.Location}}</td></tr>{{end}}
{{if .LastUpdated}}<tr><th>Last updated</th><td>{{.LastUpdated}} (on WordPress.org)</td></tr>{{end}}<tr><th>Confidence</th><td>{{.Confidence}}%</td></tr></table>
{{range .Warnings}}<p class="warn">{{.}}</p>{{end}}
{{template "vulns" .Vulnerabilities}}{{if .Possible}}<p class="muted">{{possible .Possible .Version}}</p>{{end}}
{{if .Exploits}}<p><strong>Exploits that name this plugin but no CVE</strong> (check that they apply):</p><ul>{{range .Exploits}}<li>{{exploitRow .}}</li>{{end}}</ul>{{end}}
</div>{{else}}<p class="muted">None found.</p>{{end}}

<h2>JavaScript libraries ({{len .JSLibraries}})</h2>
{{range .JSLibraries}}<div class="card"><h3>{{.Name}} {{if .Version}}{{.Version.Number}}{{end}}</h3>
{{if .Bundled}}<p class="muted">The copy WordPress ships in wp-includes: it is updated with WordPress.</p>{{end}}
<ul>{{range .URLs}}<li>{{.}}</li>{{end}}</ul>{{template "vulns" .Vulnerabilities}}</div>
{{else}}<p class="muted">None found.</p>{{end}}

{{if .Users}}<h2>Users ({{len .Users}})</h2>
<table><tr><th>ID</th><th>Username</th><th>Display name</th><th>Confidence</th></tr>
{{range .Users}}<tr><td>{{if .ID}}{{.ID}}{{end}}</td><td>{{if .Username}}{{.Username}}{{else}}<span class="muted">(display name only)</span>{{end}}</td><td>{{.DisplayName}}</td><td>{{.Confidence}}%</td></tr>
{{end}}</table>{{end}}

{{if .Timthumbs}}<h2>Timthumbs ({{len .Timthumbs}})</h2>
{{range .Timthumbs}}<div class="card"><h3>{{.URL}}</h3><p>Version: {{version .Version}}</p>{{template "vulns" .Vulnerabilities}}</div>{{end}}{{end}}

{{if .Media}}<h2>Media ({{len .Media}})</h2>
<table><tr><th>ID</th><th>File</th><th>Kind</th></tr>
{{range first 100 .Media}}<tr><td>{{.ID}}</td><td>{{if .URL}}{{.URL}}{{else}}{{.PageURL}} <span class="muted">(attachment page)</span>{{end}}</td><td>{{kind .}}{{if .MimeType}} <span class="muted">({{.MimeType}})</span>{{end}}</td></tr>
{{end}}</table>{{if gt (len .Media) 100}}<p class="muted">{{minus (len .Media) 100}} more in the JSON report.</p>{{end}}{{end}}

<h2>Scan</h2>
<table>
<tr><th>Target</th><td>{{.Target.URL}}{{if ne .Target.URL .Target.EffectiveURL}} → {{.Target.EffectiveURL}}{{end}}</td></tr>
<tr><th>Started, finished</th><td>{{.StartedAt.Format "2006-01-02 15:04:05 UTC"}}, {{.FinishedAt.Format "2006-01-02 15:04:05 UTC"}}</td></tr>
<tr><th>Detection mode</th><td>{{.DetectionMode}}{{with .Options}}; plugins {{.PluginsDetection}}, themes {{.ThemesDetection}}; -e {{.Enumerate}}; {{.Threads}} threads{{if .Throttle}}, {{.Throttle}} between requests{{end}}{{end}}</td></tr>
<tr><th>Requests</th><td>{{.Stats.Requests}} ({{bytes .Stats.BytesSent}} sent, {{bytes .Stats.BytesReceived}} received) in {{seconds .Stats.ElapsedSeconds}}{{if .Stats.FailedRequests}}; {{.Stats.FailedRequests}} failed{{end}}{{if .Stats.Blocked}}; {{.Stats.Blocked}} refused (rate limit, firewall){{end}}</td></tr>
<tr><th>User-Agent</th><td>{{.Tool.UserAgent}}</td></tr>
<tr><th>Vulnerability data</th><td>{{sources .VulnerabilityData}}</td></tr>
<tr><th>Vulnerabilities</th><td>{{counts .VulnerabilityCounts}}</td></tr>
</table>
<p class="muted">Generated by {{.Tool.Name}} {{.Tool.Version}}. Exploit links point to public code that cmsrecon never downloads or runs; review any code before running it, and only against systems you are authorized to test.</p>
</main>
</body>
</html>
{{define "vulns"}}{{if .}}<table><tr><th>Severity</th><th>Vulnerability</th><th>Details</th></tr>
{{range .}}<tr><td><span class="badge {{sev .Severity}}">{{sev .Severity}}</span></td><td>{{short .Title}}{{if .Note}}<br><span class="muted">{{.Note}}</span>{{end}}</td>
<td><span class="verdict-{{.Verdict}}">{{.Verdict}}</span>{{if .CVE}} · {{join .CVE ", "}}{{end}}{{if .CVSS}} · CVSS {{printf "%.1f" .CVSS}}{{end}}{{if .FixedIn}} · fixed in {{.FixedIn}}{{else if .Unfixed}} · no fix available{{end}}
{{if .Exploits}}<br><strong>Public exploits:</strong> {{exploits .Exploits}}<ul>{{range .Exploits}}<li>{{exploitRow .}}</li>{{end}}</ul>{{end}}
{{if .References}}<br><span class="muted">{{index .References 0}}</span>{{end}}</td></tr>
{{end}}</table>{{end}}{{end}}`))
