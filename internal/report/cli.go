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

	if len(r.InterestingFindings) > 0 || r.Status == scan.StatusCompleted {
		p.findings(r.InterestingFindings)
	}
	if r.Version != nil {
		p.version(r.Version)
	}
	if r.Status == scan.StatusCompleted || r.MainTheme != nil {
		p.theme(r)
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

func (p *printer) version(v *scan.Version) {
	p.heading("WordPress version")
	switch {
	case v.Number != "":
		p.good("%s (confidence %d%%)", p.style(bold, v.Number), v.Confidence)
	case len(v.Candidates) > 0:
		c := v.Candidates[0]
		p.info("Unknown: the best guess, %s, has only %d%% confidence (below %d%%)", c.Number, c.Confidence, scan.MinVersionConfidence)
	default:
		p.info("Unknown: no version signal found")
	}
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
	p.good("%s (confidence %d%%)", p.style(bold, t.Slug), t.Confidence)
	p.themeDetails(t, "")
	if t.Parent != nil {
		p.detail("Parent theme: %s", t.Parent.Slug)
		p.themeDetails(t.Parent, "  ")
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
	if t.Version != nil && t.Version.Number != "" {
		p.detail("%sVersion: %s (confidence %d%%)", indent, t.Version.Number, t.Version.Confidence)
	} else {
		p.detail("%sVersion: unknown", indent)
	}
	if p.o.Verbose {
		p.evidence("Found by", indent, t.Evidence)
		if t.Version != nil {
			p.evidence("Version found by", indent, t.Version.Evidence)
		}
	}
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
