// Command cmsrecon is a WordPress reconnaissance scanner for authorized
// security assessments.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/report"
	"github.com/theodoros997/cmsrecon/internal/scan"
	"github.com/theodoros997/cmsrecon/internal/update"
)

// Exit codes, documented in the scan usage and the README.
const (
	exitOK          = 0   // the scan completed
	exitError       = 1   // cmsrecon itself failed, e.g. the report could not be written
	exitUsage       = 2   // invalid command line
	exitStopped     = 3   // a pre-flight check stopped the scan; the report says why
	exitVulnerable  = 5   // the scan completed and found confirmed or likely vulnerabilities, as WPScan's 5
	exitInterrupted = 130 // interrupted with Ctrl-C; the partial report is still written
)

const usage = `cmsrecon - WordPress reconnaissance for authorized security assessments

Usage:
  cmsrecon scan [options] URL   Scan a WordPress site (run "cmsrecon scan -h" for options)
  cmsrecon -u URL [options]     Same as "scan", WPScan style
  cmsrecon update               Download or refresh the vulnerability database
  cmsrecon version              Print the version

Only scan sites you are authorized to test.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "update":
		return runUpdate(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, buildinfo.String())
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	if strings.HasPrefix(args[0], "-") {
		return runScan(args, stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := cli.ParseScan(args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\nRun \"cmsrecon scan -h\" for usage.\n", err)
		return exitUsage
	}
	if opts.DryRun {
		printPlan(stdout, opts)
		return exitOK
	}

	out := stdout
	if opts.Output != "" {
		f, err := os.Create(opts.Output)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		defer f.Close()
		out = f
	}
	client, err := httpclient.New(opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	toTerminal := opts.Format == cli.FormatCLI && opts.Output == ""

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	scanner := scan.New(opts, client)
	var prog *progress
	// The progress line needs a terminal that understands escape codes.
	if report.ColorEnabled(stderr) {
		prog = &progress{w: stderr}
		scanner.Progress = prog.update
	}
	res := scanner.Run(ctx, nil)
	prog.clear()

	// The CLI report on stdout carries the notices; anywhere else the user
	// would not see them, so print them now.
	if !toTerminal {
		for _, n := range res.Notices {
			fmt.Fprintln(stderr, "notice:", n)
		}
	}

	if opts.Format == cli.FormatJSON {
		err = report.WriteJSON(out, res)
	} else {
		err = report.WriteCLI(out, res, report.Options{
			Color:   toTerminal && !opts.NoColor && report.ColorEnabled(stdout),
			Verbose: opts.Verbose,
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: writing the report: %v\n", err)
		return exitError
	}
	if !toTerminal && res.Stop != nil {
		fmt.Fprintf(stderr, "scan stopped: %s %s\n", res.Stop.Message, res.Stop.Hint)
	}
	if opts.Output != "" {
		fmt.Fprintf(stderr, "Report written to %s\n", opts.Output)
	}

	return scanExit(res)
}

// scanExit is the exit code of a scan that wrote its report.
func scanExit(res *scan.Result) int {
	switch {
	case res.Status == scan.StatusStopped:
		return exitStopped
	case res.Status == scan.StatusInterrupted:
		return exitInterrupted
	case res.VulnerabilityCounts.Confirmed+res.VulnerabilityCounts.Likely > 0:
		return exitVulnerable
	}
	return exitOK
}

func runUpdate(args []string, stdout, stderr io.Writer) int {
	o, err := cli.ParseUpdate(args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\nRun \"cmsrecon update -h\" for usage.\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(stderr, "Updating the data in %s\n", o.DataDir)
	results, err := update.Run(ctx, update.Options{
		DataDir:      o.DataDir,
		Sources:      o.Sources,
		WordfenceKey: o.WordfenceKey,
		GitHubToken:  os.Getenv("GITHUB_TOKEN"),
		Proxy:        o.Proxy,
		Timeout:      o.Timeout,
		Endpoints:    update.DefaultEndpoints,
		Log:          stderr,
	})
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(stdout, "[!] %s failed: %v\n", update.Label(r.Source), r.Err)
		case r.Skipped:
			fmt.Fprintf(stdout, "[i] %s skipped: %s\n", update.Label(r.Source), r.Summary)
		default:
			fmt.Fprintf(stdout, "[+] %s: %s\n", update.Label(r.Source), r.Summary)
		}
	}
	switch {
	case ctx.Err() != nil:
		fmt.Fprintln(stderr, "Interrupted; the sources not finished keep their previous data.")
		return exitInterrupted
	case err != nil:
		return exitError
	}
	return exitOK
}

// printPlan describes what a scan with these options would do.
func printPlan(w io.Writer, o *cli.ScanOptions) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s:\t%s\n", k, v) }

	row("Target", o.Target.String())
	row("Detection mode", string(o.DetectionMode))
	e := o.Enumerate
	if o.WPAuth != nil {
		row("Plugins and themes", "REST API inventory as "+o.WPAuth.Username)
	} else {
		row("Plugins", detectionPlan(o, o.PluginsDetection, e.Plugins, o.PluginsList, "plugins"))
		row("Themes", detectionPlan(o, o.ThemesDetection, e.Themes, o.ThemesList, "themes"))
	}
	if o.ContentDir != "" {
		row("wp-content", o.ContentDir)
	}
	if o.PluginsDir != "" {
		row("Plugins folder", o.PluginsDir)
	}
	crawl := "homepage and 404 page only"
	if o.CrawlPages > 0 && o.DetectionMode != cli.ModePassive {
		crawl = fmt.Sprintf("up to %d more pages, plus the login page", o.CrawlPages)
	}
	row("Pages read", crawl)
	users := "no"
	if e.Users != nil {
		users = "author IDs " + e.Users.String()
	}
	row("Users", users)
	row("Config backups", yesNo(e.ConfigBackups))
	row("DB exports", yesNo(e.DBExports))
	row("Backup folders", yesNo(e.BackupFolders))

	concurrency := fmt.Sprintf("%d threads", o.Threads)
	if o.Throttle > 0 {
		concurrency = fmt.Sprintf("1 thread, %s between requests", o.Throttle)
	}
	row("Concurrency", concurrency)
	if o.Proxy != nil {
		row("Proxy", o.Proxy.Redacted())
	}
	dest := "stdout"
	if o.Output != "" {
		dest = o.Output
	}
	row("Report", fmt.Sprintf("%s to %s", o.Format, dest))
	row("Data", o.DataDir)
	tw.Flush()
}

// detectionPlan describes how plugins or themes will be found.
func detectionPlan(o *cli.ScanOptions, mode cli.DetectionMode, list cli.ItemSet, named []string, what string) string {
	var parts []string
	if mode.Discover() {
		parts = append(parts, "found on the site")
	}
	switch {
	case len(named) > 0 && o.DetectionMode == cli.ModePassive:
		parts = append(parts, fmt.Sprintf("no check of the named %s (%d) in passive detection mode", what, len(named)))
	case len(named) > 0:
		parts = append(parts, fmt.Sprintf("check of the named %s (%d)", what, len(named)))
	case mode.BruteForce() && o.DetectionMode == cli.ModePassive:
		parts = append(parts, "no brute force in passive detection mode")
	case mode.BruteForce() && list != cli.ItemsNone:
		parts = append(parts, fmt.Sprintf("brute force of %s %s", list, what))
	case mode.BruteForce():
		parts = append(parts, "nothing to brute-force (-e has no "+what+" list)")
	}
	return strings.Join(parts, ", then ")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// progress shows how far brute-force runs are on one terminal line.
type progress struct {
	w     io.Writer
	mu    sync.Mutex
	last  time.Time
	shown bool
}

func (p *progress) update(label string, done, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if done < total && time.Since(p.last) < 200*time.Millisecond {
		return
	}
	p.last = time.Now()
	p.shown = true
	fmt.Fprintf(p.w, "\r\x1b[K[i] %s: %d/%d", label, done, total)
}

// clear removes the progress line; it is safe on a nil progress.
func (p *progress) clear() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.shown {
		fmt.Fprint(p.w, "\r\x1b[K")
	}
}
