// Command cmsrecon is a WordPress reconnaissance scanner for authorized
// security assessments.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/progress"
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
	exitTimedOut    = 4   // the scan reached --max-scan-duration; the partial report is still written
	exitVulnerable  = 5   // the scan completed and found confirmed or likely vulnerabilities, as WPScan's 5
	exitBlocked     = 6   // the target kept failing or refusing requests, so the scan stopped; the partial report is still written
	exitInterrupted = 130 // interrupted with Ctrl-C; the partial report is still written
)

const usage = `cmsrecon - WordPress reconnaissance for authorized security assessments

Usage:
  cmsrecon scan [options] URL   Scan a WordPress site (run "cmsrecon scan -h" for options)
  cmsrecon -u URL [options]     Same as "scan", WPScan style
  cmsrecon update               Download or refresh the vulnerability database
  cmsrecon report FILE.json     Render a saved JSON report as cli, html or md
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
	case "report":
		return runReport(args[1:], stdout, stderr)
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
	if strings.Contains(args[0], ".") || strings.Contains(args[0], "://") {
		fmt.Fprintf(stderr, "unknown command %q; to scan it, run:\n  cmsrecon scan %s\n", args[0], strings.Join(args, " "))
		return exitUsage
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
	if opts.Update {
		// The update's own output goes to stderr, so that stdout only
		// carries the report.
		switch runUpdate(updateArgs(opts), stderr, stderr) {
		case exitOK:
		case exitInterrupted:
			return exitInterrupted
		default:
			fmt.Fprintln(stderr, "warning: the update did not finish; scanning with the data already there")
		}
		fmt.Fprintln(stderr)
	}

	out := stdout
	var f *os.File
	if opts.Output != "" {
		if f, err = os.Create(opts.Output); err != nil {
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
	defer client.Close()

	toTerminal := opts.Format == cli.FormatCLI && opts.Output == ""

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	scanner := scan.New(opts, client)
	// The live status needs a terminal that understands escape codes.
	var live *progress.Terminal
	if !opts.NoProgress && report.ColorEnabled(stderr) {
		live = progress.NewTerminal(stderr, !opts.NoColor, func() string {
			return plural(int(client.Stats().Requests), "request")
		})
		scanner.Steps = live
		fmt.Fprintf(stderr, "Scanning %s\n", opts.Target)
	}
	res := scanner.Run(ctx, nil)
	if live != nil {
		live.Close()
		fmt.Fprintln(stderr)
	}

	// The CLI report on stdout carries the notices; anywhere else the user
	// would not see them, so print them now.
	if !toTerminal {
		for _, n := range res.Notices {
			fmt.Fprintln(stderr, "notice:", n)
		}
	}

	err = writeReport(out, res, opts.Format, report.Options{
		Color:   toTerminal && !opts.NoColor && report.ColorEnabled(stdout),
		Verbose: opts.Verbose,
	})
	if err == nil && opts.Output != "" {
		err = f.Close()
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: writing the report: %v\n", err)
		return exitError
	}
	if err := client.Close(); err != nil {
		fmt.Fprintf(stderr, "error: writing the request log: %v\n", err)
	}
	if !toTerminal {
		// The report went elsewhere: say in a few lines what it holds.
		if res.Stop != nil {
			fmt.Fprintln(stderr, strings.TrimSpace("scan stopped: "+res.Stop.Message+" "+res.Stop.Hint))
		} else {
			report.WriteBrief(stderr, res, report.Options{Color: !opts.NoColor && report.ColorEnabled(stderr)})
			fmt.Fprintln(stderr)
		}
	}
	if opts.Output != "" {
		fmt.Fprintf(stderr, "Report written to %s\n", opts.Output)
	}
	if opts.LogRequests != "" {
		fmt.Fprintf(stderr, "Requests logged to %s\n", opts.LogRequests)
	}

	return scanExit(res)
}

// writeReport writes a result in the chosen format.
func writeReport(w io.Writer, res *scan.Result, format cli.Format, o report.Options) error {
	switch format {
	case cli.FormatJSON:
		return report.WriteJSON(w, res)
	case cli.FormatHTML:
		return report.WriteHTML(w, res)
	case cli.FormatMarkdown:
		return report.WriteMarkdown(w, res)
	}
	return report.WriteCLI(w, res, o)
}

// updateArgs are the update command's arguments for scan --update: the
// scan's data directory, proxy, timeout and config file.
func updateArgs(o *cli.ScanOptions) []string {
	args := []string{"--data-dir", o.DataDir, "--timeout", o.Timeout.String()}
	if o.Proxy != nil {
		args = append(args, "--proxy", o.Proxy.String())
	}
	config := o.ConfigFile
	if config == "" {
		config = "none" // the scan read none
	}
	return append(args, "--config", config)
}

// runReport renders a saved JSON report in another format.
func runReport(args []string, stdout, stderr io.Writer) int {
	o, err := cli.ParseReport(args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\nRun \"cmsrecon report -h\" for usage.\n", err)
		return exitUsage
	}
	data, err := os.ReadFile(o.Input)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	res, err := report.ReadJSON(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s: %v\n", o.Input, err)
		return exitError
	}
	out := stdout
	var f *os.File
	if o.Output != "" {
		if f, err = os.Create(o.Output); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		defer f.Close()
		out = f
	}
	err = writeReport(out, res, o.Format, report.Options{
		Color:   o.Output == "" && !o.NoColor && report.ColorEnabled(stdout),
		Verbose: o.Verbose,
	})
	if err == nil && f != nil {
		err = f.Close()
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: writing the report: %v\n", err)
		return exitError
	}
	if o.Output != "" {
		fmt.Fprintf(stderr, "Report written to %s\n", o.Output)
	}
	return exitOK
}

// scanExit is the exit code of a scan that wrote its report.
func scanExit(res *scan.Result) int {
	switch {
	case res.Status == scan.StatusStopped:
		return exitStopped
	case res.Status == scan.StatusInterrupted:
		return exitInterrupted
	case res.Status == scan.StatusTimedOut:
		return exitTimedOut
	case res.Status == scan.StatusBlocked:
		return exitBlocked
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
	uo := update.Options{
		DataDir:      o.DataDir,
		Sources:      o.Sources,
		WordfenceKey: o.WordfenceKey,
		GitHubToken:  os.Getenv("GITHUB_TOKEN"),
		Proxy:        o.Proxy,
		Timeout:      o.Timeout,
		Endpoints:    update.DefaultEndpoints,
		Log:          stderr,
	}
	var live *progress.Terminal
	if report.ColorEnabled(stderr) {
		live = progress.NewTerminal(stderr, true, nil)
		live.ShowDurations(false) // the results say how long each source took
		uo.Steps = live
	}
	results, err := update.Run(ctx, uo)
	if live != nil {
		live.Close()
	}
	// The live lines already said what happened to each source when they
	// share the terminal with stdout.
	if live == nil || !report.ColorEnabled(stdout) {
		printUpdateResults(stdout, results)
	}
	if size, files := dataSize(o.DataDir); files > 0 {
		fmt.Fprintf(stdout, "[i] %s holds %s in %d files\n", o.DataDir, update.FormatSize(size), files)
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

func printUpdateResults(stdout io.Writer, results []update.Result) {
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(stdout, "[!] %s failed: %v\n", update.Label(r.Source), r.Err)
			if r.Summary != "" {
				fmt.Fprintf(stdout, "[i] %s stored what it could: %s\n", update.Label(r.Source), r.Summary)
			}
		case r.Skipped:
			fmt.Fprintf(stdout, "[i] %s skipped: %s\n", update.Label(r.Source), r.Summary)
		default:
			fmt.Fprintf(stdout, "[+] %s: %s\n", update.Label(r.Source), r.Summary)
		}
	}
}

// dataSize adds up the files in the data directory.
func dataSize(dir string) (int64, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	var total int64
	n := 0
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
			total += info.Size()
			n++
		}
	}
	return total, n
}

// printPlan describes what a scan with these options would do.
func printPlan(w io.Writer, o *cli.ScanOptions) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s:\t%s\n", k, v) }

	plan := scan.PlanScan(o)
	row("Target", o.Target.String())
	for _, host := range slices.Sorted(maps.Keys(o.Resolve)) {
		row("Connect to", o.Resolve[host]+" for "+host)
	}
	if len(o.Scope) > 0 {
		row("Also in scope", strings.Join(o.Scope, ", "))
	}
	row("Detection mode", string(o.DetectionMode))
	e := o.Enumerate
	if o.WPAuth != nil {
		row("Plugins and themes", "REST API inventory as "+o.WPAuth.Username)
	} else {
		row("Plugins", detectionPlan(o, o.PluginsDetection, e.Plugins, o.PluginsList, "plugins", plan))
		row("Themes", detectionPlan(o, o.ThemesDetection, e.Themes, o.ThemesList, "themes", plan))
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
	if o.LoginURI != "" {
		row("Login page", o.LoginURI)
	}
	users := "no"
	if e.Users != nil {
		users = "author IDs " + e.Users.String()
	}
	row("Users", users)
	media := "no"
	if e.Media != nil {
		media = "the REST API, or attachment IDs " + e.Media.String() + " when it is closed"
	}
	row("Media", media)
	row("Timthumbs", yesNo(e.Timthumbs))
	row("Config backups", yesNo(e.ConfigBackups))
	row("DB exports", yesNo(e.DBExports))
	row("Backup folders", yesNo(e.BackupFolders))

	concurrency := fmt.Sprintf("%d threads", o.Threads)
	if o.Throttle > 0 {
		concurrency = fmt.Sprintf("1 thread, %s between requests", o.Throttle)
	}
	row("Concurrency", concurrency)
	if o.MaxScanDuration > 0 {
		row("Max duration", o.MaxScanDuration.String())
	}
	if o.Proxy != nil {
		row("Proxy", o.Proxy.Redacted())
	}
	ua := httpclient.DefaultUserAgent()
	switch {
	case o.UserAgent != "":
		ua = o.UserAgent
	case o.RandomUserAgent:
		ua = "a random browser User-Agent"
	}
	row("User-Agent", ua)
	dest := "stdout"
	if o.Output != "" {
		dest = o.Output
	}
	row("Report", fmt.Sprintf("%s to %s", o.Format, dest))
	if o.LogRequests != "" {
		row("Request log", o.LogRequests)
	}
	if o.ConfigFile != "" {
		row("Config file", o.ConfigFile)
	}

	row("Data", dataPlan(o.DataDir, plan.Data))
	requests := fmt.Sprintf("about %d", plan.Requests)
	if o.DetectionMode != cli.ModePassive {
		requests += ", plus about 6 for each plugin and theme found"
	}
	if o.Update {
		requests += ", after \"cmsrecon update\" (--update)"
	}
	row("Requests", requests)
	if o.Throttle > 0 {
		row("Duration", "at least "+(time.Duration(plan.Requests)*o.Throttle).Round(time.Second).String()+" (--throttle)")
	}
	tw.Flush()
	for _, n := range plan.Notices {
		fmt.Fprintf(w, "\nNote: %s", n)
	}
	if len(plan.Notices) > 0 {
		fmt.Fprintln(w)
	}
}

// dataPlan describes the vulnerability data a scan would use.
func dataPlan(dir string, d *scan.DataInfo) string {
	if d == nil || len(d.Sources) == 0 {
		return dir + " (empty: run \"cmsrecon update\" or add --update)"
	}
	var parts []string
	oldest := time.Now()
	for _, src := range d.Sources {
		parts = append(parts, src.Name)
		if src.UpdatedAt.Before(oldest) {
			oldest = src.UpdatedAt
		}
	}
	age := "updated today"
	if days := int(time.Since(oldest).Hours() / 24); days == 1 {
		age = "1 day old"
	} else if days > 1 {
		age = fmt.Sprintf("%d days old", days)
	}
	return fmt.Sprintf("%s (%s; %s)", dir, strings.Join(parts, ", "), age)
}

// detectionPlan describes how plugins or themes will be found.
func detectionPlan(o *cli.ScanOptions, mode cli.DetectionMode, list cli.ItemSet, named []string, what string, plan *scan.Plan) string {
	count := plan.PluginsBruteForce
	if what == "themes" {
		count = plan.ThemesBruteForce
	}
	code := what[:1] // -e p, -e t
	if list == cli.ItemsAll {
		code = "a" + code
	}
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
	case mode.BruteForce() && list == cli.ItemsVulnerable && !hasVulnData(plan.Data):
		parts = append(parts, fmt.Sprintf("brute force of popular %s (%d slugs; the vulnerable list needs \"cmsrecon update\")", what, count))
	case mode.BruteForce() && list != cli.ItemsNone:
		parts = append(parts, fmt.Sprintf("brute force of %s %s (%d slugs)", list, what, count))
	case mode.BruteForce():
		parts = append(parts, "nothing to brute-force (-e has no "+what+" list)")
	case list == cli.ItemsPopular || list == cli.ItemsAll:
		parts = append(parts, fmt.Sprintf("no brute force: -e %s only chooses the list to brute-force, which --%s-detection %s does not do (use mixed)", code, what, mode))
	}
	return strings.Join(parts, ", then ")
}

func hasVulnData(d *scan.DataInfo) bool {
	for _, src := range d.Sources {
		if src.Name == "wordfence" || src.Name == "cve" {
			return true
		}
	}
	return false
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// plural says "1 request" or "12 requests".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
