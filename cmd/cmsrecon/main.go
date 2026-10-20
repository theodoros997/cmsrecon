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
	"text/tabwriter"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/report"
	"github.com/theodoros997/cmsrecon/internal/scan"
)

// Exit codes, documented in the scan usage and the README.
const (
	exitOK          = 0   // the scan completed
	exitError       = 1   // cmsrecon itself failed, e.g. the report could not be written
	exitUsage       = 2   // invalid command line
	exitStopped     = 3   // a pre-flight check stopped the scan; the report says why
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
		fmt.Fprintln(stderr, "update: the vulnerability database is not implemented yet")
		return exitError
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
	notices := notImplemented(opts)
	if opts.DryRun {
		printPlan(stdout, opts, notices)
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

	// The CLI report on stdout carries the notices; anywhere else the user
	// would not see them, so print them now.
	toTerminal := opts.Format == cli.FormatCLI && opts.Output == ""
	if !toTerminal {
		for _, n := range notices {
			fmt.Fprintln(stderr, "notice:", n)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res := scan.New(opts, client).Run(ctx, notices)

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

	switch res.Status {
	case scan.StatusStopped:
		return exitStopped
	case scan.StatusInterrupted:
		return exitInterrupted
	}
	return exitOK
}

// notImplemented returns one notice listing the requested enumerations that
// this version cannot run yet, or nothing.
func notImplemented(o *cli.ScanOptions) []string {
	var skipped []string
	e := o.Enumerate
	if o.WPAuth != nil {
		skipped = append(skipped, "REST API inventory (--wp-auth)")
	} else {
		if e.Plugins != cli.ItemsNone {
			skipped = append(skipped, fmt.Sprintf("%s plugins (%sp)", e.Plugins, itemCode(e.Plugins)))
		}
		if e.Themes != cli.ItemsNone {
			skipped = append(skipped, fmt.Sprintf("%s themes (%st)", e.Themes, itemCode(e.Themes)))
		}
	}
	if e.ConfigBackups {
		skipped = append(skipped, "config backups (cb)")
	}
	if e.DBExports {
		skipped = append(skipped, "database exports (dbe)")
	}
	if e.BackupFolders {
		skipped = append(skipped, "backup folders (bf)")
	}
	if e.Users != nil {
		skipped = append(skipped, fmt.Sprintf("users (u%s)", e.Users))
	}
	if len(skipped) == 0 {
		return nil
	}
	return []string{"Not implemented yet, skipped: " + strings.Join(skipped, ", ") + "."}
}

func itemCode(s cli.ItemSet) string {
	switch s {
	case cli.ItemsVulnerable:
		return "v"
	case cli.ItemsAll:
		return "a"
	}
	return ""
}

// printPlan describes what a scan with these options would do.
func printPlan(w io.Writer, o *cli.ScanOptions, notices []string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s:\t%s\n", k, v) }

	row("Target", o.Target.String())
	row("Detection mode", string(o.DetectionMode))
	e := o.Enumerate
	if o.WPAuth != nil {
		row("Plugins and themes", "REST API inventory as "+o.WPAuth.Username)
	} else {
		row("Plugins", e.Plugins.String())
		row("Themes", e.Themes.String())
	}
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
	tw.Flush()
	for _, n := range notices {
		fmt.Fprintln(w, "\nNote:", n)
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
