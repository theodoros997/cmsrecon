// Command cmsrecon is a WordPress reconnaissance scanner for authorized
// security assessments.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/cli"
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
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "update":
		fmt.Fprintln(stderr, "update: the vulnerability database is not implemented yet")
		return 1
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, buildinfo.String())
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	if strings.HasPrefix(args[0], "-") {
		return runScan(args, stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := cli.ParseScan(args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\nRun \"cmsrecon scan -h\" for usage.\n", err)
		return 2
	}
	if !opts.DryRun {
		fmt.Fprintln(stderr, "error: scanning is not implemented yet (use --dry-run to see the scan plan)")
		return 1
	}
	printPlan(stdout, opts)
	return 0
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
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
