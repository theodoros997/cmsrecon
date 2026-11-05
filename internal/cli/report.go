package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// ReportOptions are the options of "cmsrecon report", which renders a
// saved JSON report again in another format.
type ReportOptions struct {
	Input   string // the JSON report
	Format  Format
	Output  string
	NoColor bool
	Verbose bool
}

// ParseReport parses the arguments of the report command.
func ParseReport(args []string, out io.Writer) (*ReportOptions, error) {
	o := &ReportOptions{}
	var format string
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&format, "f", "", "")
	fs.StringVar(&format, "format", "", "")
	fs.StringVar(&o.Output, "o", "", "")
	fs.StringVar(&o.Output, "output", "", "")
	fs.BoolVar(&o.NoColor, "no-color", false, "")
	fs.BoolVar(&o.Verbose, "v", false, "")
	fs.BoolVar(&o.Verbose, "verbose", false, "")

	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(out, ReportUsage)
			}
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	switch len(positional) {
	case 0:
		return nil, errors.New("give the JSON report to render: cmsrecon report scan.json -f html -o scan.html")
	case 1:
		o.Input = positional[0]
	default:
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(positional[1:], " "))
	}
	if format == "" {
		format = formatFor(o.Output)
	}
	var err error
	if o.Format, err = parseFormat(format); err != nil {
		return nil, err
	}
	if o.Output != "" && o.Output == o.Input {
		return nil, errors.New("-o names the input report: choose another file")
	}
	return o, nil
}

// ReportUsage is the help text of the report command.
const ReportUsage = `Usage:
  cmsrecon report [options] REPORT.json

Renders a JSON report saved by "cmsrecon scan -f json" (or -o scan.json) in
another format, without scanning again.

Options:
  -f, --format FORMAT   cli, json, html or md (default: from the -o file's extension,
                        else cli)
  -o, --output FILE     Write the report to FILE instead of stdout
      --no-color        Disable colored output
  -v, --verbose         Show how each finding was detected (cli format)

Example:
  cmsrecon scan example.com -o scan.json
  cmsrecon report scan.json -o scan.html
`
