package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// UpdateSources are the data sources "cmsrecon update" knows, in the order
// they run.
var UpdateSources = []string{"wordfence", "cve", "wporg", "retirejs"}

// UpdateOptions is a validated update configuration.
type UpdateOptions struct {
	DataDir      string
	Sources      []string
	WordfenceKey string
	Proxy        *url.URL
	Timeout      time.Duration
}

// ParseUpdate parses the arguments of the update command. The Wordfence
// key defaults to the WORDFENCE_API_KEY environment variable.
func ParseUpdate(args []string, out io.Writer) (*UpdateOptions, error) {
	o := &UpdateOptions{}
	var sources, proxy string
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&o.DataDir, "data-dir", "", "")
	fs.StringVar(&sources, "sources", strings.Join(UpdateSources, ","), "")
	fs.StringVar(&o.WordfenceKey, "wordfence-key", os.Getenv("WORDFENCE_API_KEY"), "")
	fs.StringVar(&proxy, "proxy", "", "")
	fs.DurationVar(&o.Timeout, "timeout", 60*time.Second, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, UpdateUsage)
		}
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	for _, s := range strings.Split(sources, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !slices.Contains(UpdateSources, s) {
			return nil, fmt.Errorf("unknown source %q in --sources (use %s)", s, strings.Join(UpdateSources, ", "))
		}
		if !slices.Contains(o.Sources, s) {
			o.Sources = append(o.Sources, s)
		}
	}
	if len(o.Sources) == 0 {
		return nil, errors.New("--sources is empty")
	}
	if proxy != "" {
		var err error
		if o.Proxy, err = parseProxy(proxy); err != nil {
			return nil, err
		}
	}
	if o.Timeout <= 0 {
		return nil, errors.New("--timeout must be positive")
	}
	o.WordfenceKey = strings.TrimSpace(o.WordfenceKey)
	if o.DataDir == "" {
		o.DataDir = defaultDataDir()
	}
	if o.DataDir == "" {
		return nil, errors.New("no cache directory found: use --data-dir")
	}
	return o, nil
}

// UpdateUsage is the help text of the update command.
const UpdateUsage = `Usage:
  cmsrecon update [options]

Downloads the vulnerability data and plugin lists that scans use. A scan
never contacts these sources; run update again to refresh them.

Sources (all by default):
  wordfence   Wordfence Intelligence feed: WordPress core, plugin and theme
              vulnerabilities. Needs a free API key from a Wordfence account
  cve         CVE List: a cross-check of the version ranges, and the only
              vulnerability source without a Wordfence key. Downloads the
              daily release (about 500 MB), skipped when it has not changed
  wporg       WordPress.org: popular plugins and themes with their latest
              versions, and every plugin and theme slug (for -e ap, at)
  retirejs    retire.js: vulnerable JavaScript libraries

Options:
      --data-dir DIR          Where to store the data (default: <user cache dir>/cmsrecon)
      --sources LIST          Comma-separated sources to update (default "wordfence,cve,wporg,retirejs")
      --wordfence-key KEY     Wordfence Intelligence API key (default: $WORDFENCE_API_KEY)
      --proxy URL             Proxy for the downloads (default: the HTTPS_PROXY environment variable)
      --timeout DURATION      How long to wait for a server to answer (default 60s)

Set GITHUB_TOKEN to raise GitHub's API rate limit for the CVE List.

Exit codes:
  0    Every requested source was updated or skipped
  1    A source failed; the others were still updated
  2    Invalid command line
  130  Interrupted with Ctrl-C
`
