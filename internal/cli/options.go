// Package cli parses and validates cmsrecon's command-line options.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DetectionMode controls which finders run.
type DetectionMode string

const (
	ModePassive    DetectionMode = "passive"    // only parse pages the scan fetches anyway
	ModeMixed      DetectionMode = "mixed"      // passive and aggressive finders
	ModeAggressive DetectionMode = "aggressive" // only finders that request specific paths
)

// Format is the report format.
type Format string

const (
	FormatCLI  Format = "cli"
	FormatJSON Format = "json"
)

// Credentials is a login:password pair.
type Credentials struct {
	Username string
	Password string
}

// ScanOptions is a validated scan configuration.
type ScanOptions struct {
	Target         *url.URL
	Enumerate      Enumeration
	DetectionMode  DetectionMode
	Force          bool
	FollowRedirect bool
	Scope          []string
	WPAuth         *Credentials // WordPress Application Password for the REST inventory

	UserAgent       string
	RandomUserAgent bool
	Headers         http.Header
	Cookie          string
	HTTPAuth        *Credentials
	Proxy           *url.URL
	Threads         int
	Throttle        time.Duration
	Timeout         time.Duration
	Insecure        bool

	Format  Format
	Output  string
	NoColor bool
	Verbose bool
	DryRun  bool

	DataDir string
}

// ParseScan parses the arguments of the scan command. Flags and the target URL
// may appear in any order. On -h/--help it writes the usage to out and returns
// flag.ErrHelp.
func ParseScan(args []string, out io.Writer) (*ScanOptions, error) {
	o := &ScanOptions{}
	var target, enumerate, mode, format, scope, proxy, httpAuth, wpAuth string
	headers := headerFlag{}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	fs.StringVar(&target, "u", "", "")
	fs.StringVar(&target, "url", "", "")
	fs.BoolVar(&o.Force, "force", false, "")
	fs.BoolVar(&o.FollowRedirect, "follow-redirect", false, "")
	fs.StringVar(&scope, "scope", "", "")
	fs.StringVar(&wpAuth, "wp-auth", "", "")

	fs.StringVar(&enumerate, "e", DefaultEnumeration, "")
	fs.StringVar(&enumerate, "enumerate", DefaultEnumeration, "")
	fs.StringVar(&mode, "detection-mode", string(ModeMixed), "")

	fs.StringVar(&o.UserAgent, "user-agent", "", "")
	fs.BoolVar(&o.RandomUserAgent, "random-user-agent", false, "")
	fs.Var(headers, "H", "")
	fs.Var(headers, "header", "")
	fs.StringVar(&o.Cookie, "cookie", "", "")
	fs.StringVar(&httpAuth, "http-auth", "", "")
	fs.StringVar(&proxy, "proxy", "", "")
	fs.IntVar(&o.Threads, "t", 5, "")
	fs.IntVar(&o.Threads, "threads", 5, "")
	fs.DurationVar(&o.Throttle, "throttle", 0, "")
	fs.DurationVar(&o.Timeout, "timeout", 60*time.Second, "")
	fs.BoolVar(&o.Insecure, "insecure", false, "")

	fs.StringVar(&format, "f", string(FormatCLI), "")
	fs.StringVar(&format, "format", string(FormatCLI), "")
	fs.StringVar(&o.Output, "o", "", "")
	fs.StringVar(&o.Output, "output", "", "")
	fs.BoolVar(&o.NoColor, "no-color", false, "")
	fs.BoolVar(&o.Verbose, "v", false, "")
	fs.BoolVar(&o.Verbose, "verbose", false, "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")

	fs.StringVar(&o.DataDir, "data-dir", "", "")

	// The flag package stops at the first non-flag argument, so keep parsing
	// after each positional one to allow "scan example.com -e vp".
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(out, ScanUsage)
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
	if target == "" && len(positional) == 1 {
		target, positional = positional[0], nil
	}
	if len(positional) > 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(positional, " "))
	}

	var err error
	if o.Target, err = normalizeTarget(target); err != nil {
		return nil, err
	}
	if o.Enumerate, err = ParseEnumeration(enumerate); err != nil {
		return nil, err
	}
	if o.DetectionMode, err = parseMode(mode); err != nil {
		return nil, err
	}
	if o.Format, err = parseFormat(format); err != nil {
		return nil, err
	}
	for _, d := range strings.Split(scope, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			o.Scope = append(o.Scope, d)
		}
	}
	if httpAuth != "" {
		if o.HTTPAuth, err = parseCredentials("http-auth", httpAuth); err != nil {
			return nil, err
		}
	}
	if wpAuth != "" {
		if o.WPAuth, err = parseCredentials("wp-auth", wpAuth); err != nil {
			return nil, err
		}
	}
	if proxy != "" {
		if o.Proxy, err = parseProxy(proxy); err != nil {
			return nil, err
		}
	}
	if o.Threads < 1 {
		return nil, errors.New("--threads must be at least 1")
	}
	if o.Throttle < 0 {
		return nil, errors.New("--throttle must not be negative")
	}
	if o.Throttle > 0 {
		o.Threads = 1
	}
	if o.Timeout <= 0 {
		return nil, errors.New("--timeout must be positive")
	}
	o.Headers = http.Header(headers)
	if o.DataDir == "" {
		o.DataDir = defaultDataDir()
	}
	return o, nil
}

// normalizeTarget turns user input into a base URL ending in "/".
// Like WPScan, it assumes http:// when no scheme is given; the scan follows
// an http -> https redirect on the same host.
func normalizeTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("a target URL is required (-u/--url)")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q (use http or https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid target URL %q: missing host", raw)
	}
	u.RawQuery, u.Fragment = "", ""
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
		if u.RawPath != "" {
			u.RawPath += "/"
		}
	}
	return u, nil
}

func parseMode(s string) (DetectionMode, error) {
	switch m := DetectionMode(strings.ToLower(s)); m {
	case ModePassive, ModeMixed, ModeAggressive:
		return m, nil
	}
	return "", fmt.Errorf("invalid --detection-mode %q (use passive, mixed or aggressive)", s)
}

func parseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case FormatCLI, FormatJSON:
		return f, nil
	}
	return "", fmt.Errorf("invalid --format %q (use cli or json)", s)
}

func parseCredentials(flagName, s string) (*Credentials, error) {
	user, pass, ok := strings.Cut(s, ":")
	if !ok || user == "" {
		return nil, fmt.Errorf("--%s must look like login:password", flagName)
	}
	return &Credentials{Username: user, Password: pass}, nil
}

func parseProxy(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid --proxy %q (expected scheme://host:port)", s)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
		return u, nil
	}
	return nil, fmt.Errorf("unsupported --proxy scheme %q (use http, https, socks5 or socks5h)", u.Scheme)
}

func defaultDataDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "cmsrecon")
}

// headerFlag collects repeated -H "Name: value" flags.
type headerFlag http.Header

func (h headerFlag) String() string { return "" }

func (h headerFlag) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" || strings.ContainsAny(name, " \t") {
		return fmt.Errorf("header %q must look like \"Name: value\"", v)
	}
	http.Header(h).Add(name, strings.TrimSpace(value))
	return nil
}

// ScanUsage is the help text of the scan command.
const ScanUsage = `Usage:
  cmsrecon scan [options] URL
  cmsrecon -u URL [options]

Target:
  -u, --url URL               Site to scan; http:// is assumed when no scheme is given
      --force                 Scan even if the site does not look like WordPress or returns 403
      --follow-redirect       Also follow a homepage redirect to an out-of-scope host
                              (redirects within the scope are always followed)
      --scope DOMAINS         Extra in-scope domains, comma separated (e.g. cdn.example.com;
                              *.example.com covers every subdomain)
      --wp-auth USER:APP_PW   Admin Application Password: read the exact plugin and theme
                              list from the REST API instead of detecting it

Detection:
  -e, --enumerate LIST        What to enumerate (default "vp,vt,cb,dbe,bf,u"; "none" for nothing)
                                vp | p | ap   vulnerable | popular | all plugins
                                vt | t | at   vulnerable | popular | all themes
                                cb            wp-config.php backups
                                dbe           database exports
                                bf            backup folders with directory listing
                                u[RANGE]      users, checking author IDs RANGE (default u1-10)
                              The vulnerable and all lists need "cmsrecon update"; until
                              then the popular lists are used
      --detection-mode MODE   passive, mixed or aggressive (default mixed)

HTTP:
      --user-agent UA         User-Agent to send
      --random-user-agent     Use a random browser User-Agent for the scan
  -H, --header "NAME: VALUE"  Extra request header (repeatable)
      --cookie COOKIES        Cookie header value, e.g. "a=1; b=2"
      --http-auth USER:PASS   HTTP Basic authentication
      --proxy URL             http, https, socks5 or socks5h proxy, e.g. http://127.0.0.1:8080
  -t, --threads N             Concurrent requests (default 5)
      --throttle DURATION     Wait between requests, e.g. 500ms (forces --threads 1)
      --timeout DURATION      Per-request timeout (default 60s)
      --insecure              Skip TLS certificate verification

Output:
  -f, --format FORMAT         cli or json (default cli)
  -o, --output FILE           Write results to FILE instead of stdout
      --no-color              Disable colored output
  -v, --verbose               Show how each finding was detected
      --dry-run               Print the scan plan and exit without sending any request

Data:
      --data-dir DIR          Where "cmsrecon update" stored the vulnerability data
                              (default: <user cache dir>/cmsrecon)

Exit codes:
  0    The scan completed
  1    cmsrecon failed, e.g. the report file could not be written
  2    Invalid command line
  3    A pre-flight check stopped the scan (unreachable, authentication required,
       403, out-of-scope redirect, not WordPress, WordPress.com, unfinished
       install); the report says why
  130  Interrupted with Ctrl-C; the partial report is still written
`
