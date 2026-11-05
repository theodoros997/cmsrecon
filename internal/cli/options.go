// Package cli parses and validates cmsrecon's command-line options.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	FormatCLI      Format = "cli"
	FormatJSON     Format = "json"
	FormatHTML     Format = "html"
	FormatMarkdown Format = "md"
)

// Credentials is a login:password pair.
type Credentials struct {
	Username string
	Password string
}

// ScanOptions is a validated scan configuration.
type ScanOptions struct {
	Target        *url.URL
	Enumerate     Enumeration
	DetectionMode DetectionMode
	// PluginsDetection and ThemesDetection work as WPScan's
	// --plugins-detection: passive (the default) finds what the site
	// uses without guessing, mixed adds brute force of the -e list, and
	// aggressive only brute-forces.
	PluginsDetection DetectionMode
	ThemesDetection  DetectionMode
	CrawlPages       int      // extra pages read to discover plugins and themes
	PluginsList      []string // --plugins-list: exactly these plugins are checked
	ThemesList       []string // --themes-list
	ContentDir       string   // --wp-content-dir, when detection gets it wrong
	PluginsDir       string   // --wp-plugins-dir
	LoginURI         string   // --login-uri: the login page, when a plugin moved it
	EnumerateSpec    string   // -e as given, for the report
	Force            bool
	FollowRedirect   bool
	Scope            []string
	WPAuth           *Credentials // WordPress Application Password for the REST inventory

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
	MaxScanDuration time.Duration     // stop the scan after this long; 0 for no limit
	Resolve         map[string]string // host -> address to connect to (--resolve, --vhost)
	LogRequests     string            // --log-requests: a file that logs every request

	Format       Format
	Output       string
	NoColor      bool
	NoProgress   bool // no live progress on stderr
	Verbose      bool
	ShowPossible bool // list the possible vulnerabilities instead of counting them
	DryRun       bool
	Update       bool // run "cmsrecon update" before the scan

	DataDir    string
	ConfigFile string // the config file whose defaults were applied; empty when none
}

// ParseScan parses the arguments of the scan command. Flags and the target URL
// may appear in any order. On -h/--help it writes the usage to out and returns
// flag.ErrHelp.
func ParseScan(args []string, out io.Writer) (*ScanOptions, error) {
	o := &ScanOptions{}
	var target, enumerate, mode, pluginsMode, themesMode, format, scope, proxy, httpAuth, wpAuth string
	var pluginsList, themesList, maxDuration, resolve, vhost, apiToken string
	var stealthy, noBanner bool
	headers := headerFlag{}
	timeout := durationFlag{d: 60 * time.Second, bare: time.Second}
	throttle := durationFlag{bare: time.Millisecond} // WPScan's --throttle is in milliseconds

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
	fs.StringVar(&pluginsMode, "plugins-detection", string(ModePassive), "")
	fs.StringVar(&themesMode, "themes-detection", string(ModePassive), "")
	fs.IntVar(&o.CrawlPages, "crawl", DefaultCrawlPages, "")
	fs.StringVar(&pluginsList, "plugins-list", "", "")
	fs.StringVar(&themesList, "themes-list", "", "")
	fs.StringVar(&o.ContentDir, "wp-content-dir", "", "")
	fs.StringVar(&o.PluginsDir, "wp-plugins-dir", "", "")
	fs.StringVar(&o.LoginURI, "login-uri", "", "")
	fs.BoolVar(&stealthy, "stealthy", false, "")

	fs.StringVar(&o.UserAgent, "user-agent", "", "")
	fs.BoolVar(&o.RandomUserAgent, "random-user-agent", false, "")
	fs.Var(headers, "H", "")
	fs.Var(headers, "header", "")
	fs.Var(wpscanHeaders{headers}, "headers", "") // WPScan: "A: 1; B: 2"
	fs.StringVar(&o.Cookie, "cookie", "", "")
	fs.StringVar(&o.Cookie, "cookie-string", "", "") // WPScan's name
	fs.StringVar(&httpAuth, "http-auth", "", "")
	fs.StringVar(&proxy, "proxy", "", "")
	fs.IntVar(&o.Threads, "t", 5, "")
	fs.IntVar(&o.Threads, "threads", 5, "")
	fs.IntVar(&o.Threads, "max-threads", 5, "") // WPScan's name
	fs.Var(&throttle, "throttle", "")
	fs.Var(&timeout, "timeout", "")
	fs.Var(&timeout, "request-timeout", "") // WPScan's name
	fs.BoolVar(&o.Insecure, "insecure", false, "")
	fs.BoolVar(&o.Insecure, "disable-tls-checks", false, "") // WPScan's name
	fs.BoolVar(&o.RandomUserAgent, "rua", false, "")         // WPScan's name
	fs.StringVar(&maxDuration, "max-scan-duration", "", "")
	fs.StringVar(&resolve, "resolve", "", "")
	fs.StringVar(&vhost, "vhost", "", "")
	fs.StringVar(&o.LogRequests, "log-requests", "", "")
	fs.StringVar(&apiToken, "api-token", "", "")
	fs.BoolVar(&noBanner, "no-banner", false, "")
	fs.BoolVar(&o.Update, "update", false, "")
	fs.StringVar(&o.ConfigFile, "config", "", "")

	fs.StringVar(&format, "f", "", "")
	fs.StringVar(&format, "format", "", "")
	fs.StringVar(&o.Output, "o", "", "")
	fs.StringVar(&o.Output, "output", "", "")
	fs.BoolVar(&o.NoColor, "no-color", false, "")
	fs.BoolVar(&o.NoProgress, "no-progress", false, "")
	fs.BoolVar(&o.Verbose, "v", false, "")
	fs.BoolVar(&o.Verbose, "verbose", false, "")
	fs.BoolVar(&o.ShowPossible, "possible", false, "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")

	fs.StringVar(&o.DataDir, "data-dir", "", "")

	// Defaults from the config file come first, so the command line wins.
	cfgArgs, cfgFile, err := configArgs(args, fs)
	if err != nil {
		return nil, err
	}
	args = append(cfgArgs, args...)

	// The flag package stops at the first non-flag argument, so keep parsing
	// after each positional one to allow "scan example.com -e vp".
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(out, ScanUsage)
			}
			return nil, flagHint(err)
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
	o.ConfigFile = cfgFile
	if apiToken != "" {
		return nil, errors.New("--api-token: cmsrecon needs no API token; its vulnerability data comes from \"cmsrecon update\" (set WORDFENCE_API_KEY for the best data)")
	}
	if strings.HasPrefix(strings.TrimSpace(target), "-") {
		return nil, fmt.Errorf("the target %q looks like an option: give the site's URL after -u", target)
	}

	if o.Target, err = normalizeTarget(target); err != nil {
		return nil, err
	}
	if o.Resolve, err = parseResolve(resolve, vhost, o.Target); err != nil {
		return nil, err
	}
	if len(o.Resolve) > 0 && proxy != "" {
		return nil, errors.New("--resolve and --vhost choose the address to connect to, which a --proxy decides instead: use one or the other")
	}
	o.EnumerateSpec = enumerate
	if o.Enumerate, err = ParseEnumeration(enumerate); err != nil {
		return nil, err
	}
	if o.DetectionMode, err = parseMode("detection-mode", mode); err != nil {
		return nil, err
	}
	if o.PluginsDetection, err = parseMode("plugins-detection", pluginsMode); err != nil {
		return nil, err
	}
	if o.ThemesDetection, err = parseMode("themes-detection", themesMode); err != nil {
		return nil, err
	}
	if o.CrawlPages < 0 || o.CrawlPages > MaxCrawlPages {
		return nil, fmt.Errorf("--crawl must be between 0 and %d", MaxCrawlPages)
	}
	if o.MaxScanDuration, err = parseMaxDuration(maxDuration); err != nil {
		return nil, err
	}
	if o.PluginsList, err = parseSlugList("plugins-list", pluginsList); err != nil {
		return nil, err
	}
	if o.ThemesList, err = parseSlugList("themes-list", themesList); err != nil {
		return nil, err
	}
	// --stealthy, as in WPScan: a browser User-Agent and only the pages a
	// visitor's browser would load.
	if stealthy {
		o.RandomUserAgent = true
		o.DetectionMode = ModePassive
	}
	if format == "" {
		format = formatFor(o.Output)
	}
	if f := strings.ToLower(format); f == "cli-no-color" || f == "cli-no-colour" { // WPScan's names
		format, o.NoColor = string(FormatCLI), true
	}
	if o.Format, err = parseFormat(format); err != nil {
		return nil, err
	}
	o.Timeout, o.Throttle = timeout.d, throttle.d
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

var slugListRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// parseSlugList reads --plugins-list or --themes-list: slugs separated by
// commas, or the name of a file with one slug per line ("#" starts a
// comment).
func parseSlugList(flagName, v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	items := strings.Split(v, ",")
	if data, err := os.ReadFile(v); err == nil {
		items = strings.Split(string(data), "\n")
	} else if ext := strings.ToLower(filepath.Ext(v)); !strings.Contains(v, ",") && (strings.ContainsAny(v, `/\`) || ext == ".txt" || ext == ".lst" || ext == ".list" || ext == ".csv") {
		// "plugins.txt" or "lists/x": a file that is not there, not a slug.
		return nil, fmt.Errorf("--%s: %w", flagName, err)
	}
	var out []string
	seen := map[string]bool{}
	for _, it := range items {
		it, _, _ = strings.Cut(it, "#")
		it = strings.TrimSpace(it)
		if it == "" || seen[strings.ToLower(it)] {
			continue
		}
		if !slugListRe.MatchString(it) {
			return nil, fmt.Errorf("--%s: %q is not a plugin or theme slug", flagName, it)
		}
		seen[strings.ToLower(it)] = true
		out = append(out, it)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--%s is empty", flagName)
	}
	return out, nil
}

// parseMaxDuration reads --max-scan-duration: a duration such as 10m or
// 1h30m, or a number of seconds as in WPScan.
func parseMaxDuration(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		n, nerr := strconv.Atoi(v)
		if nerr != nil {
			return 0, fmt.Errorf("invalid --max-scan-duration %q (use e.g. 600, 10m or 1h30m)", v)
		}
		d = time.Duration(n) * time.Second
	}
	if d <= 0 {
		return 0, fmt.Errorf("--max-scan-duration must be positive")
	}
	return d, nil
}

// Crawl limits: how many extra pages discovery reads by default, at most.
const (
	DefaultCrawlPages = 10
	MaxCrawlPages     = 100
)

func parseMode(flagName, s string) (DetectionMode, error) {
	switch m := DetectionMode(strings.ToLower(s)); m {
	case ModePassive, ModeMixed, ModeAggressive:
		return m, nil
	}
	return "", fmt.Errorf("invalid --%s %q (use passive, mixed or aggressive)", flagName, s)
}

// BruteForce reports whether a --plugins-detection or --themes-detection
// mode brute-forces the -e list.
func (m DetectionMode) BruteForce() bool { return m == ModeMixed || m == ModeAggressive }

// Discover reports whether a --plugins-detection or --themes-detection
// mode finds plugins and themes from what the site shows. The zero value
// counts as passive.
func (m DetectionMode) Discover() bool { return m != ModeAggressive }

func parseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case FormatCLI, FormatJSON, FormatHTML, FormatMarkdown:
		return f, nil
	case "markdown":
		return FormatMarkdown, nil
	case "htm":
		return FormatHTML, nil
	}
	return "", fmt.Errorf("invalid --format %q (use cli, json, html or md)", s)
}

// formatFor is the format a report file's extension asks for: -o
// report.json writes JSON without -f json.
func formatFor(output string) string {
	switch strings.ToLower(filepath.Ext(output)) {
	case ".json":
		return string(FormatJSON)
	case ".html", ".htm":
		return string(FormatHTML)
	case ".md", ".markdown":
		return string(FormatMarkdown)
	}
	return string(FormatCLI)
}

// durationFlag is a duration that also takes a bare number, in the unit
// WPScan uses for the same option: seconds for --timeout, milliseconds
// for --throttle.
type durationFlag struct {
	d    time.Duration
	bare time.Duration
}

func (f *durationFlag) String() string { return f.d.String() }

func (f *durationFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		f.d = time.Duration(n * float64(f.bare))
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("%q is not a duration (e.g. 30s, 500ms, or a number of %s)", v, map[time.Duration]string{time.Second: "seconds", time.Millisecond: "milliseconds"}[f.bare])
	}
	f.d = d
	return nil
}

// wpscanHeaders reads WPScan's --headers "A: 1; B: 2".
type wpscanHeaders struct{ h headerFlag }

func (w wpscanHeaders) String() string { return "" }

func (w wpscanHeaders) Set(v string) error {
	for _, part := range strings.Split(v, ";") {
		if part = strings.TrimSpace(part); part != "" {
			if err := w.h.Set(part); err != nil {
				return err
			}
		}
	}
	return nil
}

// wpscanOnly maps WPScan options cmsrecon does not have to what to use.
var wpscanOnly = map[string]string{
	"enterprise-db-token":   "cmsrecon needs no token: \"cmsrecon update\" downloads its vulnerability data",
	"passwords":             "cmsrecon never guesses passwords",
	"usernames":             "cmsrecon never guesses passwords",
	"password-attack":       "cmsrecon never guesses passwords",
	"cache-dir":             "use --data-dir",
	"clear-cache":           "cmsrecon keeps no response cache",
	"cookie-jar":            "cookies the site sets are kept for the scan; use --cookie to send your own",
	"wp-version-all":        "the version checks always run; -v shows every signal",
	"plugins-threshold":     "brute force is off by default; choose its list with -e",
	"themes-threshold":      "brute force is off by default; choose its list with -e",
	"exclude-content-based": "soft-404 pages are recognized automatically",
}

// flagHint rewords the flag package's errors for options WPScan users
// try.
func flagHint(err error) error {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		name = strings.TrimLeft(name, "-")
		if hint, ok := wpscanOnly[name]; ok {
			return fmt.Errorf("unknown option --%s: %s", name, hint)
		}
		return fmt.Errorf("unknown option --%s (run \"cmsrecon scan -h\" for the options)", name)
	}
	return err
}

// parseResolve reads --resolve and --vhost into the addresses to connect
// to. --resolve takes "ADDRESS" (for the target's host), "HOST=ADDRESS" or
// curl's "HOST:PORT:ADDRESS", comma separated. --vhost NAME with -u
// https://ADDRESS/ scans NAME while connecting to ADDRESS, as WPScan's
// --vhost does: the target becomes NAME, so Host, TLS SNI and the scope
// are NAME's.
func parseResolve(resolve, vhost string, target *url.URL) (map[string]string, error) {
	out := map[string]string{}
	if vhost = strings.ToLower(strings.TrimSpace(vhost)); vhost != "" {
		if strings.ContainsAny(vhost, "/:@ ") {
			return nil, fmt.Errorf("--vhost %q must be a host name, such as www.example.com", vhost)
		}
		out[vhost] = target.Hostname()
		port := target.Port()
		target.Host = vhost
		if port != "" {
			target.Host = net.JoinHostPort(vhost, port)
		}
	}
	for _, entry := range strings.Split(resolve, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, addr := strings.ToLower(target.Hostname()), entry
		switch {
		case net.ParseIP(strings.Trim(entry, "[]")) != nil:
			// A bare address, IPv6 ones included: for the target's host.
		case strings.Contains(entry, "="):
			host, addr, _ = strings.Cut(entry, "=")
		case strings.Count(entry, ":") == 2:
			parts := strings.SplitN(entry, ":", 3)
			host, addr = parts[0], parts[2]
		}
		host, addr = strings.ToLower(strings.TrimSpace(host)), strings.Trim(strings.TrimSpace(addr), "[]")
		if net.ParseIP(addr) == nil {
			return nil, fmt.Errorf("--resolve %q: %q is not an IP address", entry, addr)
		}
		out[host] = addr
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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
  -e, --enumerate LIST        What to enumerate (default "vp,vt,cb,dbe,bf,u"; "none" for nothing).
                              Items starting with + add to the default list instead of
                              replacing it: -e +tt,+m adds TimThumbs and media
                                vp | p | ap   vulnerable | popular | all plugins
                                vt | t | at   vulnerable | popular | all themes
                                cb            wp-config.php backups
                                dbe           database exports
                                bf            backup folders with directory listing
                                tt            TimThumb scripts in the themes' and plugins' folders
                                u[RANGE]      users, checking author IDs RANGE (default u1-10)
                                m[RANGE]      media files: the REST API, or attachment IDs RANGE
                                              when it is closed (default m1-100)
      --detection-mode MODE   passive, mixed or aggressive (default mixed)
      --plugins-detection MODE
                              passive (default): find the plugins the site uses from its
                              pages, sitemaps, REST API and directory listings, without
                              guessing; mixed: also brute-force every plugin of the -e
                              list (vp, p or ap: thousands of requests); aggressive:
                              brute force only. Vulnerabilities are matched either way
      --themes-detection MODE Same for themes (default passive)
      --crawl N               Extra pages read to find plugins and themes: one per kind
                              of page from the sitemaps and the homepage's links, plus
                              the login page (default 10; 0 to read only the homepage)
      --plugins-list LIST     Check these plugins, one request each, instead of an -e list: slugs
                              separated by commas, or a file with one slug per line
      --themes-list LIST      Same for themes
      --wp-content-dir DIR    The content directory, when detection gets it wrong
                              (e.g. app/ or https://cdn.example.com/content/)
      --wp-plugins-dir DIR    The plugins directory (default: <content dir>/plugins/)
      --login-uri PATH        The login page, when a plugin moved it (e.g. /my-login/)
      --stealthy              A browser User-Agent and passive detection: only the pages a
                              visitor's browser would load (as WPScan's --stealthy)

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
      --resolve ADDRESS       Connect to ADDRESS instead of the address DNS gives, e.g. a
                              server behind a CDN or not yet in DNS; also HOST=ADDRESS
                              or curl's HOST:PORT:ADDRESS, comma separated
      --vhost NAME            Scan the site NAME at the -u address: -u https://10.0.0.5/
                              --vhost www.example.com (Host, TLS name and scope are NAME's)
      --max-scan-duration D   Stop the scan after D (e.g. 10m, or 600 seconds) and report
                              what was found so far

Output:
  -f, --format FORMAT         cli, json, html or md (default: from the -o file's extension,
                              else cli)
  -o, --output FILE           Write the report to FILE instead of stdout; a short summary
                              is printed on stderr
      --no-color              Disable colored output
      --no-progress           Do not show what the scan is doing while it runs (shown on
                              stderr when it is a terminal)
  -v, --verbose               Show how each finding was detected
      --possible              List the possible vulnerabilities (those of components whose
                              version is unknown) instead of only counting them
      --dry-run               Print the scan plan and exit without sending any request
      --log-requests FILE     Log every request (time, method, URL, status, size, duration)
                              to FILE, tab separated

Data:
      --data-dir DIR          Where "cmsrecon update" stored the vulnerability data
                              (default: <user cache dir>/cmsrecon)
      --update                Run "cmsrecon update" before the scan

Config file:
      --config FILE           Defaults for any option, one "option = value" per line
                              (default: $CMSRECON_CONFIG, else <user config dir>/cmsrecon/config;
                              "none" for no file). The command line overrides it

WPScan names work too: --url, --max-threads, --request-timeout, --disable-tls-checks,
--rua, --cookie-string, --headers and --no-banner. --api-token is not needed:
"cmsrecon update" downloads the vulnerability data.

Exit codes:
  0    The scan completed
  1    cmsrecon failed, e.g. the report file could not be written
  2    Invalid command line
  3    A pre-flight check stopped the scan (unreachable, authentication required,
       403, out-of-scope redirect, not WordPress, WordPress.com, unfinished
       install); the report says why
  4    The scan reached --max-scan-duration; the partial report is still written
  5    The scan completed and found confirmed or likely vulnerabilities
  6    The target kept failing or refusing requests (rate limit, firewall,
       outage), so the scan stopped; the partial report is still written
  130  Interrupted with Ctrl-C; the partial report is still written
`
