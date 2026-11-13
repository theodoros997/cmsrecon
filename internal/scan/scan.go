// Package scan runs the WordPress checks described in docs/checks.md against
// one target and collects the results.
package scan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theodoros997/cmsrecon/internal/buildinfo"
	"github.com/theodoros997/cmsrecon/internal/cli"
	"github.com/theodoros997/cmsrecon/internal/httpclient"
	"github.com/theodoros997/cmsrecon/internal/progress"
	"github.com/theodoros997/cmsrecon/internal/wordlists"
	"github.com/theodoros997/cmsrecon/internal/wporg"
)

// Modes recorded in evidence.
const (
	modePassive    = "passive"
	modeAggressive = "aggressive"
)

// Scanner scans one target. Create it with New and call Run once.
type Scanner struct {
	// Steps, when set, is told what the scan is doing: each step as it
	// starts, what it is busy with, and its result. It is called from
	// several goroutines.
	Steps progress.Reporter
	// Org asks WordPress.org for plugin checksums. A scan makes its own
	// unless one is set, which tests do.
	Org *wporg.Client

	orgOnce sync.Once
	orgDown atomic.Bool // WordPress.org failed once: it is not asked again

	opts   *cli.ScanOptions
	client *httpclient.Client
	base   *url.URL // the scanned URL, updated by followed redirects
	data   *scanData

	home     *page
	notFound *page    // the answer to a random path: the site's 404 page
	content  *url.URL // the wp-content directory on the target host
	core     *url.URL // where WordPress's own files are: the site root, or /wp/ for Bedrock
	plugins  *url.URL // the plugins directory: <content>/plugins/ or --wp-plugins-dir
	themes   *url.URL // the themes directory: <content>/themes/
	server   string   // web server family

	cacheMu sync.Mutex
	cache   map[string]*fetch

	baseMu    sync.Mutex
	baselines map[string]*baseline

	headRefused  atomic.Bool  // the server answers HEAD with 405 or 501
	probeBlocked atomic.Int64 // brute-force answers that were a rate limit or a block page

	restOnce     sync.Once
	restAPI      *restAPI
	crawlOnce    sync.Once
	crawled      *crawlResult
	combinedOnce sync.Once
	combined     []combinedFile
	invOnce      sync.Once
	inv          *inventory

	mu  sync.Mutex // guards res
	res *Result
}

// fetch is a cached GET, shared by every check that needs the same URL.
type fetch struct {
	done chan struct{}
	resp *httpclient.Response
	err  error
}

// New returns a scanner for opts.Target that sends its requests through client.
func New(opts *cli.ScanOptions, client *httpclient.Client) *Scanner {
	base := *opts.Target
	return &Scanner{
		opts:      opts,
		client:    client,
		base:      &base,
		cache:     map[string]*fetch{},
		baselines: map[string]*baseline{},
	}
}

// errMaxDuration is the cause of a scan stopped by --max-scan-duration.
var errMaxDuration = errors.New("the scan reached --max-scan-duration")

// errTargetFailing is the cause of a scan stopped by the client's circuit
// breaker: the target kept failing or refusing requests.
var errTargetFailing = errors.New("the target kept failing or refusing requests")

// maxErrors caps how many failed requests the result lists.
const maxErrors = 100

// Run scans the target and always returns a result. Notices are copied into
// the result as they are. When ctx is cancelled, Run returns what it found so
// far with StatusInterrupted, or StatusTimedOut when --max-scan-duration
// ran out.
func (s *Scanner) Run(ctx context.Context, notices []string) *Result {
	start := time.Now()
	if d := s.opts.MaxScanDuration; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, d, errMaxDuration)
		defer cancel()
	}
	// When the target keeps failing or refusing, everything after that
	// point would read "nothing found": stop instead, and say why.
	ctx, stopFailing := context.WithCancelCause(ctx)
	defer stopFailing(nil)
	s.client.OnFailing(func(string) { stopFailing(errTargetFailing) })
	s.res = &Result{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "cmsrecon", Version: buildinfo.Version, UserAgent: s.client.UserAgent()},
		Target:        Target{URL: s.opts.Target.String(), EffectiveURL: s.base.String()},
		DetectionMode: string(s.opts.DetectionMode),
		Options:       optionsOf(s.opts),
		StartedAt:     start.UTC().Truncate(time.Second),
		Notices:       append([]string(nil), notices...),
	}
	switch s.opts.DetectionMode {
	case cli.ModePassive:
		s.res.Notices = append(s.res.Notices, "Passive mode only reads the homepage, the 404 page and the feeds it links to; most interesting findings need mixed or aggressive mode.")
	case cli.ModeAggressive:
		s.res.Notices = append(s.res.Notices, "Aggressive mode skips the passive checks: interesting headers, versions from the homepage and its feeds, and the main theme.")
	}

	st := s.steps()
	st.Start(stepData)
	s.loadData()
	st.Done(stepData, s.dataSummary())
	st.Start(stepPreflight)
	if s.preflight(ctx) {
		st.Done(stepPreflight, s.preflightSummary())
		s.runChecks(ctx)
		s.res.Status = StatusCompleted
	} else if s.res.Stop != nil {
		st.Fail(stepPreflight, s.res.Stop.Message)
	} else {
		st.Fail(stepPreflight, "interrupted")
	}
	if ctx.Err() != nil {
		s.res.Status = StatusInterrupted
		switch cause := context.Cause(ctx); {
		case errors.Is(cause, errMaxDuration):
			s.res.Status = StatusTimedOut
			s.res.Notices = append(s.res.Notices, fmt.Sprintf("The scan stopped after --max-scan-duration %s: the checks still running were cut short, so the results are partial.", s.opts.MaxScanDuration))
		case errors.Is(cause, errTargetFailing):
			s.res.Status = StatusBlocked
			s.res.Notices = append(s.res.Notices, fmt.Sprintf("The scan stopped after %d requests because the target kept failing or refusing them, even after slowing down and pausing (%s). The steps that finished before that are complete; what was not checked by then is missing, not absent. Scan again later, more slowly (--throttle 2s), or from an allowed IP.", s.client.Stats().Requests, s.client.Failing()))
		}
		if s.res.Stop != nil && s.res.Stop.Code == StopConnectionFailed {
			s.res.Stop = nil // the request failed because of the interruption
		}
	}
	s.finish(start)
	return s.res
}

// runChecks runs the checks in the order of what they cost and what they
// are worth. A firewall that starts dropping requests usually does so
// after many guesses that answered 404, so the checks that read what the
// site shows come first, and the guesses last:
//
//  1. the version, the main theme, the plugins and themes the pages show,
//     the users, the libraries, and the findings at paths every WordPress
//     has (xmlrpc.php, robots.txt, the login page);
//  2. the findings that guess a path (debug.log, backups, exports), and the
//     media;
//  3. brute force of plugins and themes, when asked for;
//  4. what the folders of the plugins and themes found expose, and TimThumb.
//
// A scan cut short during a later part keeps what the earlier ones found.
func (s *Scanner) runChecks(ctx context.Context) {
	st := s.steps()
	quiet := []func(context.Context) []Finding{
		s.checkHeaders, s.checkSecurityHeaders, s.checkPHPVersion, s.checkDisplayedErrors,
		s.checkRobots, s.checkXMLRPC, s.checkReadme, s.checkFullPathDisclosure,
		s.checkMultisite, s.checkRegistration, s.checkUploadListing, s.checkWPCron,
	}
	guesses := []func(context.Context) []Finding{
		s.checkDebugLog, s.checkBackupDB, s.checkDuplicatorLog, s.checkMuPlugins, s.checkTmmDBMigrate,
		s.checkSQLDump, s.checkEmergencyScript, s.checkPHPDisabled, s.checkFantastico,
		s.checkSearchReplaceDB, s.checkSensitiveFiles, s.checkConfigBackups, s.checkDBExports,
		s.checkBackupFolders,
	}
	var checked atomic.Int32
	total := len(quiet) + len(guesses)
	runFindings := func(wg *sync.WaitGroup, checks []func(context.Context) []Finding) {
		for _, check := range checks {
			wg.Go(func() {
				if f := check(ctx); len(f) > 0 {
					s.mu.Lock()
					s.res.InterestingFindings = append(s.res.InterestingFindings, f...)
					s.mu.Unlock()
				}
				st.Update(stepFindings, fmt.Sprintf("%d/%d checks", checked.Add(1), total))
			})
		}
	}

	// Part 1: what the site shows.
	var wg sync.WaitGroup
	st.Start(stepFindings)
	runFindings(&wg, quiet)
	var v *Version
	var main *Theme
	var ps *pluginScan
	inventory := false
	// The ?ver= signals of themes and plugins need the core version, and
	// theme enumeration needs the main theme, so they come after.
	wg.Go(func() {
		st.Start(stepVersion)
		v = s.detectVersion(ctx)
		latest(v, s.data.lists.CoreLatest)
		s.setResult(func(r *Result) { r.Version = v })
		s.endStep(ctx, stepVersion, versionSummary(v))
		var others []*Theme
		inv := s.restInventory(ctx)
		if inv != nil && len(inv.themes) > 0 {
			inventory = true
			main, others = s.themesFromInventory(inv)
		} else {
			// Its signals are passive: aggressive mode skips it.
			if s.passive() {
				st.Start(stepMainTheme)
			}
			main = s.detectMainTheme(ctx, v)
			for t := main; t != nil; t = t.Parent {
				latest(t.Version, s.data.lists.Latest(wordlists.Themes, t.Slug))
			}
			if s.passive() {
				s.endStep(ctx, stepMainTheme, mainThemeSummary(main))
			}
		}
		s.setResult(func(r *Result) { r.MainTheme, r.Themes = main, others })
		var inner sync.WaitGroup
		inner.Go(func() {
			st.Start(stepPlugins)
			ps = s.discoverPlugins(ctx, v)
			plugins := s.pluginList(ps)
			s.setResult(func(r *Result) { r.Plugins = plugins })
			if !s.wantsPluginBruteForce() {
				s.endStep(ctx, stepPlugins, countSummary(len(plugins), "found", "none found"))
			}
		})
		if !inventory {
			inner.Go(func() {
				st.Start(stepThemes)
				themes := s.enumerateThemes(ctx, v, main, false)
				s.setResult(func(r *Result) { r.Themes = themes })
				if !s.wantsThemeBruteForce() {
					s.endStep(ctx, stepThemes, countSummary(len(themes), "other themes found", "no other theme found"))
				}
			})
		}
		inner.Wait()
	})
	if s.opts.Enumerate.Users != nil {
		wg.Go(func() {
			st.Start(stepUsers)
			users := s.enumerateUsers(ctx)
			s.setResult(func(r *Result) { r.Users = users })
			s.endStep(ctx, stepUsers, countSummary(len(users), "found", "none found"))
		})
	}
	wg.Go(func() {
		st.Start(stepJS)
		libs := s.detectJSLibraries(ctx)
		s.setResult(func(r *Result) { r.JSLibraries = libs })
		s.endStep(ctx, stepJS, countSummary(len(libs), "found", "none found"))
	})
	wg.Wait()

	// Part 2: the guesses.
	runFindings(&wg, guesses)
	if s.opts.Enumerate.Media != nil && s.aggressive() {
		wg.Go(func() {
			st.Start(stepMedia)
			media := s.enumerateMedia(ctx)
			s.setResult(func(r *Result) { r.Media = media })
			s.endStep(ctx, stepMedia, countSummary(len(media), "files found", "no file found"))
		})
	}
	wg.Wait()
	s.endStep(ctx, stepFindings, s.findingsSummary())

	// Part 3: brute force, the noisiest of all.
	if ps != nil && s.wantsPluginBruteForce() {
		wg.Go(func() {
			before := len(s.pluginList(ps))
			s.bruteForcePlugins(ctx, ps)
			plugins := s.pluginList(ps)
			s.setResult(func(r *Result) { r.Plugins = plugins })
			s.endBruteForce(ctx, stepPlugins, before, countSummary(len(plugins), "found", "none found"))
		})
	} else if ps != nil {
		s.bruteForcePlugins(ctx, ps) // nothing to request: it only explains -e ap without brute force
	}
	if !inventory && s.wantsThemeBruteForce() {
		wg.Go(func() {
			s.mu.Lock()
			before := len(s.res.Themes)
			s.mu.Unlock()
			if ctx.Err() == nil {
				themes := s.enumerateThemes(ctx, v, main, true)
				s.setResult(func(r *Result) { r.Themes = themes })
				before = len(themes)
			}
			s.endBruteForce(ctx, stepThemes, before, countSummary(before, "other themes found", "no other theme found"))
		})
	} else if !inventory {
		s.themeBruteForceNotice()
	}
	wg.Wait()

	// Part 4: these look into the folders of the themes and plugins found.
	if s.aggressive() {
		st.Start(stepFolders)
		n := s.checkItems(ctx)
		s.endStep(ctx, stepFolders, countSummary(n, "warnings", "nothing exposed"))
	} else {
		s.checkItems(ctx)
	}
	if s.opts.Enumerate.Timthumbs && s.aggressive() {
		st.Start(stepTimthumbs)
		s.res.Timthumbs = s.enumerateTimthumbs(ctx)
		s.endStep(ctx, stepTimthumbs, countSummary(len(s.res.Timthumbs), "found", "none found"))
	}
	st.Start(stepVulns)
	s.matchVulnerabilities()
	st.Done(stepVulns, s.vulnSummary()) // matching needs no request: it always finishes
}

// endBruteForce ends a step whose discovery finished earlier: when the
// scan stopped during the brute force, what discovery found still stands.
func (s *Scanner) endBruteForce(ctx context.Context, step string, found int, result string) {
	if ctx.Err() == nil {
		s.steps().Done(step, result)
		return
	}
	s.steps().Fail(step, fmt.Sprintf("%d found from what the site shows; the brute force was cut short", found))
}

// setResult changes the result under its lock.
func (s *Scanner) setResult(f func(*Result)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s.res)
}

func (s *Scanner) finish(start time.Time) {
	r := s.res
	r.FinishedAt = time.Now().UTC().Truncate(time.Second)
	r.Target.EffectiveURL = s.base.String()
	r.Target.Scope = s.client.Scope()
	sort.Strings(r.Target.Scope)
	sort.SliceStable(r.InterestingFindings, func(i, j int) bool {
		return findingRank(r.InterestingFindings[i].ID) < findingRank(r.InterestingFindings[j].ID)
	})
	sort.SliceStable(r.Errors, func(i, j int) bool { return r.Errors[i].URL < r.Errors[j].URL })
	r.Summary = Summarize(r)
	st := s.client.Stats()
	r.Stats = Stats{
		Requests:       st.Requests,
		BytesSent:      st.BytesSent,
		BytesReceived:  st.BytesReceived,
		ElapsedSeconds: math.Round(time.Since(start).Seconds()*1000) / 1000,
		Retries:        st.Retries,
		Blocked:        st.Blocked,
		FailedRequests: r.Stats.FailedRequests,
		NotFound:       st.NotFound,
		Slowdowns:      st.Slowdowns,
		Pauses:         st.Pauses,
	}
	if st.Slowdowns > 0 && r.Status != StatusBlocked {
		paused := ""
		if st.Pauses > 0 {
			paused = fmt.Sprintf(" and paused %s", times(st.Pauses))
		}
		r.Notices = append(r.Notices, fmt.Sprintf("The scan slowed down%s because the target started to refuse or drop requests (rate limits, overloads or timeouts), then went on, one request at a time. It took longer, but nothing was skipped.", paused))
	}
	if st.Blocked > 0 && r.Status != StatusBlocked {
		of := ""
		if n := s.probeBlocked.Load(); n > 0 {
			of = fmt.Sprintf(" (%d of them for plugin or theme checks, which stay unknown)", n)
		}
		r.Notices = append(r.Notices, fmt.Sprintf("%d answers were a rate limit, an overload or a firewall block page instead of the site%s: they were not counted as found or as absent. If that is many, scan more slowly (--throttle 1s --threads 1).", st.Blocked, of))
	}
	r.normalize()
}

func times(n int64) string {
	if n == 1 {
		return "once"
	}
	return fmt.Sprintf("%d times", n)
}

func (s *Scanner) passive() bool    { return s.opts.DetectionMode != cli.ModeAggressive }
func (s *Scanner) aggressive() bool { return s.opts.DetectionMode != cli.ModePassive }

// thorough reports whether the scan trades requests for coverage
// (--aggressive): the full lists of names to guess instead of the likeliest
// ones, and every way to read a version instead of stopping at the first
// good one.
func (s *Scanner) thorough() bool { return s.opts.Thorough && s.aggressive() }

// get fetches u once per scan; later calls for the same URL share the
// response. Failed requests are recorded in the result and return nil.
func (s *Scanner) get(ctx context.Context, u string) *httpclient.Response {
	s.cacheMu.Lock()
	f, ok := s.cache[u]
	if !ok {
		f = &fetch{done: make(chan struct{})}
		s.cache[u] = f
		s.cacheMu.Unlock()
		f.resp, f.err = s.client.Get(ctx, u)
		s.recordError(ctx, u, f.err)
		close(f.done)
		// A failure or a refusal is not the page: forget it, so that a
		// later check asks again.
		if f.err != nil || (f.resp != nil && f.resp.SiteBlocked) {
			s.cacheMu.Lock()
			if s.cache[u] == f {
				delete(s.cache, u)
			}
			s.cacheMu.Unlock()
		}
	} else {
		s.cacheMu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return nil
		}
	}
	return f.resp
}

// do sends a request that is not cached, such as a POST or a partial read.
func (s *Scanner) do(ctx context.Context, r httpclient.Request) *httpclient.Response {
	resp, err := s.client.Do(ctx, r)
	s.recordError(ctx, r.URL, err)
	return resp
}

func (s *Scanner) recordError(ctx context.Context, u string, err error) {
	if err == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res.Stats.FailedRequests++
	if len(s.res.Errors) < maxErrors {
		s.res.Errors = append(s.res.Errors, RequestError{URL: u, Error: err.Error()})
	}
}

// url resolves ref against the scanned URL, e.g. "readme.html".
func (s *Scanner) url(ref string) string {
	return s.base.ResolveReference(&url.URL{Path: ref}).String()
}

// urlWithQuery resolves a path and a raw query against the scanned URL.
func (s *Scanner) urlWithQuery(ref, rawQuery string) string {
	return s.base.ResolveReference(&url.URL{Path: ref, RawQuery: rawQuery}).String()
}

// contentURL resolves ref against the wp-content directory.
func (s *Scanner) contentURL(ref string) string {
	return s.content.ResolveReference(&url.URL{Path: ref}).String()
}

// under resolves ref against a directory such as s.plugins.
func under(dir *url.URL, ref string) string {
	return dir.ResolveReference(&url.URL{Path: ref}).String()
}

// pages returns the homepage and the 404 page with a label for evidence.
func (s *Scanner) pages() []labelledPage {
	out := []labelledPage{{"homepage", modePassive, s.home}}
	if s.notFound != nil && s.notFound.resp != nil {
		out = append(out, labelledPage{"404 page", modePassive, s.notFound})
	}
	return out
}

// discoveryPages returns the pages plugin, theme, library and user
// discovery read: the homepage and the 404 page (passive), then the pages
// the crawl fetched (aggressive).
func (s *Scanner) discoveryPages(ctx context.Context) []labelledPage {
	var out []labelledPage
	if s.passive() {
		out = s.pages()
	}
	return append(out, s.sitePages(ctx).pages...)
}

type labelledPage struct {
	label string
	mode  string // the mode of the signals read from the page
	*page
}

// scopedURLs returns the in-scope URLs a page references.
func (s *Scanner) scopedURLs(p *page) []*url.URL {
	var out []*url.URL
	for _, u := range p.urls {
		if s.client.InScope(u) {
			out = append(out, u)
		}
	}
	return out
}

// combine merges confidences as independent probabilities: two signals of
// 60% and 80% give 92%. Repeats of the same method only count once (its
// highest confidence).
func combine(ev []Evidence) int {
	best := map[string]int{}
	for _, e := range ev {
		best[e.Method] = max(best[e.Method], e.Confidence)
	}
	miss := 1.0
	for _, c := range best {
		miss *= 1 - float64(min(c, 100))/100
	}
	return int(math.Round((1 - miss) * 100))
}

func sortEvidence(ev []Evidence) {
	slices.SortStableFunc(ev, func(a, b Evidence) int {
		if a.Confidence != b.Confidence {
			return b.Confidence - a.Confidence
		}
		return 0
	})
}
