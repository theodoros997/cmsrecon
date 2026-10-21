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

	opts   *cli.ScanOptions
	client *httpclient.Client
	base   *url.URL // the scanned URL, updated by followed redirects
	data   *scanData

	home     *page
	notFound *page    // the answer to a random path: the site's 404 page
	content  *url.URL // the wp-content directory on the target host
	plugins  *url.URL // the plugins directory: <content>/plugins/ or --wp-plugins-dir
	themes   *url.URL // the themes directory: <content>/themes/
	server   string   // web server family

	cacheMu sync.Mutex
	cache   map[string]*fetch

	baseMu    sync.Mutex
	baselines map[string]*baseline

	headRefused atomic.Bool // the server answers HEAD with 405 or 501

	restOnce  sync.Once
	restAPI   *restAPI
	crawlOnce sync.Once
	crawled   *crawlResult
	invOnce   sync.Once
	inv       *inventory

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
	s.res = &Result{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "cmsrecon", Version: buildinfo.Version, UserAgent: s.client.UserAgent()},
		Target:        Target{URL: s.opts.Target.String(), EffectiveURL: s.base.String()},
		DetectionMode: string(s.opts.DetectionMode),
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
		if errors.Is(context.Cause(ctx), errMaxDuration) {
			s.res.Status = StatusTimedOut
			s.res.Notices = append(s.res.Notices, fmt.Sprintf("The scan stopped after --max-scan-duration %s: the checks still running were cut short, so the results are partial.", s.opts.MaxScanDuration))
		}
		if s.res.Stop != nil && s.res.Stop.Code == StopConnectionFailed {
			s.res.Stop = nil // the request failed because of the interruption
		}
	}
	s.finish(start)
	return s.res
}

func (s *Scanner) runChecks(ctx context.Context) {
	checks := []func(context.Context) []Finding{
		s.checkHeaders, s.checkRobots, s.checkXMLRPC, s.checkReadme, s.checkDebugLog,
		s.checkFullPathDisclosure, s.checkBackupDB, s.checkDuplicatorLog, s.checkMultisite,
		s.checkMuPlugins, s.checkRegistration, s.checkUploadListing, s.checkTmmDBMigrate,
		s.checkSQLDump, s.checkEmergencyScript, s.checkWPCron, s.checkPHPDisabled,
		s.checkFantastico, s.checkSearchReplaceDB, s.checkConfigBackups, s.checkDBExports,
		s.checkBackupFolders,
	}
	st := s.steps()
	var wg sync.WaitGroup
	var checked atomic.Int32
	st.Start(stepFindings)
	for _, check := range checks {
		wg.Go(func() {
			if f := check(ctx); len(f) > 0 {
				s.mu.Lock()
				s.res.InterestingFindings = append(s.res.InterestingFindings, f...)
				s.mu.Unlock()
			}
			if n := int(checked.Add(1)); n < len(checks) {
				st.Update(stepFindings, fmt.Sprintf("%d/%d checks", n, len(checks)))
			} else {
				st.Done(stepFindings, s.findingsSummary())
			}
		})
	}
	// The ?ver= signals of themes and plugins need the core version, and
	// theme enumeration needs the main theme, so they come after.
	wg.Go(func() {
		st.Start(stepVersion)
		v := s.detectVersion(ctx)
		latest(v, s.data.lists.CoreLatest)
		st.Done(stepVersion, versionSummary(v))
		var main *Theme
		var others []*Theme
		var plugins []*Plugin
		inv := s.restInventory(ctx)
		if inv != nil && len(inv.themes) > 0 {
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
				st.Done(stepMainTheme, mainThemeSummary(main))
			}
		}
		var inner sync.WaitGroup
		inner.Go(func() {
			st.Start(stepPlugins)
			plugins = s.detectPlugins(ctx, v)
			st.Done(stepPlugins, countSummary(len(plugins), "found", "none found"))
		})
		if inv == nil || len(inv.themes) == 0 {
			inner.Go(func() {
				st.Start(stepThemes)
				others = s.enumerateThemes(ctx, v, main)
				st.Done(stepThemes, countSummary(len(others), "other themes found", "no other theme found"))
			})
		}
		inner.Wait()
		s.mu.Lock()
		s.res.Version, s.res.MainTheme, s.res.Themes, s.res.Plugins = v, main, others, plugins
		s.mu.Unlock()
	})
	if s.opts.Enumerate.Users != nil {
		wg.Go(func() {
			st.Start(stepUsers)
			users := s.enumerateUsers(ctx)
			s.mu.Lock()
			s.res.Users = users
			s.mu.Unlock()
			st.Done(stepUsers, countSummary(len(users), "found", "none found"))
		})
	}
	wg.Go(func() {
		st.Start(stepJS)
		libs := s.detectJSLibraries(ctx)
		s.mu.Lock()
		s.res.JSLibraries = libs
		s.mu.Unlock()
		st.Done(stepJS, countSummary(len(libs), "found", "none found"))
	})
	if s.opts.Enumerate.Media != nil && s.aggressive() {
		wg.Go(func() {
			st.Start(stepMedia)
			media := s.enumerateMedia(ctx)
			s.mu.Lock()
			s.res.Media = media
			s.mu.Unlock()
			st.Done(stepMedia, countSummary(len(media), "files found", "no file found"))
		})
	}
	wg.Wait()
	// These look into the folders of the themes and plugins found.
	if s.aggressive() {
		st.Start(stepFolders)
		n := s.checkItems(ctx)
		st.Done(stepFolders, countSummary(n, "warnings", "nothing exposed"))
	} else {
		s.checkItems(ctx)
	}
	if s.opts.Enumerate.Timthumbs && s.aggressive() {
		st.Start(stepTimthumbs)
		s.res.Timthumbs = s.enumerateTimthumbs(ctx)
		st.Done(stepTimthumbs, countSummary(len(s.res.Timthumbs), "found", "none found"))
	}
	st.Start(stepVulns)
	s.matchVulnerabilities()
	st.Done(stepVulns, s.vulnSummary())
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
	st := s.client.Stats()
	r.Stats = Stats{
		Requests:       st.Requests,
		BytesSent:      st.BytesSent,
		BytesReceived:  st.BytesReceived,
		ElapsedSeconds: math.Round(time.Since(start).Seconds()*1000) / 1000,
	}
	r.normalize()
}

func (s *Scanner) passive() bool    { return s.opts.DetectionMode != cli.ModeAggressive }
func (s *Scanner) aggressive() bool { return s.opts.DetectionMode != cli.ModePassive }

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
	s.res.Errors = append(s.res.Errors, RequestError{URL: u, Error: err.Error()})
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
