package scan

import "time"

// SchemaVersion is the version of the JSON report format described in
// docs/json-report.md. It changes only when a field is removed or changes
// meaning; new fields can appear without a bump.
const SchemaVersion = 1

// Scan status values.
const (
	StatusCompleted   = "completed"   // every check ran
	StatusStopped     = "stopped"     // a pre-flight check stopped the scan; see Result.Stop
	StatusInterrupted = "interrupted" // the user interrupted the scan; results are partial
)

// Stop codes explain why a pre-flight check stopped the scan.
const (
	StopConnectionFailed  = "connection_failed"
	StopHTTPAuthRequired  = "http_auth_required"
	StopProxyAuthRequired = "proxy_auth_required"
	StopForbidden         = "forbidden"
	StopRedirect          = "redirect"
	StopNotWordPress      = "not_wordpress"
	StopWordPressCom      = "wordpress_com"
	StopUnfinishedInstall = "unfinished_install"
)

// Severities of interesting findings, lowest first.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Result is everything a scan found. It is also the JSON report.
type Result struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          Tool      `json:"tool"`
	Target        Target    `json:"target"`
	DetectionMode string    `json:"detection_mode"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Status        string    `json:"status"`
	Stop          *Stop     `json:"stop"`

	WebServer           *WebServer `json:"web_server"`
	WordPress           *WordPress `json:"wordpress"`
	InterestingFindings []Finding  `json:"interesting_findings"`
	Version             *Version   `json:"version"`
	MainTheme           *Theme     `json:"main_theme"`

	Notices []string       `json:"notices"`
	Errors  []RequestError `json:"errors"`
	Stats   Stats          `json:"stats"`
}

// Tool identifies the scanner.
type Tool struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	UserAgent string `json:"user_agent"`
}

// Target describes what was scanned.
type Target struct {
	URL          string     `json:"url"`           // the URL given on the command line, normalized
	EffectiveURL string     `json:"effective_url"` // the URL scanned after followed redirects
	Redirects    []Redirect `json:"redirects"`
	Scope        []string   `json:"scope"`
}

// Redirect reasons.
const (
	RedirectInScope    = "in_scope"        // followed: the target host or a --scope domain
	RedirectFollowFlag = "follow_redirect" // followed because of --follow-redirect
	RedirectOutOfScope = "out_of_scope"    // not followed; the scan stopped
)

// Redirect is one homepage redirect seen during pre-flight.
type Redirect struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Status   int    `json:"status"`
	Followed bool   `json:"followed"`
	Reason   string `json:"reason"`
}

// Stop explains why the scan stopped early.
type Stop struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// WebServer is what the homepage's Server header says.
type WebServer struct {
	Header string `json:"header"` // raw Server header, empty when absent
	Family string `json:"family"` // apache, nginx, iis or unknown
}

// WordPress is the result of WordPress detection.
type WordPress struct {
	Detected   bool       `json:"detected"`
	ContentURL string     `json:"content_url,omitempty"` // the wp-content directory
	Evidence   []Evidence `json:"evidence"`
}

// Evidence is one signal behind a finding, version or theme.
type Evidence struct {
	Method     string `json:"method"` // how it was found, e.g. "Meta generator"
	Mode       string `json:"mode"`   // passive or aggressive
	URL        string `json:"url,omitempty"`
	Value      string `json:"value,omitempty"` // what the signal said, e.g. a version number
	Confidence int    `json:"confidence"`      // 0-100
}

// Finding is an interesting finding. Data holds machine-readable details
// whose keys are documented per finding ID in docs/json-report.md.
type Finding struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Severity   string         `json:"severity"`
	URL        string         `json:"url,omitempty"`
	Confidence int            `json:"confidence"`
	Entries    []string       `json:"entries"`
	Data       map[string]any `json:"data,omitempty"`
	References []string       `json:"references"`
	Evidence   []Evidence     `json:"evidence"`
}

// Version is a detected version. Number is empty when no candidate reached
// MinVersionConfidence.
type Version struct {
	Number     string      `json:"number"`
	Confidence int         `json:"confidence"`
	Candidates []Candidate `json:"candidates"`
	Evidence   []Evidence  `json:"evidence"`
}

// Candidate is one version number with the combined confidence of the
// signals that reported it.
type Candidate struct {
	Number     string `json:"number"`
	Confidence int    `json:"confidence"`
}

// Theme is a detected theme.
type Theme struct {
	Slug       string     `json:"slug"`
	Location   string     `json:"location"`
	StyleURL   string     `json:"style_url"`
	Confidence int        `json:"confidence"`
	Name       string     `json:"name,omitempty"`
	ThemeURI   string     `json:"theme_uri,omitempty"`
	Author     string     `json:"author,omitempty"`
	AuthorURI  string     `json:"author_uri,omitempty"`
	Version    *Version   `json:"version"`
	Parent     *Theme     `json:"parent,omitempty"`
	Evidence   []Evidence `json:"evidence"`
}

// RequestError is a request that failed during the checks. Failed requests
// do not stop the scan; the check they belong to reports nothing.
type RequestError struct {
	URL   string `json:"url"`
	Error string `json:"error"`
}

// Stats is the report footer.
type Stats struct {
	Requests       int64   `json:"requests"`
	BytesSent      int64   `json:"bytes_sent"`
	BytesReceived  int64   `json:"bytes_received"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
}

// normalize replaces nil slices with empty ones so the JSON report always
// has arrays where the format documents them.
func (r *Result) normalize() {
	r.Target.Redirects = nonNil(r.Target.Redirects)
	r.Target.Scope = nonNil(r.Target.Scope)
	r.InterestingFindings = nonNil(r.InterestingFindings)
	for i := range r.InterestingFindings {
		f := &r.InterestingFindings[i]
		f.Entries, f.References, f.Evidence = nonNil(f.Entries), nonNil(f.References), nonNil(f.Evidence)
	}
	if r.WordPress != nil {
		r.WordPress.Evidence = nonNil(r.WordPress.Evidence)
	}
	r.Version.normalize()
	for t := r.MainTheme; t != nil; t = t.Parent {
		t.Evidence = nonNil(t.Evidence)
		t.Version.normalize()
	}
	r.Notices = nonNil(r.Notices)
	r.Errors = nonNil(r.Errors)
}

func (v *Version) normalize() {
	if v != nil {
		v.Candidates, v.Evidence = nonNil(v.Candidates), nonNil(v.Evidence)
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
