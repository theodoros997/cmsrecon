package scan

import (
	"time"

	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// SchemaVersion is the version of the JSON report format described in
// docs/json-report.md. It changes only when a field is removed or changes
// meaning; new fields can appear without a bump.
const SchemaVersion = 1

// Scan status values.
const (
	StatusCompleted   = "completed"   // every check ran
	StatusStopped     = "stopped"     // a pre-flight check stopped the scan; see Result.Stop
	StatusInterrupted = "interrupted" // the user interrupted the scan; results are partial
	StatusTimedOut    = "timed_out"   // the scan reached --max-scan-duration; results are partial
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

	WebServer           *WebServer      `json:"web_server"`
	WordPress           *WordPress      `json:"wordpress"`
	InterestingFindings []Finding       `json:"interesting_findings"`
	Version             *Version        `json:"version"`
	CoreVulnerabilities []Vulnerability `json:"core_vulnerabilities"`
	MainTheme           *Theme          `json:"main_theme"`
	Themes              []*Theme        `json:"themes"`
	Plugins             []*Plugin       `json:"plugins"`
	JSLibraries         []*JSLibrary    `json:"js_libraries"`
	Users               []*User         `json:"users"`
	Timthumbs           []*Timthumb     `json:"timthumbs"`
	Media               []*Media        `json:"media"`

	VulnerabilityData   *DataInfo  `json:"vulnerability_data"`
	VulnerabilityCounts VulnCounts `json:"vulnerability_counts"`

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
	Latest     string      `json:"latest,omitempty"`   // the latest release, from the WordPress.org data
	Outdated   bool        `json:"outdated,omitempty"` // Number is older than Latest
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

	LastUpdated     string          `json:"last_updated,omitempty"` // on WordPress.org, YYYY-MM-DD
	Warnings        []string        `json:"warnings"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Possible        *PossibleVulns  `json:"possible_vulnerabilities,omitempty"`
	// Exploits are Exploit-DB entries that name the theme, and a version
	// that can include the detected one, but no CVE: matched by name, so
	// they may not apply.
	Exploits []Exploit `json:"exploits,omitempty"`
}

// PossibleVulns summarizes the vulnerabilities that may apply to a
// component whose version is unknown or uncertain. They are listed in
// Vulnerabilities only with --possible: a plugin with an unknown version
// can have hundreds.
type PossibleVulns struct {
	Count    int    `json:"count"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	FixedIn  string `json:"fixed_in,omitempty"` // a version that fixes every one of them; omitted when one has no fix
	Exploits int    `json:"with_exploits"`      // how many have a public exploit
	Listed   bool   `json:"listed"`             // they are in vulnerabilities too
}

// Plugin is a detected plugin.
type Plugin struct {
	Slug       string     `json:"slug"`
	Name       string     `json:"name,omitempty"`     // from its readme
	Location   string     `json:"location,omitempty"` // its folder, when a page or a request showed it
	ReadmeURL  string     `json:"readme_url,omitempty"`
	Confidence int        `json:"confidence"`
	Version    *Version   `json:"version"`
	Evidence   []Evidence `json:"evidence"`

	LastUpdated     string          `json:"last_updated,omitempty"` // on WordPress.org, YYYY-MM-DD
	Warnings        []string        `json:"warnings"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Possible        *PossibleVulns  `json:"possible_vulnerabilities,omitempty"`
	// Exploits are Exploit-DB entries that name the plugin, and a version
	// that can include the detected one, but no CVE: matched by name, so
	// they may not apply.
	Exploits []Exploit `json:"exploits,omitempty"`
}

// JSLibrary is a JavaScript library the scanned pages load.
type JSLibrary struct {
	Name    string   `json:"name"`
	Version *Version `json:"version"`
	URLs    []string `json:"urls"` // where it was seen, at most five

	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// User is a WordPress account found on the site. Username is the login
// slug (user_nicename), which is usually the login name; it is empty when
// only a display name was seen.
type User struct {
	ID          int        `json:"id,omitempty"`
	Username    string     `json:"username,omitempty"`
	DisplayName string     `json:"display_name,omitempty"`
	Confidence  int        `json:"confidence"`
	Evidence    []Evidence `json:"evidence"`
}

// Vulnerability verdicts, strongest first.
const (
	VerdictConfirmed = "confirmed" // the detected version is affected
	VerdictLikely    = "likely"    // affected, but the version is less certain or the sources disagree
	VerdictPossible  = "possible"  // the version is unknown, or only a secondary source says it is affected
)

// Vulnerability is a known vulnerability that applies, or may apply, to a
// detected component.
type Vulnerability struct {
	Title      string    `json:"title"`
	Verdict    string    `json:"verdict"`
	Severity   string    `json:"severity,omitempty"` // critical, high, medium or low; omitted when unknown
	CVSS       float64   `json:"cvss,omitempty"`
	CVSSVector string    `json:"cvss_vector,omitempty"`
	CVE        []string  `json:"cve"`
	CWE        string    `json:"cwe,omitempty"`
	Affected   []string  `json:"affected_versions"`
	FixedIn    string    `json:"fixed_in,omitempty"`
	Unfixed    bool      `json:"unfixed,omitempty"` // no fixed version exists
	Published  string    `json:"published,omitempty"`
	Sources    []string  `json:"sources"`        // wordfence, cve or retirejs
	Note       string    `json:"note,omitempty"` // why the verdict is not confirmed, e.g. the sources disagree
	References []string  `json:"references"`
	Exploits   []Exploit `json:"exploits,omitempty"` // public exploits and proofs of concept, most trustworthy first
}

// Exploit is a public exploit or proof of concept for one of a
// vulnerability's CVEs: a link, never downloaded or run.
type Exploit = vulndb.Exploit

// Timthumb is a copy of the TimThumb image resizing script (-e tt).
type Timthumb struct {
	URL             string          `json:"url"`
	Version         *Version        `json:"version"`
	Evidence        []Evidence      `json:"evidence"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Media is an uploaded file (-e m).
type Media struct {
	ID       int        `json:"id"`
	URL      string     `json:"url,omitempty"`      // the file; omitted when only its attachment page was seen
	PageURL  string     `json:"page_url,omitempty"` // its attachment page
	MimeType string     `json:"mime_type,omitempty"`
	Title    string     `json:"title,omitempty"`
	Evidence []Evidence `json:"evidence"`
}

// DataInfo describes the vulnerability data a scan used.
type DataInfo struct {
	Directory string       `json:"directory"`
	Sources   []DataSource `json:"sources"`
}

// DataSource is one source of data "cmsrecon update" downloaded.
type DataSource struct {
	Name      string    `json:"name"` // wordfence, cve, wporg or retirejs
	UpdatedAt time.Time `json:"updated_at"`
	Entries   int       `json:"entries,omitempty"`
}

// VulnCounts counts the vulnerabilities of every component by verdict.
type VulnCounts struct {
	Confirmed int `json:"confirmed"`
	Likely    int `json:"likely"`
	Possible  int `json:"possible"`
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
	r.CoreVulnerabilities = normalizeVulns(r.CoreVulnerabilities)
	for t := r.MainTheme; t != nil; t = t.Parent {
		t.normalize()
	}
	r.Themes = nonNil(r.Themes)
	for _, t := range r.Themes {
		t.normalize()
	}
	r.Plugins = nonNil(r.Plugins)
	for _, p := range r.Plugins {
		p.Evidence, p.Warnings = nonNil(p.Evidence), nonNil(p.Warnings)
		p.Version.normalize()
		p.Vulnerabilities = normalizeVulns(p.Vulnerabilities)
	}
	r.JSLibraries = nonNil(r.JSLibraries)
	for _, l := range r.JSLibraries {
		l.URLs = nonNil(l.URLs)
		l.Version.normalize()
		l.Vulnerabilities = normalizeVulns(l.Vulnerabilities)
	}
	r.Users = nonNil(r.Users)
	for _, u := range r.Users {
		u.Evidence = nonNil(u.Evidence)
	}
	r.Timthumbs = nonNil(r.Timthumbs)
	for _, t := range r.Timthumbs {
		t.Evidence = nonNil(t.Evidence)
		t.Version.normalize()
		t.Vulnerabilities = normalizeVulns(t.Vulnerabilities)
	}
	r.Media = nonNil(r.Media)
	for _, m := range r.Media {
		m.Evidence = nonNil(m.Evidence)
	}
	if r.VulnerabilityData != nil {
		r.VulnerabilityData.Sources = nonNil(r.VulnerabilityData.Sources)
	}
	r.Notices = nonNil(r.Notices)
	r.Errors = nonNil(r.Errors)
}

func (t *Theme) normalize() {
	t.Evidence, t.Warnings = nonNil(t.Evidence), nonNil(t.Warnings)
	t.Version.normalize()
	t.Vulnerabilities = normalizeVulns(t.Vulnerabilities)
}

func normalizeVulns(vs []Vulnerability) []Vulnerability {
	vs = nonNil(vs)
	for i := range vs {
		vs[i].CVE, vs[i].Affected = nonNil(vs[i].CVE), nonNil(vs[i].Affected)
		vs[i].Sources, vs[i].References = nonNil(vs[i].Sources), nonNil(vs[i].References)
	}
	return vs
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
