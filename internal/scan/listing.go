package scan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// listingSignatures are the directory-listing pages of each web server
// family. Apache and nginx both title their listings "Index of /path".
var listingSignatures = map[string]*regexp.Regexp{
	"apache": regexp.MustCompile(`(?i)<(?:title|h1)>Index of /`),
	"nginx":  regexp.MustCompile(`(?i)<(?:title|h1)>Index of /`),
	"iis":    regexp.MustCompile(`(?i)\[To Parent Directory\]|<title>[^<]+ - /[^<]*</title>\s*</head>\s*<body>\s*<h1>`),
}

var listingLinkRe = regexp.MustCompile(`(?i)<a\s+href="([^"]+)"[^>]*>([^<]+)</a>`)

const maxListingEntries = 20

// dirListing reports whether res is a directory listing, using the
// signature of the detected web server or, when it is unknown, all of them.
// It returns the listed names, at most maxListingEntries of them.
func (s *Scanner) dirListing(res *httpclient.Response) ([]string, bool) {
	names, ok := s.listingEntries(res)
	if len(names) > maxListingEntries {
		more := len(names) - maxListingEntries
		names = append(names[:maxListingEntries:maxListingEntries], fmt.Sprintf("... and %d more", more))
	}
	return names, ok
}

// listingEntries is dirListing without the cap on the number of names.
func (s *Scanner) listingEntries(res *httpclient.Response) ([]string, bool) {
	if res == nil || res.StatusCode != 200 {
		return nil, false
	}
	listed := false
	if sig, ok := listingSignatures[s.server]; ok {
		listed = sig.Match(res.Body)
	} else {
		for _, sig := range listingSignatures {
			listed = listed || sig.Match(res.Body)
		}
	}
	if !listed {
		return nil, false
	}
	var names []string
	for _, m := range listingLinkRe.FindAllSubmatch(res.Body, -1) {
		href, text := string(m[1]), strings.TrimSpace(string(m[2]))
		if strings.HasPrefix(href, "?") || href == "../" || href == "/" || strings.Contains(text, "Parent Directory") || text == "../" {
			continue
		}
		names = append(names, text)
	}
	return names, true
}
