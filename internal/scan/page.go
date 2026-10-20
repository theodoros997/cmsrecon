package scan

import (
	"bytes"
	"html"
	"net/url"
	"regexp"
	"strings"

	xhtml "golang.org/x/net/html"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// page is a fetched HTML page with the parts the finders look at.
type page struct {
	resp        *httpclient.Response
	text        string     // body with JSON "\/" escapes and HTML entities decoded
	generators  []string   // <meta name="generator"> contents
	links       []pageLink // <link> elements
	bodyClasses []string
	urls        []*url.URL // every http(s) URL the page references, resolved and deduplicated
}

type pageLink struct {
	rel  string // lower case
	typ  string // lower case
	href *url.URL
}

// urlAttrs are the attributes whose values are URLs (srcset is split).
var urlAttrs = map[string]bool{
	"src": true, "href": true, "action": true, "poster": true, "data": true,
	"data-src": true, "data-href": true, "data-lazy-src": true,
	"srcset": true, "data-srcset": true, "content": true,
}

var (
	// Absolute and protocol-relative URLs anywhere in the page, including
	// inline scripts and styles. Protocol-relative ones need a dot in the
	// host so that "//comment" in JavaScript is not taken for a URL.
	absURLRe = regexp.MustCompile(`(?i)(?:https?://[a-z0-9.\-]+|//[a-z0-9\-]+\.[a-z0-9.\-]+)(?::\d+)?(?:/[^\s"'<>()\\]*)?`)
	cssURLRe = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")\s]+)`)
)

func parsePage(resp *httpclient.Response) *page {
	p := &page{resp: resp}
	if resp == nil {
		return p
	}
	p.text = html.UnescapeString(strings.ReplaceAll(string(resp.Body), `\/`, "/"))

	seen := map[string]bool{}
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "data:") {
			return
		}
		u, err := resp.URL.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return
		}
		u.Fragment = ""
		if s := u.String(); !seen[s] {
			seen[s] = true
			p.urls = append(p.urls, u)
		}
	}

	z := xhtml.NewTokenizer(bytes.NewReader(resp.Body))
	for {
		tt := z.Next()
		if tt == xhtml.ErrorToken {
			break
		}
		if tt != xhtml.StartTagToken && tt != xhtml.SelfClosingTagToken {
			continue
		}
		t := z.Token()
		attrs := map[string]string{}
		for _, a := range t.Attr {
			attrs[strings.ToLower(a.Key)] = a.Val
		}
		switch t.Data {
		case "meta":
			if strings.EqualFold(attrs["name"], "generator") {
				p.generators = append(p.generators, strings.TrimSpace(attrs["content"]))
			}
		case "link":
			if href, err := resp.URL.Parse(strings.TrimSpace(attrs["href"])); err == nil && attrs["href"] != "" {
				p.links = append(p.links, pageLink{
					rel:  strings.ToLower(attrs["rel"]),
					typ:  strings.ToLower(attrs["type"]),
					href: href,
				})
			}
		case "body":
			p.bodyClasses = strings.Fields(attrs["class"])
		}
		for name, val := range attrs {
			switch {
			case !urlAttrs[name]:
			case strings.HasSuffix(name, "srcset"):
				for _, part := range strings.Split(val, ",") {
					if f := strings.Fields(part); len(f) > 0 {
						add(f[0])
					}
				}
			case name == "content":
				// Only meta contents that are URLs, e.g. og:image.
				if strings.HasPrefix(val, "http") || strings.HasPrefix(val, "/") {
					add(val)
				}
			default:
				add(val)
			}
		}
	}

	for _, m := range absURLRe.FindAllString(p.text, -1) {
		add(m)
	}
	for _, m := range cssURLRe.FindAllStringSubmatch(p.text, -1) {
		add(m[1])
	}
	return p
}

// linksTo returns the hrefs of <link> elements whose rel contains rel.
func (p *page) linksTo(rel string) []*url.URL {
	var out []*url.URL
	for _, l := range p.links {
		for _, r := range strings.Fields(l.rel) {
			if r == rel {
				out = append(out, l.href)
				break
			}
		}
	}
	return out
}
