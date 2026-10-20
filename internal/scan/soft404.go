package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// similarThreshold is how alike two normalized bodies must be (0-1) to count
// as the same page.
const similarThreshold = 0.9

// baseline is the response to a random, non-existent path. Catch-all sites,
// WAFs and "403 for everything" setups answer every path the same way, so a
// response that matches the baseline of its directory says nothing.
type baseline struct {
	once   sync.Once
	name   string // the random file or directory name requested
	resp   *httpclient.Response
	tokens bag
}

// baselineFor returns the response to a random path next to u: in the same
// directory, with the same extension, or a directory when u is one. It is
// fetched once per (directory, extension) and may be nil if the request failed.
func (s *Scanner) baselineFor(ctx context.Context, u *url.URL) *baseline {
	dir, suffix := baselineKey(u.Path)
	key := u.Scheme + "://" + u.Host + dir + "|" + suffix

	s.baseMu.Lock()
	b, ok := s.baselines[key]
	if !ok {
		b = &baseline{}
		s.baselines[key] = b
	}
	s.baseMu.Unlock()

	b.once.Do(func() {
		b.name = randomName() + suffix
		ref := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: dir + b.name}
		b.resp = s.do(ctx, httpclient.Request{URL: ref.String()})
		if b.resp != nil {
			b.tokens = tokenize(b.resp.Body, strings.TrimSuffix(b.name, "/"))
		}
	})
	if b.resp == nil {
		return nil
	}
	return b
}

// baselineKey splits a path into its directory and the suffix a random
// sibling needs: "/" for directories, the extension for files.
func baselineKey(p string) (dir, suffix string) {
	if strings.HasSuffix(p, "/") {
		dir, suffix = path.Dir(strings.TrimSuffix(p, "/")), "/"
	} else {
		dir, suffix = path.Dir(p), path.Ext(p)
	}
	if dir == "." {
		dir = "/"
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return dir, suffix
}

// isNotFound reports whether res, the response for u, means "not found": a
// 404 or 410, or a soft-404, i.e. the homepage or the same answer a random
// path in the same directory gets.
func (s *Scanner) isNotFound(ctx context.Context, u *url.URL, res *httpclient.Response) bool {
	if res == nil || res.StatusCode == 404 || res.StatusCode == 410 {
		return true
	}
	name := path.Base(strings.TrimSuffix(u.Path, "/"))
	if b := s.baselineFor(ctx, u); b != nil && sameAnswer(res, name, b) {
		return true
	}
	if res.StatusCode == 200 && s.home != nil && s.home.resp != nil && s.home.resp.StatusCode == 200 {
		if similarity(tokenize(res.Body, name), tokenize(s.home.resp.Body)) >= similarThreshold {
			return true
		}
	}
	return false
}

// sameAnswer compares a response with a baseline: same status and either the
// same redirect target or a similar body.
func sameAnswer(res *httpclient.Response, name string, b *baseline) bool {
	if res.StatusCode != b.resp.StatusCode {
		return false
	}
	if res.IsRedirect() {
		la, errA := res.Location()
		lb, errB := b.resp.Location()
		if errA != nil || errB != nil {
			return false
		}
		bname := strings.TrimSuffix(b.name, "/")
		return strings.ReplaceAll(la.String(), name, "") == strings.ReplaceAll(lb.String(), bname, "")
	}
	return similarity(tokenize(res.Body, name), b.tokens) >= similarThreshold
}

// bag is a multiset of page tokens.
type bag map[string]int

var (
	hexRunRe = regexp.MustCompile(`[0-9a-fA-F]{8,}`)
	digitsRe = regexp.MustCompile(`[0-9]+`)
)

// tokenize normalizes a body and splits it into tags and lines. The request
// path names are removed (pages often echo them), and hex runs and numbers
// are collapsed so that nonces and timestamps do not make identical pages
// look different.
func tokenize(body []byte, names ...string) bag {
	s := string(body)
	for _, n := range names {
		if n != "" && n != "." && n != "/" {
			s = strings.ReplaceAll(s, n, "")
		}
	}
	s = hexRunRe.ReplaceAllString(s, "#")
	s = digitsRe.ReplaceAllString(s, "0")
	b := bag{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '<' || r == '\n' }) {
		if t := strings.TrimSpace(part); t != "" {
			b[t]++
		}
	}
	return b
}

// similarity is the Dice coefficient of two token bags: 1 for identical
// pages, 0 for pages with nothing in common.
func similarity(a, b bag) float64 {
	var na, nb, common int
	for t, n := range a {
		na += n
		common += min(n, b[t])
	}
	for _, n := range b {
		nb += n
	}
	if na+nb == 0 {
		return 1
	}
	return 2 * float64(common) / float64(na+nb)
}

func randomName() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
