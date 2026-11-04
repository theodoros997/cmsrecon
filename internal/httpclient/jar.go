package httpclient

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

// scopedJar keeps the cookies the site sets and sends them back, to
// in-scope hosts only: a cookie check or a load balancer that redirects
// until its cookie comes back would otherwise loop.
type scopedJar struct {
	jar *cookiejar.Jar
	c   *Client
}

func newScopedJar(c *Client) (*scopedJar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &scopedJar{jar: jar, c: c}, nil
}

func (j *scopedJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j.c.InScope(u) {
		j.jar.SetCookies(u, cookies)
	}
}

func (j *scopedJar) Cookies(u *url.URL) []*http.Cookie {
	if !j.c.InScope(u) {
		return nil
	}
	return j.jar.Cookies(u)
}
