package scan

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// listMethodsCall asks the server which XML-RPC methods it exposes. It is
// read-only: it calls nothing else and sends no credentials.
const listMethodsCall = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`

// xmlrpcValue is a <value>, typed (<string>, <int>) or untyped.
type xmlrpcValue struct {
	String string `xml:"string"`
	Int    string `xml:"int"`
	Text   string `xml:",chardata"`
}

func (v xmlrpcValue) str() string {
	for _, s := range []string{v.String, v.Int, v.Text} {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

type methodResponse struct {
	Values []xmlrpcValue `xml:"params>param>value>array>data>value"`
	Fault  *struct {
		Members []struct {
			Name  string      `xml:"name"`
			Value xmlrpcValue `xml:"value"`
		} `xml:"value>struct>member"`
	} `xml:"fault"`
}

func parseMethodResponse(body []byte) (*methodResponse, error) {
	var mr methodResponse
	d := xml.NewDecoder(bytes.NewReader(body))
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := d.Decode(&mr); err != nil {
		return nil, err
	}
	return &mr, nil
}

func (s *Scanner) checkXMLRPC(ctx context.Context) []Finding {
	f := Finding{ID: idXMLRPC, Severity: SeverityInfo,
		References: []string{"https://codex.wordpress.org/XML-RPC_Pingback_API"}}

	// The advertised endpoint is used even in aggressive mode, where it
	// only picks the URL and is not reported as evidence.
	if xp := s.home.resp.Header.Get("X-Pingback"); xp != "" {
		if u, err := s.base.Parse(xp); err == nil && s.client.InScope(u) {
			f.URL = u.String()
			if s.passive() {
				f.Evidence = append(f.Evidence, Evidence{
					Method: "X-Pingback header", Mode: modePassive, URL: s.base.String(), Value: xp, Confidence: 60,
				})
			}
		}
	}
	for _, u := range s.home.linksTo("pingback") {
		if !s.client.InScope(u) {
			continue
		}
		if f.URL == "" {
			f.URL = u.String()
		}
		if s.passive() {
			f.Evidence = append(f.Evidence, Evidence{
				Method: "Pingback link in the homepage", Mode: modePassive, URL: s.base.String(), Value: u.String(), Confidence: 60,
			})
		}
		break
	}
	if f.URL == "" {
		f.URL = s.url("xmlrpc.php")
	}

	if s.aggressive() {
		if res := s.get(ctx, f.URL); res != nil && bytes.Contains(res.Body, []byte("XML-RPC server accepts POST requests only")) {
			f.Evidence = append(f.Evidence, direct(f.URL, 100))
		}
		s.listMethods(ctx, &f)
	}
	if len(f.Evidence) == 0 {
		return nil
	}
	f.Title = "XML-RPC seems to be enabled"
	for _, e := range f.Evidence {
		if e.Mode == modeAggressive {
			f.Title = "XML-RPC is enabled"
		}
	}
	f.Confidence = combine(f.Evidence)
	sortEvidence(f.Evidence)
	return []Finding{f}
}

// listMethods calls system.listMethods and records which of the methods that
// matter to an assessment are exposed.
func (s *Scanner) listMethods(ctx context.Context, f *Finding) {
	res := s.do(ctx, httpclient.Request{
		Method: http.MethodPost,
		URL:    f.URL,
		Header: http.Header{"Content-Type": {"text/xml"}},
		Body:   []byte(listMethodsCall),
	})
	if res == nil {
		return
	}
	mr, err := parseMethodResponse(res.Body)
	switch {
	case err != nil:
		if len(f.Evidence) > 0 {
			f.Entries = append(f.Entries, fmt.Sprintf("system.listMethods did not return an XML-RPC response (HTTP %d)", res.StatusCode))
		}
	case mr.Fault != nil:
		msg := "unknown fault"
		for _, m := range mr.Fault.Members {
			if m.Name == "faultString" {
				msg = m.Value.str()
			}
		}
		f.Evidence = append(f.Evidence, Evidence{
			Method: "system.listMethods", Mode: modeAggressive, URL: f.URL, Value: "fault: " + msg, Confidence: 100,
		})
		f.Entries = append(f.Entries, "system.listMethods returned a fault: "+msg)
	case len(mr.Values) > 0:
		methods := make([]string, 0, len(mr.Values))
		for _, v := range mr.Values {
			methods = append(methods, v.str())
		}
		pingback := slices.Contains(methods, "pingback.ping")
		multicall := slices.Contains(methods, "system.multicall")
		f.Evidence = append(f.Evidence, Evidence{
			Method: "system.listMethods", Mode: modeAggressive, URL: f.URL,
			Value: fmt.Sprintf("%d methods", len(methods)), Confidence: 100,
		})
		f.Entries = append(f.Entries, fmt.Sprintf("system.listMethods: %d methods exposed", len(methods)))
		if pingback {
			f.Entries = append(f.Entries, "pingback.ping is exposed: the site can be made to request arbitrary URLs (SSRF, DDoS reflection)")
		} else {
			f.Entries = append(f.Entries, "pingback.ping is not exposed")
		}
		if multicall {
			f.Entries = append(f.Entries, "system.multicall is exposed: many calls fit in one request, which speeds up password guessing (not tested)")
		} else {
			f.Entries = append(f.Entries, "system.multicall is not exposed")
		}
		if pingback || multicall {
			f.Severity = SeverityLow
		}
		f.Data = map[string]any{"methods": len(methods), "pingback_ping": pingback, "system_multicall": multicall}
	}
}
