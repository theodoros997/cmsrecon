package scan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/cli"
)

// TestPlanEstimate keeps the --dry-run estimate close to what a scan of a
// site with nothing to find really sends.
func TestPlanEstimate(t *testing.T) {
	for _, spec := range []string{"vp,vt", "vp,vt,cb,dbe,bf,u", "u1-30,m1-20", "tt,cb", "none", cli.AggressiveEnumeration} {
		for _, mode := range []cli.DetectionMode{cli.ModeMixed, cli.ModePassive} {
			for _, thorough := range []bool{false, true} {
				f := newFakeWP(t).addBaseSite()
				o := options(f.URL(), mode)
				e, err := cli.ParseEnumeration(spec)
				if err != nil {
					t.Fatal(err)
				}
				o.Enumerate, o.Thorough = e, thorough
				plan := PlanScan(o)
				got := int(runScan(t, o).Stats.Requests)
				if d := plan.Requests - got; d < -got/10-3 || d > got/10+3 {
					t.Errorf("-e %s, %s, --aggressive %v: estimate %d, the scan sent %d", spec, mode, thorough, plan.Requests, got)
				}
			}
		}
	}

	// Brute force adds one request per slug.
	f := newFakeWP(t).addBaseSite()
	o := options(f.URL(), cli.ModeMixed)
	o.Enumerate = cli.Enumeration{Plugins: cli.ItemsPopular}
	o.PluginsDetection = cli.ModeMixed
	plan := PlanScan(o)
	if plan.PluginsBruteForce < 500 || plan.ThemesBruteForce != 0 {
		t.Errorf("brute force of the popular plugins = %d, themes %d", plan.PluginsBruteForce, plan.ThemesBruteForce)
	}
	if got := int(runScan(t, o).Stats.Requests); plan.Requests < got*9/10 || plan.Requests > got*11/10 {
		t.Errorf("brute force: estimate %d, the scan sent %d", plan.Requests, got)
	}
	if len(f.requested()) == 0 || len(plan.Notices) == 0 {
		t.Errorf("the plan should note the missing data: %v", plan.Notices)
	}
}

func TestLoginURI(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	delete(f.routes, "/wp-login.php")
	f.routes["/my-login/"] = respond(200, "text/html", `<form name="loginform" id="loginform" action="/my-login/" method="post">`)
	f.routes["/my-login/?action=register"] = respond(200, "text/html", `<form name="registerform" id="registerform" action="/my-login/?action=register" method="post">`)
	o := options(f.URL(), cli.ModeMixed)
	o.LoginURI = "/my-login/"
	r := runScan(t, o)

	reqs := f.requested()
	if !slices.Contains(reqs, "GET /my-login/") || slices.Contains(reqs, "GET /wp-login.php") {
		t.Errorf("--login-uri should replace wp-login.php: %v", reqs)
	}
	if findingByID(r, idRegistration) == nil {
		t.Errorf("registration on the moved login page was not found: %v", findingIDs(r))
	}

	// An out-of-scope login URI is ignored.
	f2 := newFakeWP(t).addBaseSite()
	o = options(f2.URL(), cli.ModeMixed)
	o.LoginURI = "https://other.example/login"
	runScan(t, o)
	if !slices.Contains(f2.requested(), "GET /wp-login.php") {
		t.Error("an out-of-scope --login-uri must fall back to wp-login.php")
	}
}

func TestConnectErrors(t *testing.T) {
	o := &cli.ScanOptions{}
	for _, tc := range []struct {
		err       error
		why, hint string
	}{
		{&net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}, "does not resolve", "--resolve"},
		{&net.OpError{Op: "dial", Err: errors.New("connectex: No connection could be made because the target machine actively refused it.")}, "refused", "port"},
		{context.DeadlineExceeded, "timed out", "--proxy"},
		{errors.New("something else"), "something else", ""},
	} {
		why, hint := connectError(tc.err, o)
		if !strings.Contains(why, tc.why) || !strings.Contains(hint, tc.hint) {
			t.Errorf("%v: %q / %q", tc.err, why, hint)
		}
	}

	// A real refused connection and a real certificate error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	r := runScan(t, options("http://"+addr+"/", cli.ModeMixed))
	if r.Stop == nil || !strings.Contains(r.Stop.Message, "the connection was refused") || strings.Contains(r.Stop.Message, `Get "`) {
		t.Errorf("refused = %+v", r.Stop)
	}

	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	r = runScan(t, options(srv.URL+"/", cli.ModeMixed))
	if r.Stop == nil || !strings.Contains(r.Stop.Message, "TLS certificate") || !strings.Contains(r.Stop.Hint, "--insecure") {
		t.Errorf("untrusted certificate = %+v", r.Stop)
	}
}

func TestScanOptionsInResult(t *testing.T) {
	f := newFakeWP(t).addBaseSite()
	o := options(f.URL(), cli.ModeMixed)
	o.EnumerateSpec = "+tt"
	o.Enumerate = cli.Enumeration{Timthumbs: true}
	o.HTTPAuth = &cli.Credentials{Username: "u", Password: "secret"}
	r := runScan(t, o)
	if r.Options == nil || r.Options.Enumerate != "+tt" || !r.Options.HTTPAuth || r.Options.Threads != 5 {
		t.Errorf("scan_options = %+v", r.Options)
	}
	if r.Summary == nil {
		t.Error("the result needs its summary")
	}
}
