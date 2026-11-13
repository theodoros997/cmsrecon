package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRateLimitsRequests checks --rate: a burst starts at once, then the
// requests are spaced.
func TestRateLimitsRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	o := options(t, srv.URL)
	o.Rate = 100 // 10ms apart after the burst
	c := newClient(t, o)

	start := time.Now()
	var wg sync.WaitGroup
	for range rateBurst + 10 {
		wg.Go(func() { c.Get(context.Background(), srv.URL) })
	}
	wg.Wait()
	d := time.Since(start)
	if d < 80*time.Millisecond {
		t.Errorf("%d requests took %s; 10 of them should wait 10ms each", rateBurst+10, d)
	}
	if d > 2*time.Second {
		t.Errorf("%d requests took %s; the burst should not wait", rateBurst+10, d)
	}

	o.Rate = 0
	c = newClient(t, o)
	start = time.Now()
	for range 30 {
		c.Get(context.Background(), srv.URL)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("without --rate, 30 requests took %s", d)
	}
}

// TestSlowsDownWhenTheTargetStruggles: after a rate limit answer the
// client sends one request at a time, further apart, and speeds up again
// once the answers are good.
func TestSlowsDownWhenTheTargetStruggles(t *testing.T) {
	var limited atomic.Bool
	var inFlight, maxInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		if limited.Load() {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer srv.Close()
	c := newClient(t, options(t, srv.URL))
	ctx := context.Background()

	limited.Store(true)
	c.Get(ctx, srv.URL)
	limited.Store(false)
	if !c.pace.slowedDown() {
		t.Fatal("a rate limit answer should slow the client down")
	}
	if st := c.Stats(); st.Slowdowns == 0 {
		t.Errorf("stats = %+v", st)
	}

	maxInFlight.Store(0)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { c.Get(ctx, srv.URL) })
	}
	wg.Wait()
	if maxInFlight.Load() != 1 {
		t.Errorf("%d requests at once while slowed down, want 1", maxInFlight.Load())
	}

	// maxRetries+1 bad answers raised the level that far; each level
	// needs recoverAfter good answers to go back down.
	for range (maxRetries + 1) * recoverAfter {
		c.Get(ctx, srv.URL)
	}
	if c.pace.slowedDown() {
		t.Error("the client should speed up again after enough good answers")
	}
}

// TestPausesBeforeGivingUp: bad answers in a row pause the scan twice
// before the breaker trips.
func TestPausesBeforeGivingUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := newClient(t, options(t, srv.URL))
	var tripped atomic.Int32
	c.OnFailing(func(string) { tripped.Add(1) })
	for i := range tripAfter {
		if tripped.Load() != 0 {
			t.Fatalf("tripped after %d bad answers, want %d", i, tripAfter)
		}
		c.Get(context.Background(), srv.URL)
	}
	if tripped.Load() != 1 {
		t.Errorf("tripped %d times after %d bad answers", tripped.Load(), tripAfter)
	}
	if st := c.Stats(); st.Pauses != 2 {
		t.Errorf("pauses = %d, want 2 (after %d and %d bad answers)", st.Pauses, coolAfter, 2*coolAfter)
	}
}

func TestCountsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newClient(t, options(t, srv.URL))
	for _, p := range []string{"/", "/a", "/b"} {
		c.Get(context.Background(), srv.URL+p)
	}
	if st := c.Stats(); st.NotFound != 2 || st.Requests != 3 {
		t.Errorf("stats = %+v", st)
	}
}
