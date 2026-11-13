package httpclient

import (
	"context"
	"sync"
	"time"
)

// Pacing is how the client reacts when the target struggles. Tests shorten
// the durations.
var Pacing = struct {
	// SlowStep is the wait added between requests at the first sign of
	// trouble; it doubles with each further sign, up to eight times.
	SlowStep time.Duration
	// CoolDown is the pause after coolAfter bad answers in a row; the next
	// pause is twice as long.
	CoolDown time.Duration
}{500 * time.Millisecond, 15 * time.Second}

const (
	maxSlowLevel = 4  // the wait between requests stops growing here (8 x SlowStep)
	recoverAfter = 20 // good answers before the client speeds up one level
	coolAfter    = 4  // bad answers in a row before a pause
	rateBurst    = 10 // requests --rate lets start at once after a quiet moment
)

// pacer spaces requests out. Its base interval comes from --throttle or
// --rate. While the target shows signs of trouble (rate limits, overloads,
// timeouts, dropped connections) it sends one request at a time, further
// and further apart, and it speeds up again as good answers come in.
type pacer struct {
	mu      sync.Mutex
	base    time.Duration // between the starts of two requests; 0 for none
	burst   int           // requests that may start at once after a quiet moment
	next    time.Time     // the earliest start of the next request
	level   int           // slowdown level; 0 while the target is fine
	good    int           // good answers since the level last changed
	pauseTo time.Time     // a cool-down: no request starts before this
	slowed  int           // how many times the client slowed down
	pauses  int           // how many cool-downs it took

	lane chan struct{} // one request at a time while level > 0
}

func newPacer(throttle time.Duration, rate float64) *pacer {
	p := &pacer{lane: make(chan struct{}, 1)}
	switch {
	case throttle > 0:
		p.base = throttle
	case rate > 0:
		p.base = time.Duration(float64(time.Second) / rate)
		p.burst = rateBurst
	}
	return p
}

// interval is the current gap between request starts.
func (p *pacer) interval() time.Duration {
	if p.level == 0 {
		return p.base
	}
	return max(p.base, Pacing.SlowStep<<(p.level-1))
}

// enter waits for the request's turn. While the client is slowed down it
// also takes the single lane; the caller calls the returned function when
// the request is done.
func (p *pacer) enter(ctx context.Context) (leave func(), err error) {
	leave = func() {}
	p.mu.Lock()
	single := p.level > 0
	p.mu.Unlock()
	if single {
		select {
		case p.lane <- struct{}{}:
			leave = func() { <-p.lane }
		case <-ctx.Done():
			return leave, ctx.Err()
		}
	}

	p.mu.Lock()
	now := time.Now()
	slot := p.next
	gap := p.interval()
	// After a quiet moment, a burst may start at once.
	if earliest := now.Add(-time.Duration(p.burst) * gap); p.level == 0 && slot.Before(earliest) {
		slot = earliest
	}
	if p.level > 0 && slot.Before(now) {
		slot = now
	}
	if slot.Before(p.pauseTo) {
		slot = p.pauseTo
	}
	p.next = slot.Add(gap)
	p.mu.Unlock()

	if d := time.Until(slot); d > 0 {
		if err := sleep(ctx, d); err != nil {
			leave()
			return func() {}, err
		}
	}
	return leave, nil
}

// report tells the pacer how an attempt ended.
func (p *pacer) report(bad bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if bad {
		if p.level < maxSlowLevel {
			p.level++
		}
		p.good = 0
		p.slowed++
		return
	}
	if p.level == 0 {
		return
	}
	if p.good++; p.good >= recoverAfter {
		p.level--
		p.good = 0
	}
}

// pause holds every request back for a cool-down, each one twice as long
// as the one before.
func (p *pacer) pause() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := Pacing.CoolDown << p.pauses
	p.pauses++
	if until := time.Now().Add(d); until.After(p.pauseTo) {
		p.pauseTo = until
	}
	return d
}

// slowedDown reports whether the client is sending one request at a time.
func (p *pacer) slowedDown() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.level > 0
}

func (p *pacer) counts() (slowed, pauses int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.slowed, p.pauses
}
