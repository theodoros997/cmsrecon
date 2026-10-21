// Package progress shows what a long-running command is doing: each step
// starts, says what it is busy with, and ends with a one-line result.
// In a terminal the running steps share a status line with a spinner,
// the elapsed time and a request count, and each finished step leaves a
// line above it, so the screen reads as a log of what was done.
package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Reporter receives the progress of a command. Calls may come from
// several goroutines.
type Reporter interface {
	// Start says a step began.
	Start(step string)
	// Update says what a running step is busy with, e.g. "readme files 12/30".
	Update(step, detail string)
	// Done says a step finished, with a one-line result.
	Done(step, result string)
	// Fail says a step finished without a result, with why.
	Fail(step, reason string)
}

// Nop reports nothing.
type Nop struct{}

func (Nop) Start(string)          {}
func (Nop) Update(string, string) {}
func (Nop) Done(string, string)   {}
func (Nop) Fail(string, string)   {}

// Width is the longest status line drawn: a line that wraps cannot be
// redrawn in place, and 80 columns is the narrowest common terminal.
const Width = 79

var spinner = []string{"|", "/", "-", "\\"}

// Terminal draws progress on a terminal that understands ANSI escape codes.
type Terminal struct {
	w         io.Writer
	color     bool
	counter   func() string // extra figures for the status line, e.g. "142 requests"
	durations bool          // add how long each step took to its line
	start     time.Time
	interval  time.Duration

	mu     sync.Mutex
	active []*step
	frame  int
	drawn  bool
	stop   chan struct{}
	wg     sync.WaitGroup
}

type step struct {
	name, detail string
	started      time.Time
}

// NewTerminal starts drawing on w. counter, if not nil, adds figures to
// the status line. Call Close when the command is done.
func NewTerminal(w io.Writer, color bool, counter func() string) *Terminal {
	return newTerminal(w, color, counter, 120*time.Millisecond)
}

func newTerminal(w io.Writer, color bool, counter func() string, interval time.Duration) *Terminal {
	t := &Terminal{w: w, color: color, counter: counter, durations: true, start: time.Now(), interval: interval, stop: make(chan struct{})}
	t.wg.Go(t.tick)
	return t
}

// ShowDurations turns on or off the time each step took on its line; it
// is on by default.
func (t *Terminal) ShowDurations(on bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.durations = on
}

func (t *Terminal) tick() {
	tk := time.NewTicker(t.interval)
	defer tk.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tk.C:
			t.mu.Lock()
			t.frame++
			t.redraw()
			t.mu.Unlock()
		}
	}
}

// Close stops the spinner and clears the status line.
func (t *Terminal) Close() {
	close(t.stop)
	t.wg.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clear()
}

func (t *Terminal) Start(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.find(name) == nil {
		t.active = append(t.active, &step{name: name, started: time.Now()})
	}
	t.redraw()
}

// Update changes what a running step shows; a step that is not running
// is ignored.
func (t *Terminal) Update(name, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.find(name); s != nil {
		s.detail = detail
	}
}

func (t *Terminal) Done(name, result string) { t.finish(name, "[+]", "\x1b[32m", result) }
func (t *Terminal) Fail(name, reason string) { t.finish(name, "[!]", "\x1b[31m", reason) }

func (t *Terminal) finish(name, mark, color, text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	started := t.start
	for i, s := range t.active {
		if s.name == name {
			started = s.started
			t.active = append(t.active[:i], t.active[i+1:]...)
			break
		}
	}
	t.clear()
	if t.color {
		mark = color + mark + "\x1b[0m"
	}
	line := name
	if text != "" {
		line += ": " + text
	}
	if t.durations {
		line += " (" + Duration(time.Since(started)) + ")"
	}
	fmt.Fprintf(t.w, "%s %s\n", mark, line)
	t.redraw()
}

func (t *Terminal) find(name string) *step {
	for _, s := range t.active {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (t *Terminal) clear() {
	if t.drawn {
		fmt.Fprint(t.w, "\r\x1b[K")
		t.drawn = false
	}
}

// redraw draws the status line: the spinner, the elapsed time and the
// counter, then the running steps, the first with what it is doing.
func (t *Terminal) redraw() {
	if len(t.active) == 0 {
		t.clear()
		return
	}
	head := fmt.Sprintf("[%s] %s", spinner[t.frame%len(spinner)], Duration(time.Since(t.start)))
	if t.counter != nil {
		if c := t.counter(); c != "" {
			head += ", " + c
		}
	}
	var parts []string
	for _, s := range t.active {
		p := s.name
		if s.detail != "" {
			p += " (" + s.detail + ")"
		}
		parts = append(parts, p)
	}
	fmt.Fprint(t.w, "\r\x1b[K"+Line(head+" | "+strings.Join(parts, ", ")))
	t.drawn = true
}

// Line shortens s to Width columns.
func Line(s string) string {
	r := []rune(s)
	if len(r) <= Width {
		return s
	}
	return string(r[:Width-3]) + "..."
}

// Duration formats an elapsed time for people: 850ms, 4.2s, 1m05s.
func Duration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}
