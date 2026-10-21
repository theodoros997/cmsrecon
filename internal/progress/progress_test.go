package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for the ticker goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestTerminal(t *testing.T) {
	var buf syncBuffer
	term := newTerminal(&buf, false, func() string { return "7 requests" }, 5*time.Millisecond)
	term.Start("Plugins")
	term.Start("Users")
	term.Update("Plugins", "brute force 10/400")
	term.Update("Not running", "ignored")
	time.Sleep(30 * time.Millisecond)
	term.Done("Users", "2 found")
	term.Fail("Plugins", "interrupted")
	term.Close()

	out := buf.String()
	for _, want := range []string{"7 requests | Plugins (brute force 10/400), Users", "[+] Users: 2 found (", "[!] Plugins: interrupted ("} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%q", want, out)
		}
	}
	if strings.Contains(out, "Not running") {
		t.Error("an update for a step that is not running was drawn")
	}
	if !strings.HasSuffix(out, "\r\x1b[K") && !strings.HasSuffix(out, "\n") {
		t.Errorf("Close leaves a status line behind: %q", out[max(0, len(out)-40):])
	}
	for _, frame := range strings.Split(out, "\r\x1b[K") {
		for _, line := range strings.Split(frame, "\n") {
			if len([]rune(line)) > Width && !strings.HasPrefix(line, "[+]") && !strings.HasPrefix(line, "[!]") {
				t.Errorf("status line longer than %d columns: %q", Width, line)
			}
		}
	}
}

func TestDurationsOff(t *testing.T) {
	var buf syncBuffer
	term := NewTerminal(&buf, false, nil)
	term.ShowDurations(false)
	term.Start("retire.js")
	term.Done("retire.js", "100 libraries (1s)")
	term.Close()
	if !strings.Contains(buf.String(), "[+] retire.js: 100 libraries (1s)\n") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestLineAndDuration(t *testing.T) {
	if got := Line(strings.Repeat("x", 100)); len(got) != Width || !strings.HasSuffix(got, "...") {
		t.Errorf("Line = %q", got)
	}
	for d, want := range map[time.Duration]string{850 * time.Millisecond: "850ms", 4200 * time.Millisecond: "4.2s", 65 * time.Second: "1m05s"} {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%s) = %q, want %q", d, got, want)
		}
	}
}
