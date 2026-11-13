package httpclient

import (
	"os"
	"testing"
	"time"
)

// TestMain shortens the waits of the adaptive pacing: a real slowdown
// takes seconds.
func TestMain(m *testing.M) {
	Pacing.SlowStep = time.Millisecond
	Pacing.CoolDown = 5 * time.Millisecond
	os.Exit(m.Run())
}
