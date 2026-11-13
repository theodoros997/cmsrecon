package scan

import (
	"os"
	"testing"
	"time"

	"github.com/theodoros997/cmsrecon/internal/httpclient"
)

// TestMain shortens the waits of the client's adaptive pacing: a real
// slowdown takes seconds.
func TestMain(m *testing.M) {
	httpclient.Pacing.SlowStep = time.Millisecond
	httpclient.Pacing.CoolDown = 5 * time.Millisecond
	os.Exit(m.Run())
}
