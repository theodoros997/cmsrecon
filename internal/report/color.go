package report

import (
	"io"
	"os"
)

// ColorEnabled reports whether output written to w can be coloured: w is a
// terminal, NO_COLOR is not set, TERM is not "dumb" and, on Windows, the
// console accepts ANSI escape sequences.
func ColorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return enableVT(f)
}
