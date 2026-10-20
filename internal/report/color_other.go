//go:build !windows

package report

import "os"

func enableVT(*os.File) bool { return true }
