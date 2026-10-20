// Package fsutil has file helpers shared by the data packages.
package fsutil

import (
	"os"
	"path/filepath"
)

// WriteAtomic writes a file through a temporary file in the same directory
// and renames it into place, so readers see the old file or the new one,
// never a partial one. The directory is created if needed.
func WriteAtomic(path string, write func(*os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteFileAtomic replaces path with data atomically.
func WriteFileAtomic(path string, data []byte) error {
	return WriteAtomic(path, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}
