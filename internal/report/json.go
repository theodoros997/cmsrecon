// Package report renders scan results as a coloured CLI report, JSON,
// HTML or Markdown.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/theodoros997/cmsrecon/internal/scan"
)

// WriteJSON writes the result as indented JSON. The format is documented in
// docs/json-report.md.
func WriteJSON(w io.Writer, r *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// ReadJSON reads a report written by WriteJSON, to render it again.
func ReadJSON(data []byte) (*scan.Result, error) {
	var r scan.Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("not a cmsrecon JSON report: %w", err)
	}
	switch {
	case r.SchemaVersion == 0 || r.Tool.Name != "cmsrecon":
		return nil, errors.New("not a cmsrecon JSON report")
	case r.SchemaVersion > scan.SchemaVersion:
		return nil, fmt.Errorf("the report has schema version %d, newer than this cmsrecon reads (%d): update cmsrecon", r.SchemaVersion, scan.SchemaVersion)
	}
	if r.Summary == nil {
		r.Summary = scan.Summarize(&r)
	}
	return &r, nil
}
