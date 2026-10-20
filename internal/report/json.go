// Package report renders scan results as a coloured CLI report or as JSON.
package report

import (
	"encoding/json"
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
