package report

import (
	"encoding/json"
	"io"
)

// JSON writes findings as a pretty-printed JSON array to w.
func JSON(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
