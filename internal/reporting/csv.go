package reporting

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

// WriteCSV writes the findings as CSV, one row per finding.
func (r *Report) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	header := []string{
		"id", "type", "severity", "confidence", "cvss", "cvss_vector",
		"url", "parameter", "cwe", "owasp_top10", "wstg", "tool",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, f := range r.ScanResult.Findings {
		row := []string{
			f.ID,
			f.Type,
			string(f.Severity),
			string(f.Confidence),
			strconv.FormatFloat(f.CVSS, 'f', 1, 64),
			f.CVSSVector,
			f.URL,
			f.Parameter,
			strings.Join(f.CWE, ";"),
			strings.Join(f.Top10, ";"),
			strings.Join(f.WSTG, ";"),
			f.Tool,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
