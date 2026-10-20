package reporting

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

// sanitizeCSVCell prefixes values that spreadsheet applications interpret as
// formulas (=, +, -, @, TAB, CR) with a single-quote to prevent CSV injection.
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

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
			sanitizeCSVCell(f.ID),
			sanitizeCSVCell(f.Type),
			sanitizeCSVCell(string(f.Severity)),
			sanitizeCSVCell(string(f.Confidence)),
			strconv.FormatFloat(f.CVSS, 'f', 1, 64),
			sanitizeCSVCell(f.CVSSVector),
			sanitizeCSVCell(f.URL),
			sanitizeCSVCell(f.Parameter),
			sanitizeCSVCell(strings.Join(f.CWE, ";")),
			sanitizeCSVCell(strings.Join(f.Top10, ";")),
			sanitizeCSVCell(strings.Join(f.WSTG, ";")),
			sanitizeCSVCell(f.Tool),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
