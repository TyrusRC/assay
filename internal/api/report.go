package api

import (
	"io"

	"github.com/TyrusRC/assay/internal/reporting"
)

// formatJSON is the default report format.
const formatJSON = "json"

// reportContentType returns the MIME type for a report format and whether the
// format is recognized.
func reportContentType(format string) (string, bool) {
	switch format {
	case formatJSON, "sarif", "gitlab":
		return "application/json", true
	case "html":
		return "text/html; charset=utf-8", true
	case "csv":
		return "text/csv", true
	case "md":
		return "text/markdown; charset=utf-8", true
	case "junit":
		return "application/xml", true
	default:
		return "", false
	}
}

// writeReport renders report to w in the requested format. The format must
// have been validated via reportContentType first.
func writeReport(w io.Writer, report *reporting.Report, format string) error {
	switch format {
	case formatJSON:
		return report.WriteJSON(w)
	case "html":
		return report.WriteHTML(w)
	case "csv":
		return report.WriteCSV(w)
	case "md":
		return report.WriteMarkdown(w)
	case "sarif":
		return report.WriteSARIF(w)
	case "junit":
		return report.WriteJUnit(w)
	case "gitlab":
		return report.WriteGitLab(w)
	default:
		return report.WriteJSON(w)
	}
}
