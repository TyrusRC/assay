package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TyrusRC/assay/internal/reporting"
)

var validFormats = map[string]string{
	"text": "txt", "json": "json", "html": "html", "csv": "csv", "md": "md",
	"sarif": "sarif", "junit": "xml",
}

// resolveFormats parses --format plus the --json/--html back-compat aliases
// into a deduplicated, validated, order-preserving list. Empty input with no
// aliases defaults to "text".
func resolveFormats(format string, jsonAlias, htmlAlias bool) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	add := func(f string) error {
		f = strings.TrimSpace(strings.ToLower(f))
		if f == "" {
			return nil
		}
		if _, ok := validFormats[f]; !ok {
			return fmt.Errorf("unknown report format %q (valid: text,json,html,csv,md,sarif,junit)", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
		return nil
	}
	for _, f := range strings.Split(format, ",") {
		if err := add(f); err != nil {
			return nil, err
		}
	}
	if jsonAlias {
		if err := add("json"); err != nil {
			return nil, err
		}
	}
	if htmlAlias {
		if err := add("html"); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		out = []string{"text"}
	}
	return out, nil
}

// validateOutput enforces that multiple formats require an output directory.
func validateOutput(formats []string, outputDir string) error {
	if len(formats) > 1 && outputDir == "" {
		return fmt.Errorf("multiple formats (%s) require --output-dir", strings.Join(formats, ","))
	}
	return nil
}

// writeReports renders each requested format. With an empty outputDir the
// single format is written to stdout; otherwise one file per format is written
// into outputDir and the paths are reported to stderr.
func writeReports(report *reporting.Report, formats []string, outputDir string) error {
	if outputDir == "" {
		return writeOne(report, formats[0], os.Stdout)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	for _, f := range formats {
		path := filepath.Join(outputDir, "assay-report."+validFormats[f])
		file, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		if err := writeOne(report, f, file); err != nil {
			file.Close()
			return fmt.Errorf("write %s: %w", path, err)
		}
		file.Close()
		fmt.Fprintf(os.Stderr, "[+] wrote %s\n", path)
	}
	return nil
}

// printDelta writes a one-line baseline-diff summary plus the new findings to
// stderr, so CI logs surface what changed since the last scan.
func printDelta(d reporting.Delta) {
	fmt.Fprintf(os.Stderr, "[*] Baseline diff: %d new, %d fixed, %d unchanged\n",
		len(d.New), len(d.Fixed), len(d.Existing))
	for _, f := range d.New {
		fmt.Fprintf(os.Stderr, "    + NEW  [%s] %s %s\n", f.Severity, f.Type, f.URL)
	}
	for _, f := range d.Fixed {
		fmt.Fprintf(os.Stderr, "    - FIXED [%s] %s %s\n", f.Severity, f.Type, f.URL)
	}
}

func writeOne(report *reporting.Report, format string, w *os.File) error {
	switch format {
	case "json":
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
	default:
		return report.WriteText(w)
	}
}
