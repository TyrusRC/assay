package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/reporting"
	"github.com/TyrusRC/assay/internal/scanner"
)

// TestWriteReports_FilesPerFormat verifies that writing multiple formats to an
// output directory produces one non-empty file per format.
func TestWriteReports_FilesPerFormat(t *testing.T) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/?id=1"
	f.CWE = []string{"CWE-89"}
	report := reporting.NewReport(&scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{f},
	})

	dir := t.TempDir()
	if err := writeReports(report, []string{"html", "csv", "md"}, dir); err != nil {
		t.Fatalf("writeReports error: %v", err)
	}

	for _, name := range []string{"assay-report.html", "assay-report.csv", "assay-report.md"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}
