package reporting

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

func TestWriteHTML_RichReport(t *testing.T) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/?id=1"
	f.Parameter = "id"
	f.Description = "SQLi in id"
	f.Evidence = "<script>alert(1)</script>" // must be escaped
	f.CWE = []string{"CWE-89"}
	f.Top10 = []string{"A03:2021"}
	r := NewReport(&scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{f},
	})

	var buf bytes.Buffer
	if err := r.WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"<!DOCTYPE html>", "assay", "SQL Injection", "Critical", "CWE-89", "9.8"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("evidence was not HTML-escaped")
	}
}

func TestWriteHTML_NoFindings(t *testing.T) {
	r := NewReport(&scanner.ScanResult{Targets: []string{"https://example.com"}})
	var buf bytes.Buffer
	if err := r.WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	if !strings.Contains(buf.String(), "<!DOCTYPE html>") {
		t.Error("expected valid HTML even with no findings")
	}
}
