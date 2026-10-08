package reporting

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

func TestWriteMarkdown(t *testing.T) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/?id=1"
	f.Parameter = "id"
	f.Description = "SQLi in id"
	f.CWE = []string{"CWE-89"}
	r := NewReport(&scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{f},
	})

	var buf bytes.Buffer
	if err := r.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"# assay Scan Report", "## Summary", "SQL Injection", "https://example.com/?id=1", "CWE-89"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestWriteMarkdown_RequestResponse(t *testing.T) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/?id=1"
	f.SetEvidence("sqli error", "GET /?id=1' HTTP/1.1\r\nHost: example.com", "HTTP/1.1 500\r\n\r\npg_query error")
	r := NewReport(&scanner.ScanResult{Findings: core.Findings{f}})

	var buf bytes.Buffer
	if err := r.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"**Request:**", "GET /?id=1'", "**Response:**", "pg_query error"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing req/resp evidence %q", want)
		}
	}
}
