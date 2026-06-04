package reporting

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

func TestWriteCSV(t *testing.T) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/?id=1"
	f.Parameter = "id"
	f.CWE = []string{"CWE-89"}
	f.Top10 = []string{"A03:2021"}
	r := NewReport(&scanner.ScanResult{Findings: core.Findings{f}})

	var buf bytes.Buffer
	if err := r.WriteCSV(&buf); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(records) != 2 { // header + 1 finding
		t.Fatalf("got %d rows, want 2", len(records))
	}
	if records[0][1] != "type" {
		t.Errorf("header[1] = %q, want \"type\"", records[0][1])
	}
	if records[1][1] != "SQL Injection" {
		t.Errorf("row type = %q, want \"SQL Injection\"", records[1][1])
	}
}
