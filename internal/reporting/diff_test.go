package reporting

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

func finding(typ, url string, sev core.Severity) *core.Finding {
	f := core.NewFinding(typ, sev)
	f.URL = url
	return f
}

func TestDiffFindings(t *testing.T) {
	base := core.Findings{
		finding("SQL Injection", "https://x/?id=1", core.SeverityCritical),
		finding("XSS", "https://x/?q=1", core.SeverityHigh),
	}
	curr := core.Findings{
		finding("SQL Injection", "https://x/?id=1", core.SeverityCritical), // existing
		finding("CORS Misconfig", "https://x/", core.SeverityMedium),       // new
	}

	d := DiffFindings(base, curr)
	if len(d.New) != 1 || d.New[0].Type != "CORS Misconfig" {
		t.Errorf("New = %v, want [CORS Misconfig]", typesOf(d.New))
	}
	if len(d.Existing) != 1 || d.Existing[0].Type != "SQL Injection" {
		t.Errorf("Existing = %v, want [SQL Injection]", typesOf(d.Existing))
	}
	if len(d.Fixed) != 1 || d.Fixed[0].Type != "XSS" {
		t.Errorf("Fixed = %v, want [XSS]", typesOf(d.Fixed))
	}
}

func TestDiffFindings_EmptyBaseline(t *testing.T) {
	curr := core.Findings{finding("SQLi", "https://x/?id=1", core.SeverityCritical)}
	d := DiffFindings(nil, curr)
	if len(d.New) != 1 || len(d.Existing) != 0 || len(d.Fixed) != 0 {
		t.Errorf("empty baseline: New=%d Existing=%d Fixed=%d", len(d.New), len(d.Existing), len(d.Fixed))
	}
}

func TestLoadBaselineFindings_RoundTrip(t *testing.T) {
	// Write a real JSON report, then load it back as a baseline.
	f := finding("SQL Injection", "https://x/?id=1", core.SeverityCritical)
	f.CWE = []string{"CWE-89"}
	report := NewReport(&scanner.ScanResult{
		Targets:  []string{"https://x"},
		Findings: core.Findings{f},
	})
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadBaselineFindings(path)
	if err != nil {
		t.Fatalf("LoadBaselineFindings: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Type != "SQL Injection" {
		t.Fatalf("loaded = %v, want [SQL Injection]", typesOf(loaded))
	}

	// A re-scan that finds the same issue must classify it as existing, not new.
	d := DiffFindings(loaded, core.Findings{finding("SQL Injection", "https://x/?id=1", core.SeverityCritical)})
	if len(d.New) != 0 || len(d.Existing) != 1 {
		t.Errorf("round-trip diff: New=%d Existing=%d, want 0/1", len(d.New), len(d.Existing))
	}
}

func TestLoadBaselineFindings_Errors(t *testing.T) {
	if _, err := LoadBaselineFindings(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for missing baseline file")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaselineFindings(bad); err == nil {
		t.Error("expected error for malformed baseline JSON")
	}
}

func typesOf(fs core.Findings) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Type
	}
	return out
}
