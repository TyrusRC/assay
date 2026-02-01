package core

import (
	"testing"
	"time"
)

func TestNewFinding(t *testing.T) {
	f := NewFinding("SQL Injection", SeverityCritical)

	if f.ID == "" {
		t.Error("Finding.ID should not be empty")
	}
	if f.Type != "SQL Injection" {
		t.Errorf("Finding.Type = %q, want %q", f.Type, "SQL Injection")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("Finding.Severity = %v, want %v", f.Severity, SeverityCritical)
	}
	if f.Confidence != ConfidenceMedium {
		t.Errorf("Finding.Confidence = %v, want %v (default)", f.Confidence, ConfidenceMedium)
	}
	if f.Timestamp.IsZero() {
		t.Error("Finding.Timestamp should not be zero")
	}
}

func TestFinding_Validate(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		wantErr bool
	}{
		{
			name: "valid finding",
			finding: Finding{
				ID:       "test-1",
				Type:     "SQL Injection",
				Severity: SeverityCritical,
				URL:      "https://example.com/test",
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			finding: Finding{
				Type:     "SQL Injection",
				Severity: SeverityCritical,
				URL:      "https://example.com/test",
			},
			wantErr: true,
		},
		{
			name: "missing type",
			finding: Finding{
				ID:       "test-1",
				Severity: SeverityCritical,
				URL:      "https://example.com/test",
			},
			wantErr: true,
		},
		{
			name: "invalid severity",
			finding: Finding{
				ID:       "test-1",
				Type:     "SQL Injection",
				Severity: Severity("invalid"),
				URL:      "https://example.com/test",
			},
			wantErr: true,
		},
		{
			name: "missing URL",
			finding: Finding{
				ID:       "test-1",
				Type:     "SQL Injection",
				Severity: SeverityCritical,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.finding.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Finding.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFinding_DeduplicationKey(t *testing.T) {
	f1 := Finding{
		Type:      "SQL Injection",
		URL:       "https://example.com/test",
		Parameter: "id",
	}
	f2 := Finding{
		Type:      "SQL Injection",
		URL:       "https://example.com/test",
		Parameter: "id",
	}
	f3 := Finding{
		Type:      "SQL Injection",
		URL:       "https://example.com/other",
		Parameter: "id",
	}

	if f1.DeduplicationKey() != f2.DeduplicationKey() {
		t.Error("Same findings should have same deduplication key")
	}
	if f1.DeduplicationKey() == f3.DeduplicationKey() {
		t.Error("Different findings should have different deduplication keys")
	}
}

func TestFinding_WithOWASPMapping(t *testing.T) {
	f := NewFinding("SQL Injection", SeverityCritical)
	f.WithOWASPMapping([]string{"WSTG-INPV-05"}, []string{"A03:2021"}, []string{"CWE-89"})

	if len(f.WSTG) != 1 || f.WSTG[0] != "WSTG-INPV-05" {
		t.Errorf("Finding.WSTG = %v, want [WSTG-INPV-05]", f.WSTG)
	}
	if len(f.Top10) != 1 || f.Top10[0] != "A03:2021" {
		t.Errorf("Finding.Top10 = %v, want [A03:2021]", f.Top10)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
		t.Errorf("Finding.CWE = %v, want [CWE-89]", f.CWE)
	}
}

func TestFinding_SetEvidence(t *testing.T) {
	f := NewFinding("SQL Injection", SeverityCritical)
	f.SetEvidence("Error message found", "GET /test?id=1' HTTP/1.1", "HTTP/1.1 500 Error")

	if f.Evidence != "Error message found" {
		t.Errorf("Finding.Evidence = %q, want %q", f.Evidence, "Error message found")
	}
	if f.Request != "GET /test?id=1' HTTP/1.1" {
		t.Errorf("Finding.Request not set correctly")
	}
	if f.Response != "HTTP/1.1 500 Error" {
		t.Errorf("Finding.Response not set correctly")
	}
}

func TestFindings_SortBySeverity(t *testing.T) {
	findings := Findings{
		{ID: "1", Severity: SeverityLow},
		{ID: "2", Severity: SeverityCritical},
		{ID: "3", Severity: SeverityMedium},
		{ID: "4", Severity: SeverityHigh},
	}

	findings.SortBySeverity()

	expected := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	for i, f := range findings {
		if f.Severity != expected[i] {
			t.Errorf("findings[%d].Severity = %v, want %v", i, f.Severity, expected[i])
		}
	}
}

func TestFindings_Deduplicate(t *testing.T) {
	findings := Findings{
		{ID: "1", Type: "SQLi", URL: "https://example.com/test", Parameter: "id"},
		{ID: "2", Type: "SQLi", URL: "https://example.com/test", Parameter: "id"}, // duplicate
		{ID: "3", Type: "XSS", URL: "https://example.com/test", Parameter: "id"},
	}

	deduplicated := findings.Deduplicate()

	if len(deduplicated) != 2 {
		t.Errorf("len(deduplicated) = %d, want 2", len(deduplicated))
	}
}

func TestFindings_FilterBySeverity(t *testing.T) {
	findings := Findings{
		{ID: "1", Severity: SeverityLow},
		{ID: "2", Severity: SeverityCritical},
		{ID: "3", Severity: SeverityMedium},
		{ID: "4", Severity: SeverityHigh},
		{ID: "5", Severity: SeverityCritical},
	}

	critical := findings.FilterBySeverity(SeverityCritical)
	if len(critical) != 2 {
		t.Errorf("len(critical) = %d, want 2", len(critical))
	}

	highAndAbove := findings.FilterByMinSeverity(SeverityHigh)
	if len(highAndAbove) != 3 {
		t.Errorf("len(highAndAbove) = %d, want 3", len(highAndAbove))
	}
}

func TestFinding_Age(t *testing.T) {
	f := Finding{
		Timestamp: time.Now().Add(-24 * time.Hour),
	}

	age := f.Age()
	if age < 23*time.Hour || age > 25*time.Hour {
		t.Errorf("Finding.Age() = %v, expected ~24h", age)
	}
}
