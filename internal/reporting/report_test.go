package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/scanner"
)

func TestNewReport(t *testing.T) {
	result := &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{},
	}

	report := NewReport(result)

	if report == nil {
		t.Fatal("NewReport() returned nil")
	}
	if report.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestReport_ToJSON(t *testing.T) {
	result := &scanner.ScanResult{
		Targets: []string{"https://example.com"},
		Findings: core.Findings{
			{
				ID:       "test-1",
				Type:     "SQL Injection",
				Severity: core.SeverityHigh,
				URL:      "https://example.com/page?id=1",
			},
		},
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  5 * time.Second,
		ToolsRun:  1,
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteJSON(&buf)

	if err != nil {
		t.Errorf("WriteJSON() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SQL Injection") {
		t.Error("JSON output should contain finding type")
	}
	if !strings.Contains(output, "https://example.com") {
		t.Error("JSON output should contain target URL")
	}
}

func TestReport_ToSARIF(t *testing.T) {
	result := &scanner.ScanResult{
		Targets: []string{"https://example.com"},
		Findings: core.Findings{
			{
				ID:       "test-1",
				Type:     "SQL Injection",
				Severity: core.SeverityHigh,
				URL:      "https://example.com/page?id=1",
				CWE:      []string{"CWE-89"},
			},
		},
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteSARIF(&buf)

	if err != nil {
		t.Errorf("WriteSARIF() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "sarif") {
		t.Error("SARIF output should contain sarif identifier")
	}
}

func TestReport_ToText(t *testing.T) {
	result := &scanner.ScanResult{
		Targets: []string{"https://example.com"},
		Findings: core.Findings{
			{
				ID:       "test-1",
				Type:     "SQL Injection",
				Severity: core.SeverityHigh,
				URL:      "https://example.com/page?id=1",
			},
		},
		ToolsRun:     1,
		ToolsSkipped: 0,
		Duration:     5 * time.Second,
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteText(&buf)

	if err != nil {
		t.Errorf("WriteText() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SQL Injection") {
		t.Error("Text output should contain finding type")
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity core.Severity
		want     string
	}{
		{core.SeverityCritical, "error"},
		{core.SeverityHigh, "error"},
		{core.SeverityMedium, "warning"},
		{core.SeverityLow, "note"},
		{core.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := severityToSARIFLevel(tt.severity)
			if got != tt.want {
				t.Errorf("severityToSARIFLevel(%v) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}
