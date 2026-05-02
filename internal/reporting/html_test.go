package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/scanner"
)

func TestWriteHTML_BasicStructure(t *testing.T) {
	result := &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{},
		Duration: 10 * time.Second,
		ToolsRun: 1,
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteHTML(&buf)

	if err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	output := buf.String()

	checks := []struct {
		name     string
		contains string
	}{
		{"doctype", "<!DOCTYPE html>"},
		{"title", "<title>SKWS Scan Report</title>"},
		{"target", "https://example.com"},
		{"no vuln message", "No vulnerabilities found."},
		{"css embedded", "<style>"},
		{"script embedded", "<script>"},
		{"footer", "Swiss Knife for Web Security"},
	}

	for _, c := range checks {
		if !strings.Contains(output, c.contains) {
			t.Errorf("HTML output missing %s: expected to contain %q", c.name, c.contains)
		}
	}
}

func TestWriteHTML_WithFindings(t *testing.T) {
	finding := &core.Finding{
		ID:          "sqli-1",
		Type:        "SQL Injection",
		Severity:    core.SeverityCritical,
		URL:         "https://example.com/page?id=1",
		Parameter:   "id",
		Description: "Time-based blind SQL injection",
		Evidence:    "sleep(5) caused 5s delay",
		Tool:        "sqlmap",
		WSTG:        []string{"WSTG-INPV-05"},
		Top10:       []string{"A03:2021"},
		CWE:         []string{"CWE-89"},
	}

	result := &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{finding},
		Duration: 30 * time.Second,
		ToolsRun: 2,
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteHTML(&buf)

	if err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	output := buf.String()

	checks := []struct {
		name     string
		contains string
	}{
		{"finding type", "SQL Injection"},
		{"severity badge", "badge-critical"},
		{"severity text", "critical"},
		{"URL", "https://example.com/page?id=1"},
		{"parameter", "id"},
		{"description", "Time-based blind SQL injection"},
		{"evidence", "sleep(5) caused 5s delay"},
		{"tool", "sqlmap"},
		{"WSTG", "WSTG-INPV-05"},
		{"Top10", "A03:2021"},
		{"CWE", "CWE-89"},
		{"finding ID", "sqli-1"},
	}

	for _, c := range checks {
		if !strings.Contains(output, c.contains) {
			t.Errorf("HTML output missing %s: expected to contain %q", c.name, c.contains)
		}
	}
}

func TestWriteHTML_SeverityBadges(t *testing.T) {
	findings := core.Findings{
		{ID: "1", Type: "Critical Finding", Severity: core.SeverityCritical, URL: "https://example.com"},
		{ID: "2", Type: "High Finding", Severity: core.SeverityHigh, URL: "https://example.com"},
		{ID: "3", Type: "Medium Finding", Severity: core.SeverityMedium, URL: "https://example.com"},
		{ID: "4", Type: "Low Finding", Severity: core.SeverityLow, URL: "https://example.com"},
		{ID: "5", Type: "Info Finding", Severity: core.SeverityInfo, URL: "https://example.com"},
	}

	result := &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: findings,
		Duration: 5 * time.Second,
		ToolsRun: 1,
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteHTML(&buf)

	if err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	output := buf.String()

	badges := []string{"badge-critical", "badge-high", "badge-medium", "badge-low", "badge-info"}
	for _, badge := range badges {
		if !strings.Contains(output, badge) {
			t.Errorf("HTML output missing badge class %q", badge)
		}
	}
}

func TestWriteHTML_SummaryCards(t *testing.T) {
	findings := core.Findings{
		{ID: "1", Type: "A", Severity: core.SeverityCritical, URL: "https://example.com"},
		{ID: "2", Type: "B", Severity: core.SeverityHigh, URL: "https://example.com"},
		{ID: "3", Type: "C", Severity: core.SeverityMedium, URL: "https://example.com"},
	}

	result := &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: findings,
		Duration: 5 * time.Second,
		ToolsRun: 1,
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteHTML(&buf)

	if err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	output := buf.String()

	// Check summary count classes exist
	countClasses := []string{"count-total", "count-critical", "count-high", "count-medium", "count-low", "count-info"}
	for _, cls := range countClasses {
		if !strings.Contains(output, cls) {
			t.Errorf("HTML output missing summary count class %q", cls)
		}
	}
}

func TestWriteHTML_WithErrors(t *testing.T) {
	result := &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{},
		Duration: 5 * time.Second,
		Errors:   []string{"sqlmap: timeout", "nuclei: not found"},
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteHTML(&buf)

	if err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "sqlmap: timeout") {
		t.Error("HTML output should contain error message")
	}
	if !strings.Contains(output, "nuclei: not found") {
		t.Error("HTML output should contain second error message")
	}
}

func TestWriteHTML_CollapsibleDetails(t *testing.T) {
	finding := &core.Finding{
		ID:       "test-1",
		Type:     "XSS",
		Severity: core.SeverityHigh,
		URL:      "https://example.com",
	}

	result := &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{finding},
		Duration: 5 * time.Second,
	}

	report := NewReport(result)
	var buf bytes.Buffer
	err := report.WriteHTML(&buf)

	if err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "toggleDetails") {
		t.Error("HTML output should contain toggleDetails function for collapsible details")
	}
	if !strings.Contains(output, "finding-details") {
		t.Error("HTML output should contain finding-details class")
	}
	if !strings.Contains(output, "onclick") {
		t.Error("HTML output should contain onclick handler for collapsible behavior")
	}
}

func TestSeverityBadgeClass(t *testing.T) {
	tests := []struct {
		severity core.Severity
		expected string
	}{
		{core.SeverityCritical, "badge-critical"},
		{core.SeverityHigh, "badge-high"},
		{core.SeverityMedium, "badge-medium"},
		{core.SeverityLow, "badge-low"},
		{core.SeverityInfo, "badge-info"},
		{core.Severity("unknown"), "badge-info"},
	}

	for _, tt := range tests {
		got := severityBadgeClass(tt.severity)
		if got != tt.expected {
			t.Errorf("severityBadgeClass(%q) = %q, want %q", tt.severity, got, tt.expected)
		}
	}
}
