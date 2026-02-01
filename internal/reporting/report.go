package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/scanner"
)

const (
	reportVersion = "1.0.0"
	toolName      = "skws"
)

// Report represents a scan report.
type Report struct {
	Version     string              `json:"version"`
	Tool        string              `json:"tool"`
	GeneratedAt time.Time           `json:"generated_at"`
	ScanResult  *scanner.ScanResult `json:"scan_result"`
	Summary     scanner.ScanSummary `json:"summary"`
}

// NewReport creates a new report from scan results.
func NewReport(result *scanner.ScanResult) *Report {
	return &Report{
		Version:     reportVersion,
		Tool:        toolName,
		GeneratedAt: time.Now(),
		ScanResult:  result,
		Summary:     result.Summary(),
	}
}

// WriteJSON writes the report as JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// WriteText writes the report as human-readable text.
func (r *Report) WriteText(w io.Writer) error {
	result := r.ScanResult

	fmt.Fprintln(w, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(w, "                    SKWS SCAN REPORT                            ")
	fmt.Fprintln(w, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)

	// Scan info
	fmt.Fprintf(w, "Report Version: %s\n", r.Version)
	fmt.Fprintf(w, "Generated At:   %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Scan Duration:  %s\n", result.Duration.Round(time.Second))
	fmt.Fprintln(w)

	// Targets
	fmt.Fprintln(w, "TARGETS:")
	for _, target := range result.Targets {
		fmt.Fprintf(w, "  - %s\n", target)
	}
	fmt.Fprintln(w)

	// Summary
	fmt.Fprintln(w, "SUMMARY:")
	fmt.Fprintf(w, "  Total Findings: %d\n", r.Summary.TotalFindings)
	fmt.Fprintf(w, "  Critical: %d\n", r.Summary.Critical)
	fmt.Fprintf(w, "  High:     %d\n", r.Summary.High)
	fmt.Fprintf(w, "  Medium:   %d\n", r.Summary.Medium)
	fmt.Fprintf(w, "  Low:      %d\n", r.Summary.Low)
	fmt.Fprintf(w, "  Info:     %d\n", r.Summary.Info)
	fmt.Fprintf(w, "  Tools Run: %d | Skipped: %d\n", result.ToolsRun, result.ToolsSkipped)
	fmt.Fprintln(w)

	// Findings
	if len(result.Findings) > 0 {
		fmt.Fprintln(w, "FINDINGS:")
		fmt.Fprintln(w, "---------")
		for i, finding := range result.Findings {
			fmt.Fprintf(w, "\n[%d] %s (%s)\n", i+1, finding.Type, finding.Severity)
			fmt.Fprintf(w, "    ID:  %s\n", finding.ID)
			fmt.Fprintf(w, "    URL: %s\n", finding.URL)
			if finding.Parameter != "" {
				fmt.Fprintf(w, "    Parameter: %s\n", finding.Parameter)
			}
			if finding.Description != "" {
				fmt.Fprintf(w, "    Description: %s\n", finding.Description)
			}
			if finding.Tool != "" {
				fmt.Fprintf(w, "    Tool: %s\n", finding.Tool)
			}
			if len(finding.WSTG) > 0 {
				fmt.Fprintf(w, "    WSTG: %v\n", finding.WSTG)
			}
			if len(finding.Top10) > 0 {
				fmt.Fprintf(w, "    OWASP Top 10: %v\n", finding.Top10)
			}
			if len(finding.CWE) > 0 {
				fmt.Fprintf(w, "    CWE: %v\n", finding.CWE)
			}
		}
	} else {
		fmt.Fprintln(w, "No vulnerabilities found.")
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ERRORS:")
		for _, err := range result.Errors {
			fmt.Fprintf(w, "  - %s\n", err)
		}
	}

	fmt.Fprintln(w)
	return nil
}

// SARIF output structures (Static Analysis Results Interchange Format)

// SARIFReport represents a SARIF 2.1.0 report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single SARIF run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents the scanning tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver information.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule represents a vulnerability rule.
type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription SARIFMessage    `json:"shortDescription"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       SARIFProperties `json:"properties,omitempty"`
}

// SARIFMessage represents a SARIF message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFProperties represents SARIF properties.
type SARIFProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Security struct {
		Severity string `json:"severity,omitempty"`
	} `json:"security,omitempty"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFLocation represents a finding location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents a physical location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation represents an artifact location (URL).
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF writes the report in SARIF format.
func (r *Report) WriteSARIF(w io.Writer) error {
	sarif := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           toolName,
						Version:        reportVersion,
						InformationURI: "https://github.com/swiss-knife-for-web-security/skws",
					},
				},
				Results: make([]SARIFResult, 0, len(r.ScanResult.Findings)),
			},
		},
	}

	// Add findings as results
	for _, finding := range r.ScanResult.Findings {
		result := SARIFResult{
			RuleID: finding.ID,
			Level:  severityToSARIFLevel(finding.Severity),
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s: %s", finding.Type, finding.Description),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: finding.URL,
						},
					},
				},
			},
		}
		sarif.Runs[0].Results = append(sarif.Runs[0].Results, result)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

// severityToSARIFLevel converts severity to SARIF level.
func severityToSARIFLevel(severity core.Severity) string {
	switch severity {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
