package csvinj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// formulaPayload represents a CSV/Formula injection payload.
type formulaPayload struct {
	Value       string
	Description string
}

// payloads contains the formula injection test payloads.
var defaultPayloads = []formulaPayload{
	{Value: "=CMD()", Description: "Excel CMD formula"},
	{Value: `+CMD("calc")`, Description: "Plus-prefix CMD formula"},
	{Value: "-1+1", Description: "Minus-prefix arithmetic formula"},
	{Value: "@SUM(1+1)", Description: "At-prefix SUM formula"},
	{Value: `=HYPERLINK("http://evil.com")`, Description: "Excel HYPERLINK formula"},
	{Value: "=1+1", Description: "Basic equals formula"},
	{Value: `=IMPORTXML("http://evil.com","//a")`, Description: "Google Sheets IMPORTXML formula"},
	{Value: "-2+3+cmd|' /C calc'!A0", Description: "Complex minus-prefix formula"},
}

// formulaPrefixes are the characters that indicate a formula in spreadsheet applications.
var formulaPrefixes = []string{"=", "+", "-", "@"}

// Detector performs CSV/Formula Injection vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new CSV/Formula Injection Detector.
func New(client *http.Client) *Detector {
	return &Detector{
		client: client,
	}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "csvinj"
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads int
	Timeout     time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads: 20,
		Timeout:     10 * time.Second,
	}
}

// DetectionResult contains CSV injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a parameter for CSV/Formula Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	testPayloads := defaultPayloads
	if opts.MaxPayloads > 0 && len(testPayloads) > opts.MaxPayloads {
		testPayloads = testPayloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "baseline_test_value", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	for _, payload := range testPayloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		resp, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
		if err != nil {
			continue
		}

		// CSV/Formula injection is only dangerous when the reflected
		// value is rendered in a spreadsheet application — i.e. when
		// the response is (or is later exported to) CSV/TSV/Excel.
		// Reflection into text/html is harmless from a formula-
		// injection standpoint and produces only noise.
		if !isSpreadsheetResponse(resp, target) {
			continue
		}

		// Check if the formula payload is reflected unescaped in the response
		if d.isReflectedUnescaped(resp.Body, baselineResp.Body, payload.Value) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true

			// Continue testing to find all vulnerable payloads
		}
	}

	return result, nil
}

// isSpreadsheetResponse reports whether the response body is likely to be
// consumed by a spreadsheet program — either by Content-Type, a
// Content-Disposition attachment with a CSV/XLS extension, or a target
// URL that clearly exports tabular data. Only such responses are at real
// risk of formula-injection attacks; HTML reflection is not.
func isSpreadsheetResponse(resp *http.Response, targetURL string) bool {
	if resp == nil {
		return false
	}

	ct := strings.ToLower(resp.ContentType)
	csvContentTypes := []string{
		"text/csv", "application/csv", "text/tab-separated-values",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/x-csv", "text/x-csv",
	}
	for _, want := range csvContentTypes {
		if strings.Contains(ct, want) {
			return true
		}
	}

	// Content-Disposition: attachment; filename="foo.csv"
	disp := strings.ToLower(resp.Headers["Content-Disposition"])
	if disp == "" {
		disp = strings.ToLower(resp.Headers["content-disposition"])
	}
	if strings.Contains(disp, "attachment") {
		for _, ext := range []string{".csv", ".xls", ".xlsx", ".tsv"} {
			if strings.Contains(disp, ext) {
				return true
			}
		}
	}

	// Path strongly suggests spreadsheet export (defence-in-depth).
	lowURL := strings.ToLower(targetURL)
	for _, hint := range []string{".csv", ".xlsx", ".xls", ".tsv", "/export", "/download", "export=csv", "format=csv", "format=xlsx"} {
		if strings.Contains(lowURL, hint) {
			return true
		}
	}

	return false
}

// isReflectedUnescaped checks if a formula payload is reflected in the response
// without proper sanitization and was not present in the baseline.
func (d *Detector) isReflectedUnescaped(body, baseline, payload string) bool {
	// The payload must be present in the body
	if !strings.Contains(body, payload) {
		return false
	}

	// And not present in the baseline (to avoid false positives)
	if strings.Contains(baseline, payload) {
		return false
	}

	// Verify the payload starts with a formula character
	for _, prefix := range formulaPrefixes {
		if strings.HasPrefix(payload, prefix) {
			return true
		}
	}

	return false
}

// createFinding creates a Finding from a successful CSV injection test.
func (d *Detector) createFinding(target, param string, payload formulaPayload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("CSV/Formula Injection", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("CSV/Formula Injection vulnerability in '%s' parameter: %s",
		param, payload.Description)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}

	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s\nReflected in response (status %d)\nResponse snippet: %s",
		payload.Value, payload.Description, resp.StatusCode, body)
	finding.Tool = "csvinj-detector"
	finding.Remediation = "Sanitize user input by prefixing formula characters (=, +, -, @) with a single quote or tab character. " +
		"Escape all user-controlled data before including it in CSV exports. " +
		"Consider using a safe CSV library that handles escaping automatically."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-15"},
		[]string{"A03:2021"},
		[]string{"CWE-1236"},
	)

	return finding
}
