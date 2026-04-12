// Package xpath provides detection for XPath Injection vulnerabilities.
package xpath

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/xpath"
)

// Detector performs XPath Injection detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new XPath Injection Detector.
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

// DetectOptions configures XPath injection detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
	}
}

// DetectionResult contains XPath injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
	DetectionType  string
}

// Detect checks for XPath Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads
	payloads := xpath.GetPayloads()
	if opts.IncludeWAFBypass {
		payloads = append(payloads, xpath.GetWAFBypassPayloads()...)
	}

	// Deduplicate and limit
	payloads = d.deduplicatePayloads(payloads)
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Establish baseline
	baselineResp, err := d.client.SendPayload(ctx, target, param, "xpath_baseline", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test each payload
	for _, payload := range payloads {
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

		// Check for error-based detection
		if d.hasXPathError(resp.Body) && !d.hasXPathError(baselineResp.Body) {
			result.DetectionType = "error-based"
			finding := d.createFinding(target, param, payload, resp, "error-based")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}

		// Check for boolean-based detection (significant content change)
		if d.hasSignificantChange(resp, baselineResp) {
			result.DetectionType = "boolean-based"
			finding := d.createFinding(target, param, payload, resp, "boolean-based")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// hasXPathError checks if the response contains XPath error patterns.
func (d *Detector) hasXPathError(body string) bool {
	lowerBody := strings.ToLower(body)
	for _, pattern := range xpath.GetErrorPatterns() {
		if strings.Contains(lowerBody, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// hasSignificantChange checks for significant response differences.
func (d *Detector) hasSignificantChange(resp, baseline *http.Response) bool {
	baseLen := len(baseline.Body)
	respLen := len(resp.Body)

	// Significant content length increase (>3x baseline)
	if baseLen > 0 && respLen > baseLen*3 {
		return true
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []xpath.Payload) []xpath.Payload {
	seen := make(map[string]bool)
	var unique []xpath.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a detected XPath injection.
func (d *Detector) createFinding(target, param string, payload xpath.Payload, resp *http.Response, detType string) *core.Finding {
	finding := core.NewFinding("XPath Injection", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf(
		"XPath Injection detected in parameter '%s' via %s detection. "+
			"The application constructs XPath queries using unsanitized user input, "+
			"allowing an attacker to modify queries to bypass authentication or extract XML data.",
		param, detType,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("Payload: %s\nType: %s\nDetection: %s\nResponse snippet: %s",
		payload.Value, payload.Type, detType, body)
	finding.Tool = "xpath-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Use parameterized XPath queries or XPath variable binding. " +
		"Validate and sanitize all user input before including in XPath expressions. " +
		"Escape special XPath characters in user input. " +
		"Consider using XPath 2.0 with parameter binding support."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-09"}, // Testing for XPath Injection
		[]string{"A03:2025"},     // Injection
		[]string{"CWE-643"},      // Improper Neutralization of Data within XPath Expressions
	)

	return finding
}
