// Package csti provides detection for Client-Side Template Injection vulnerabilities.
package csti

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/csti"
)

// Detector performs Client-Side Template Injection detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new CSTI Detector.
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

// DetectOptions configures CSTI detection behavior.
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

// DetectionResult contains CSTI detection results.
type DetectionResult struct {
	Vulnerable        bool
	Findings          []*core.Finding
	TestedPayloads    int
	DetectedFramework string
}

// Detect checks for Client-Side Template Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads
	payloads := csti.GetProbePayloads()
	if opts.IncludeWAFBypass {
		payloads = append(payloads, csti.GetWAFBypassPayloads()...)
	}

	// Deduplicate and limit
	payloads = d.deduplicatePayloads(payloads)
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "csti_baseline_test", method)
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

		// Check if template expression was evaluated
		if d.isTemplateEvaluated(resp, baselineResp, payload) {
			result.DetectedFramework = string(payload.Framework)
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// isTemplateEvaluated checks if a template expression was evaluated.
func (d *Detector) isTemplateEvaluated(resp, baseline *http.Response, payload csti.Payload) bool {
	if payload.Expected == "" {
		return false
	}

	// Check if the expected output is in the response
	if !d.containsExpected(resp.Body, payload.Expected) {
		return false
	}

	// Make sure the expected output wasn't already in the baseline
	if d.containsExpected(baseline.Body, payload.Expected) {
		return false
	}

	return true
}

// containsExpected checks if the response body contains the expected result.
func (d *Detector) containsExpected(body, expected string) bool {
	return strings.Contains(body, expected)
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []csti.Payload) []csti.Payload {
	seen := make(map[string]bool)
	var unique []csti.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a detected CSTI.
func (d *Detector) createFinding(target, param string, payload csti.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("Client-Side Template Injection", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf(
		"Client-Side Template Injection detected in parameter '%s'. "+
			"The application evaluates template expressions in user input, "+
			"which can lead to XSS and potentially other attacks depending on the framework.",
		param,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("Payload: %s\nExpected: %s\nFramework: %s\nResponse snippet: %s",
		payload.Value, payload.Expected, payload.Framework, body)
	finding.Tool = "csti-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Avoid rendering user input within client-side templates. " +
		"Use proper output encoding and escaping. " +
		"Implement Content-Security-Policy headers. " +
		"Consider using frameworks that auto-escape template expressions."

	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-11"}, // Testing for Client-side Template Injection
		[]string{"A03:2025"},     // Injection
		[]string{"CWE-79"},       // Improper Neutralization of Input During Web Page Generation
	)

	return finding
}
