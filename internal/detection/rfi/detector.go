// Package rfi provides detection for Remote File Inclusion vulnerabilities.
package rfi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/rfi"
)

// rfiPayload is a local type alias for cleaner code.
type rfiPayload = rfi.Payload

// Detector performs Remote File Inclusion detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new RFI Detector.
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

// DetectOptions configures RFI detection behavior.
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

// DetectionResult contains RFI detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect checks for Remote File Inclusion vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads
	payloads := rfi.GetPayloads()
	if opts.IncludeWAFBypass {
		payloads = append(payloads, rfi.GetWAFBypassPayloads()...)
	}

	// Deduplicate and limit
	payloads = d.deduplicatePayloads(payloads)
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Establish baseline
	baselineResp, err := d.client.SendPayload(ctx, target, param, "baseline_rfi_test", method)
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

		// Check for RFI indicators
		if d.isRFISuccess(resp, baselineResp, payload) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// isRFISuccess checks if the response indicates successful RFI.
func (d *Detector) isRFISuccess(resp, baseline *http.Response, payload rfi.Payload) bool {
	// Check for expected patterns
	for _, pattern := range payload.Patterns {
		if pattern != "" && strings.Contains(resp.Body, pattern) {
			// Make sure the pattern wasn't in the baseline
			if !strings.Contains(baseline.Body, pattern) {
				return true
			}
		}
	}

	// Check for common RFI success indicators
	rfiIndicators := []string{
		"uid=",        // Linux command output
		"root:x:0:0",  // /etc/passwd content
		"RFITEST",     // Our custom marker
		"httpbin.org", // External service response
		"<?php",       // PHP code executed
	}

	for _, indicator := range rfiIndicators {
		if strings.Contains(resp.Body, indicator) && !strings.Contains(baseline.Body, indicator) {
			return true
		}
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []rfi.Payload) []rfi.Payload {
	seen := make(map[string]bool)
	var unique []rfi.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a detected RFI.
func (d *Detector) createFinding(target, param string, payload rfi.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("Remote File Inclusion", core.SeverityCritical)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf(
		"Remote File Inclusion detected in parameter '%s'. The application includes content from remote URLs, "+
			"allowing an attacker to execute arbitrary code by supplying a malicious URL.",
		param,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("Payload: %s\nProtocol: %s\nResponse snippet: %s",
		payload.Value, payload.Protocol, body)
	finding.Tool = "rfi-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Never include files based on user-supplied input. " +
		"If dynamic file inclusion is required, use a whitelist of allowed files. " +
		"Disable allow_url_include in PHP configuration. " +
		"Implement proper input validation and sanitization."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-11"}, // Testing for Code Injection
		[]string{"A03:2021"},     // Injection
		[]string{"CWE-98"},       // Improper Control of Filename for Include
	)

	return finding
}
