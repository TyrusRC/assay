// Package ldap provides detection for LDAP Injection vulnerabilities.
package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/ldap"
)

// Detector performs LDAP Injection detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new LDAP Injection Detector.
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

// DetectOptions configures LDAP injection detection behavior.
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

// DetectionResult contains LDAP injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
	DetectionType  string
}

// Detect checks for LDAP Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads
	payloads := ldap.GetPayloads()
	if opts.IncludeWAFBypass {
		payloads = append(payloads, ldap.GetWAFBypassPayloads()...)
	}

	// Deduplicate and limit
	payloads = d.deduplicatePayloads(payloads)
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Establish baseline
	baselineResp, err := d.client.SendPayload(ctx, target, param, "ldap_baseline", method)
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
		if d.hasLDAPError(resp.Body) && !d.hasLDAPError(baselineResp.Body) {
			result.DetectionType = "error-based"
			finding := d.createFinding(target, param, payload, resp, "error-based")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}

		// Check for wildcard/boolean-based detection (significant content change)
		if d.hasSignificantChange(resp, baselineResp) {
			result.DetectionType = "behavior-based"
			finding := d.createFinding(target, param, payload, resp, "behavior-based")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// hasLDAPError checks if the response contains LDAP error patterns.
func (d *Detector) hasLDAPError(body string) bool {
	lowerBody := strings.ToLower(body)
	for _, pattern := range ldap.GetErrorPatterns() {
		if strings.Contains(lowerBody, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// hasSignificantChange checks for significant response differences.
func (d *Detector) hasSignificantChange(resp, baseline *http.Response) bool {
	// Check for significant content length difference (>3x baseline)
	baseLen := len(baseline.Body)
	respLen := len(resp.Body)

	if baseLen > 0 && respLen > baseLen*3 {
		return true
	}

	// Check for status code change that indicates different behavior
	if baseline.StatusCode == 200 && resp.StatusCode != baseline.StatusCode {
		return false
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []ldap.Payload) []ldap.Payload {
	seen := make(map[string]bool)
	var unique []ldap.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a detected LDAP injection.
func (d *Detector) createFinding(target, param string, payload ldap.Payload, resp *http.Response, detType string) *core.Finding {
	finding := core.NewFinding("LDAP Injection", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf(
		"LDAP Injection detected in parameter '%s' via %s detection. "+
			"The application constructs LDAP queries using unsanitized user input, "+
			"allowing an attacker to modify LDAP queries to bypass authentication or extract data.",
		param, detType,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("Payload: %s\nType: %s\nDetection: %s\nResponse snippet: %s",
		payload.Value, payload.Type, detType, body)
	finding.Tool = "ldap-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Use parameterized LDAP queries or LDAP encoding functions. " +
		"Validate and sanitize all user input before including in LDAP filters. " +
		"Escape special LDAP characters: *, (, ), \\, NUL. " +
		"Apply the principle of least privilege to LDAP service accounts."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-06"}, // Testing for LDAP Injection
		[]string{"A03:2021"},     // Injection
		[]string{"CWE-90"},       // Improper Neutralization of Special Elements in LDAP Query
	)

	return finding
}
