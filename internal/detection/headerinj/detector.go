// Package headerinj provides detection for HTTP Header Injection vulnerabilities.
package headerinj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/headerinj"
)

// Detector performs HTTP Header Injection detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Header Injection Detector.
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

// DetectOptions configures header injection detection behavior.
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

// DetectionResult contains header injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
	DetectionType  string
}

// Detect checks for HTTP Header Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads
	payloads := headerinj.GetPayloads()
	if opts.IncludeWAFBypass {
		payloads = append(payloads, headerinj.GetWAFBypassPayloads()...)
	}

	// Deduplicate and limit
	payloads = d.deduplicatePayloads(payloads)
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline
	baselineResp, err := d.client.SendPayload(ctx, target, param, "headerinj_baseline", method)
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

		// Check for injected header in response
		if payload.Marker != "" && d.hasInjectedHeader(resp.Headers, payload.Marker) {
			if !d.hasInjectedHeader(baselineResp.Headers, payload.Marker) {
				result.DetectionType = "header-injection"
				finding := d.createFinding(target, param, payload, resp)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return result, nil
			}
		}

		// Check for CRLF reflection in body
		if d.hasCRLFReflection(resp.Body, payload, baselineResp.Body) {
			result.DetectionType = "crlf-reflection"
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// hasInjectedHeader checks if a specific injected header is present.
func (d *Detector) hasInjectedHeader(headers map[string]string, marker string) bool {
	if marker == "" {
		return false
	}

	lowerMarker := strings.ToLower(marker)
	for name := range headers {
		if strings.ToLower(name) == lowerMarker {
			return true
		}
	}
	return false
}

// hasCRLFReflection checks if CRLF characters are reflected in the body.
func (d *Detector) hasCRLFReflection(body string, payload headerinj.Payload, baselineBody string) bool {
	// Check if the injected marker appears in the body (not in baseline)
	if payload.Marker != "" {
		markerInBody := strings.Contains(body, payload.Marker+":")
		markerInBaseline := strings.Contains(baselineBody, payload.Marker+":")
		if markerInBody && !markerInBaseline {
			return true
		}
	}

	// Check for response splitting indicators
	if payload.Type == headerinj.TypeResponseSplit {
		if strings.Contains(body, "<html>injected</html>") && !strings.Contains(baselineBody, "<html>injected</html>") {
			return true
		}
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []headerinj.Payload) []headerinj.Payload {
	seen := make(map[string]bool)
	var unique []headerinj.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a detected header injection.
func (d *Detector) createFinding(target, param string, payload headerinj.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("HTTP Header Injection", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf(
		"HTTP Header Injection detected in parameter '%s'. "+
			"The application includes user input in HTTP response headers without proper sanitization, "+
			"allowing an attacker to inject arbitrary headers or perform response splitting.",
		param,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("Payload: %s\nType: %s\nResponse snippet: %s",
		payload.Value, payload.Type, body)
	finding.Tool = "headerinj-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Never include user input directly in HTTP response headers. " +
		"Strip or encode CR (\\r) and LF (\\n) characters from all user input used in headers. " +
		"Use framework-provided header setting functions that handle encoding. " +
		"Implement response header output encoding."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-15"}, // Testing for HTTP Splitting/Smuggling
		[]string{"A03:2021"},     // Injection
		[]string{"CWE-113"},      // Improper Neutralization of CRLF Sequences in HTTP Headers
	)

	return finding
}
