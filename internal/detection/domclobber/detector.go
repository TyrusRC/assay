package domclobber

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/domclobber"
)

// Detector performs DOM Clobbering vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new DOM Clobbering Detector.
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
	return "domclobber"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "DOM Clobbering vulnerability detector using named HTML element injection and reflection analysis"
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      30,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
	}
}

// DetectionResult contains DOM clobbering detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a parameter for DOM Clobbering vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if param == "" {
		return result, nil
	}

	payloads := d.gatherPayloads(opts)

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	baselineResp, err := d.client.SendPayload(ctx, target, param, "baseline_test_value", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}
	baselineBody := baselineResp.Body

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

		if d.analyzeResponse(baselineBody, resp.Body, payload.Value) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// gatherPayloads collects payloads based on detection options.
func (d *Detector) gatherPayloads(opts DetectOptions) []domclobber.Payload {
	payloads := domclobber.GetPayloads()

	if !opts.IncludeWAFBypass {
		var filtered []domclobber.Payload
		for _, p := range payloads {
			if !p.WAFBypass {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	return d.deduplicatePayloads(payloads)
}

// analyzeResponse checks if the injected HTML element appears raw in the response.
// A vulnerable response contains the actual HTML tag (not HTML-encoded).
func (d *Detector) analyzeResponse(baseline, injected, payload string) bool {
	if baseline == "" && injected == "" {
		return false
	}

	// Extract the tag name and key attribute from the payload for matching.
	// For example, from `<form id=x>` we need to find `<form` with `id=x` in the response.
	tagStart := extractTagStart(payload)
	if tagStart == "" {
		return false
	}

	// The payload tag must be present in the injected response
	if !strings.Contains(injected, tagStart) {
		return false
	}

	// The payload tag must NOT be present in the baseline (to avoid false positives)
	if strings.Contains(baseline, tagStart) {
		return false
	}

	// Verify the element was not HTML-encoded in the response.
	// If the response contains &lt; instead of <, it is safely encoded.
	encodedTag := strings.ReplaceAll(tagStart, "<", "&lt;")
	if strings.Contains(injected, encodedTag) && !strings.Contains(injected, tagStart) {
		return false
	}

	return true
}

// extractTagStart extracts the opening tag portion from a payload.
// For example, "<form id=x>" returns "<form" and "<img name=x>" returns "<img".
func extractTagStart(payload string) string {
	if !strings.HasPrefix(payload, "<") {
		return ""
	}

	// Find the tag name boundary (space or >)
	end := strings.IndexAny(payload, " >")
	if end == -1 {
		return payload
	}

	return payload[:end]
}

// deduplicatePayloads removes duplicate payloads by value.
func (d *Detector) deduplicatePayloads(payloads []domclobber.Payload) []domclobber.Payload {
	seen := make(map[string]bool)
	var unique []domclobber.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful DOM clobbering test.
func (d *Detector) createFinding(target, param string, payload domclobber.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("DOM Clobbering", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("DOM Clobbering vulnerability in '%s' parameter (Element: %s, Target property: %s)",
		param, payload.Element, payload.TargetProperty)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "domclobber-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Sanitize all user input before rendering in HTML context. " +
		"Use Content Security Policy (CSP) to restrict inline scripts. " +
		"Avoid using document properties that can be clobbered (e.g., document.getElementById). " +
		"Use explicit variable declarations instead of relying on named access on Window. " +
		"Implement DOMPurify or similar sanitization libraries with DOM clobbering protection."

	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-06"},
		[]string{"A03:2025"},
		[]string{"CWE-79"},
	)

	return finding
}
