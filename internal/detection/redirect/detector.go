// Package redirect provides Open Redirect vulnerability detection.
package redirect

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/analysis"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/redirect"
)

// Detector performs Open Redirect vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Open Redirect Detector.
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

// DetectOptions configures detection behavior.
type DetectOptions struct {
	// Maximum number of payloads to test
	MaxPayloads int
	// Timeout for each request
	Timeout time.Duration
	// Include bypass payloads
	IncludeBypass bool
	// Evil domain to test redirects to
	EvilDomain string
	// Trusted domain (for bypass testing)
	TrustedDomain string
	// Follow redirects to verify
	FollowRedirects bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:     50,
		Timeout:         10 * time.Second,
		IncludeBypass:   true,
		EvilDomain:      "evil.com",
		TrustedDomain:   "",
		FollowRedirects: false,
	}
}

// DetectionResult contains Open Redirect detection results.
type DetectionResult struct {
	Vulnerable          bool
	Findings            []*core.Finding
	TestedPayloads      int
	RedirectsToExternal bool
	BypassUsed          redirect.BypassType
}

// Detect tests a parameter for Open Redirect vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Parse target URL to get the trusted domain if not provided
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return result, fmt.Errorf("invalid target URL: %w", err)
	}

	if opts.TrustedDomain == "" {
		opts.TrustedDomain = parsedTarget.Host
	}

	// Collect payloads
	payloads := redirect.GetPayloads()

	// Add domain-specific bypass payloads if bypass testing is enabled
	if opts.IncludeBypass {
		payloads = append(payloads, redirect.GeneratePayloadsForDomain(opts.TrustedDomain, opts.EvilDomain)...)
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Create a non-redirect-following client for detection.
	// Clone first to avoid mutating the shared client from concurrent goroutines.
	nonRedirectClient := d.client.Clone().WithFollowRedirects(false)

	// Capture a baseline response so the body-based redirect checks
	// (meta-refresh, JS redirects) can be gated on the baseline NOT
	// already containing the same evil-domain reference. Without this,
	// a page that benignly mentions or links to evil.com would FP.
	baselineBody := ""
	if br, berr := nonRedirectClient.SendPayload(ctx, target, param, "skws_redirect_baseline", method); berr == nil && br != nil {
		baselineBody = br.Body
	}

	// Test each payload
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		// Replace evil.com in payload with the configured evil domain
		payloadValue := strings.ReplaceAll(payload.Value, "evil.com", opts.EvilDomain)

		// Send payload
		resp, err := nonRedirectClient.SendPayload(ctx, target, param, payloadValue, method)
		if err != nil {
			continue
		}

		// Check if response indicates a redirect to external domain
		if d.isVulnerable(resp, payloadValue, opts.EvilDomain, baselineBody) {
			finding := d.createFinding(target, param, payload, resp, opts.EvilDomain)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.RedirectsToExternal = true
			result.BypassUsed = payload.BypassType

			// Continue testing to find more bypasses (but limit)
			if len(result.Findings) >= 3 {
				return result, nil
			}
		}
	}

	return result, nil
}

// DetectParams discovers redirect parameters in the target URL.
func (d *Detector) DetectParams(ctx context.Context, target, method string) ([]string, error) {
	var foundParams []string

	// Get the baseline response
	baselineResp, err := d.client.Get(ctx, target)
	if err != nil {
		return foundParams, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Create a non-redirect-following client
	nonRedirectClient := d.client.WithFollowRedirects(false)

	// Test each common redirect parameter
	for _, param := range redirect.RedirectParams() {
		select {
		case <-ctx.Done():
			return foundParams, ctx.Err()
		default:
		}

		// Add the parameter with a test URL
		testURL := target
		if strings.Contains(target, "?") {
			testURL = target + "&" + param + "=https://example.com"
		} else {
			testURL = target + "?" + param + "=https://example.com"
		}

		resp, err := nonRedirectClient.Get(ctx, testURL)
		if err != nil {
			continue
		}

		// Check if this parameter causes different behavior
		if d.isRedirectParam(resp, baselineResp) {
			foundParams = append(foundParams, param)
		}
	}

	return foundParams, nil
}

// isVulnerable determines if the response indicates a successful open redirect.
//
// Body-based signals (meta-refresh, JS redirect) require:
//  1. The baseline body did NOT already contain the evil-domain reference
//     (otherwise the page legitimately links to it).
//  2. The payload echo is stripped from the body before matching, so a
//     page that simply reflects ?next=https://evil.com into a hidden form
//     field doesn't masquerade as a redirect.
func (d *Detector) isVulnerable(resp *http.Response, payload, evilDomain, baselineBody string) bool {
	if resp == nil {
		return false
	}

	// Check for redirect status codes — Location header is authoritative
	// and the only signal we trust without baseline gating.
	isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400
	if isRedirect {
		location := resp.Headers["Location"]
		if location == "" {
			location = resp.Headers["location"]
		}
		if location != "" {
			return d.isExternalRedirect(location, evilDomain)
		}
	}

	// Body-based checks: strip echo, then require baseline-diff.
	stripped := analysis.StripEcho(resp.Body, payload)
	bodyHasEvil := strings.Contains(strings.ToLower(stripped), strings.ToLower(evilDomain))
	baselineHasEvil := strings.Contains(strings.ToLower(baselineBody), strings.ToLower(evilDomain))
	if !bodyHasEvil || baselineHasEvil {
		return false
	}

	if d.hasMetaRefreshToExternal(stripped, evilDomain) {
		return true
	}
	if d.hasJSRedirectToExternal(stripped, evilDomain) {
		return true
	}

	return false
}

// isExternalRedirect checks if a location header redirects to external domain.
func (d *Detector) isExternalRedirect(location, evilDomain string) bool {
	// Direct match
	if strings.Contains(strings.ToLower(location), strings.ToLower(evilDomain)) {
		return true
	}

	// Parse the location
	parsedLoc, err := url.Parse(location)
	if err == nil && parsedLoc.Host != "" {
		// Check if host contains evil domain
		if strings.Contains(strings.ToLower(parsedLoc.Host), strings.ToLower(evilDomain)) {
			return true
		}
	}

	// Check for protocol-relative URLs
	if strings.HasPrefix(location, "//") {
		// Remove leading slashes and check
		trimmed := strings.TrimLeft(location, "/\\")
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(evilDomain)) {
			return true
		}
	}

	return false
}

// hasMetaRefreshToExternal checks for meta refresh redirects to external domains.
func (d *Detector) hasMetaRefreshToExternal(body, evilDomain string) bool {
	bodyLower := strings.ToLower(body)
	evilLower := strings.ToLower(evilDomain)

	// Check for meta refresh patterns
	metaPatterns := []string{
		"<meta http-equiv=\"refresh\"",
		"<meta http-equiv='refresh'",
		"<meta content=",
	}

	for _, pattern := range metaPatterns {
		if strings.Contains(bodyLower, pattern) && strings.Contains(bodyLower, evilLower) {
			return true
		}
	}

	return false
}

// hasJSRedirectToExternal checks for JavaScript redirects to external domains.
func (d *Detector) hasJSRedirectToExternal(body, evilDomain string) bool {
	bodyLower := strings.ToLower(body)
	evilLower := strings.ToLower(evilDomain)

	// Check for JS redirect patterns
	jsPatterns := []string{
		"window.location",
		"location.href",
		"location.replace",
		"location.assign",
		"document.location",
	}

	for _, pattern := range jsPatterns {
		if strings.Contains(bodyLower, pattern) && strings.Contains(bodyLower, evilLower) {
			return true
		}
	}

	return false
}

// isRedirectParam checks if a parameter affects redirect behavior.
func (d *Detector) isRedirectParam(resp, baseline *http.Response) bool {
	if resp == nil {
		return false
	}

	// Check for redirect status code
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Check if baseline was also a redirect
		if baseline != nil && baseline.StatusCode >= 300 && baseline.StatusCode < 400 {
			// Check if Location header changed
			return resp.Headers["Location"] != baseline.Headers["Location"]
		}
		return true
	}

	// Check for different response behavior
	if baseline != nil {
		// Significant content difference might indicate the param is processed
		if len(resp.Body) != len(baseline.Body) && resp.StatusCode != baseline.StatusCode {
			return true
		}
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []redirect.Payload) []redirect.Payload {
	seen := make(map[string]bool)
	var unique []redirect.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful Open Redirect test.
func (d *Detector) createFinding(target, param string, payload redirect.Payload, resp *http.Response, evilDomain string) *core.Finding {
	severity := core.SeverityMedium
	// Elevate severity if bypass technique was used
	if payload.BypassType != redirect.BypassNone {
		severity = core.SeverityMedium // Still medium but note bypass worked
	}

	finding := core.NewFinding("Open Redirect", severity)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("Open Redirect vulnerability in '%s' parameter", param)

	if payload.BypassType != redirect.BypassNone {
		finding.Description += fmt.Sprintf(" (bypass technique: %s)", payload.BypassType)
	}

	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "redirect-detector"

	if resp != nil {
		location := resp.Headers["Location"]
		if location == "" {
			location = resp.Headers["location"]
		}
		if location != "" {
			finding.Evidence += fmt.Sprintf("\nRedirect Location: %s", location)
		}
		finding.Evidence += fmt.Sprintf("\nStatus Code: %d", resp.StatusCode)
	}

	finding.Remediation = "Implement a strict allowlist of permitted redirect destinations. " +
		"Avoid using user-supplied input directly in redirect URLs. " +
		"If redirects must use user input, validate against a list of known safe URLs. " +
		"Use relative paths instead of absolute URLs when possible. " +
		"Implement URL parsing to verify the domain before redirecting."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-04"}, // Client-side redirect testing
		[]string{"A01:2025"},     // Broken Access Control
		[]string{"CWE-601"},      // Open Redirect
	)

	return finding
}
