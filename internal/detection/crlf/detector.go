// Package crlf provides CRLF Injection vulnerability detection.
package crlf

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/crlf"
)

// Detector performs CRLF Injection vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new CRLF Detector.
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
	// Test header injection
	TestHeaderInjection bool
	// Test response splitting
	TestResponseSplit bool
	// Include all encoding types
	IncludeAllEncodings bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:         50,
		Timeout:             10 * time.Second,
		TestHeaderInjection: true,
		TestResponseSplit:   true,
		IncludeAllEncodings: true,
	}
}

// DetectionResult contains CRLF detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
	InjectionType  crlf.InjectionType
	EncodingUsed   crlf.EncodingType
	InjectedHeader string
}

// Detect tests a parameter for CRLF injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Collect payloads based on options
	var payloads []crlf.Payload

	if opts.TestHeaderInjection {
		payloads = append(payloads, crlf.GetHeaderInjectionPayloads()...)
	}

	if opts.TestResponseSplit {
		payloads = append(payloads, crlf.GetResponseSplitPayloads()...)
	}

	// Filter by encoding if not including all
	if !opts.IncludeAllEncodings {
		filtered := make([]crlf.Payload, 0)
		for _, p := range payloads {
			if p.EncodingType == crlf.EncodingURL || p.EncodingType == crlf.EncodingNone {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "normalvalue", method)
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

		// Send payload
		resp, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
		if err != nil {
			continue
		}

		// Check if response indicates CRLF injection success
		if d.isVulnerable(resp, baselineResp, payload) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.InjectionType = payload.InjectionType
			result.EncodingUsed = payload.EncodingType
			result.InjectedHeader = payload.InjectedHeader

			// Continue testing to find more vulns but limit
			if len(result.Findings) >= 3 {
				return result, nil
			}
		}
	}

	return result, nil
}

// isVulnerable determines if the response indicates a successful CRLF injection.
func (d *Detector) isVulnerable(resp, baseline *http.Response, payload crlf.Payload) bool {
	if resp == nil {
		return false
	}

	// Primary check: the payload's specific injected marker must appear
	// in the named header's value. Matching on header name alone (or on
	// "any new cookie since baseline") produces 100% FPs against targets
	// behind AWS ALB / CloudFront that rotate session cookies per request.
	if payload.InjectedHeader != "" {
		if d.hasInjectedHeader(resp, payload, baseline) {
			return true
		}
	}

	// Specific injected-custom-header markers (x-injected, x-crlf) are
	// narrow enough that seeing them in the response is strong evidence.
	if d.hasCustomInjectedHeader(resp) {
		return true
	}

	// Check for response splitting (double CRLF)
	if payload.InjectionType == crlf.InjectionResponseSplit {
		if d.hasResponseSplitIndicators(resp) {
			return true
		}
	}

	// Check body for reflected CRLF patterns (tight: needs literal CRLF
	// AND the payload's marker to co-occur).
	if d.hasReflectedCRLFPatterns(resp.Body, payload) {
		return true
	}

	return false
}

// extractInjectedValue parses payload.Value to recover the header value
// that would appear if the CRLF injection succeeded. For a payload like
// "%0d%0aSet-Cookie:crlf=injection" it returns "crlf=injection".
// Returns "" when the payload has no header-value portion or the value
// is too short/generic to be a reliable marker.
func (d *Detector) extractInjectedValue(payload crlf.Payload) string {
	decoded, err := url.QueryUnescape(payload.Value)
	if err != nil {
		decoded = payload.Value
	}
	lines := strings.FieldsFunc(decoded, func(r rune) bool {
		return r == '\r' || r == '\n'
	})
	for _, line := range lines {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		// Require the name to match the payload's declared injected
		// header and the value to be non-trivial (>=3 chars) so we don't
		// match incidental substrings.
		if strings.EqualFold(name, payload.InjectedHeader) && len(value) >= 3 {
			return value
		}
	}
	return ""
}

// hasInjectedHeader returns true iff the payload's specific injected
// marker appears in the value of the named response header AND was not
// already present in the baseline. Merely observing the header name in
// the response is not sufficient — session cookies rotate.
//
// Before comparing, we strip the raw payload (URL-encoded form) from
// each response header value. If an app URL-encodes our payload into a
// cookie value (e.g. `category=%0d%0aSet-Cookie:crlf=injection`), the
// marker "crlf=injection" literally appears inside that cookie value,
// but no CRLF injection happened — it's just data storage. Stripping
// the echoed payload eliminates that FP.
func (d *Detector) hasInjectedHeader(resp *http.Response, payload crlf.Payload, baseline *http.Response) bool {
	marker := d.extractInjectedValue(payload)
	if marker == "" {
		return false
	}
	markerLower := strings.ToLower(marker)
	headerLower := strings.ToLower(payload.InjectedHeader)
	rawPayloadLower := strings.ToLower(payload.Value)

	present := func(r *http.Response) bool {
		if r == nil {
			return false
		}
		for k, v := range r.Headers {
			if strings.ToLower(k) != headerLower {
				continue
			}
			stripped := strings.ToLower(v)
			if rawPayloadLower != "" {
				stripped = strings.ReplaceAll(stripped, rawPayloadLower, "")
			}
			if strings.Contains(stripped, markerLower) {
				return true
			}
		}
		return false
	}

	// Must appear in the test response but not in the baseline — baseline
	// containing the marker would mean it's noise unrelated to the payload.
	return present(resp) && !present(baseline)
}

// hasCustomInjectedHeader checks for well-known narrow marker-style
// header names that legitimate servers won't emit (x-injected, x-crlf).
func (d *Detector) hasCustomInjectedHeader(resp *http.Response) bool {
	for k := range resp.Headers {
		kLower := strings.ToLower(k)
		if strings.HasPrefix(kLower, "x-injected") || strings.HasPrefix(kLower, "x-crlf") {
			return true
		}
	}
	return false
}

// getCookieHeaders extracts Set-Cookie headers from response.
func (d *Detector) getCookieHeaders(resp *http.Response) []string {
	var cookies []string
	for k, v := range resp.Headers {
		if strings.ToLower(k) == "set-cookie" {
			cookies = append(cookies, v)
		}
	}
	return cookies
}

// hasResponseSplitIndicators checks for HTTP response splitting.
func (d *Detector) hasResponseSplitIndicators(resp *http.Response) bool {
	// Check for HTML/script content in unexpected places
	indicators := []string{
		"<html>",
		"<body>",
		"<script>",
		"Injected",
		"alert(1)",
	}

	bodyLower := strings.ToLower(resp.Body)
	for _, indicator := range indicators {
		if strings.Contains(bodyLower, strings.ToLower(indicator)) {
			// Check if this is expected content type
			contentType := resp.ContentType
			if !strings.Contains(contentType, "html") {
				return true
			}
		}
	}

	// Check for double HTTP responses (response splitting)
	if strings.Contains(resp.Body, "HTTP/1.") || strings.Contains(resp.Body, "HTTP/2") {
		return true
	}

	return false
}

// hasReflectedCRLFPatterns checks for reflected CRLF patterns in the body.
// Must find a literal CR/LF followed by the injected header AND the
// payload's specific marker value — otherwise we get FPs on docs/debug
// pages that merely mention "Set-Cookie:" as text.
func (d *Detector) hasReflectedCRLFPatterns(body string, payload crlf.Payload) bool {
	if payload.InjectedHeader == "" {
		return false
	}
	marker := d.extractInjectedValue(payload)
	if marker == "" {
		return false
	}

	sequences := []string{
		"\r\n" + payload.InjectedHeader + ":",
		"\n" + payload.InjectedHeader + ":",
	}
	for _, seq := range sequences {
		if strings.Contains(body, seq) && strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []crlf.Payload) []crlf.Payload {
	seen := make(map[string]bool)
	var unique []crlf.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful CRLF injection.
func (d *Detector) createFinding(target, param string, payload crlf.Payload, resp *http.Response) *core.Finding {
	severity := core.SeverityMedium
	if payload.InjectionType == crlf.InjectionResponseSplit {
		severity = core.SeverityHigh
	}
	// If Location header can be injected, it's high severity
	if payload.InjectedHeader == "Location" || payload.InjectedHeader == "Set-Cookie" {
		severity = core.SeverityHigh
	}

	finding := core.NewFinding("CRLF Injection", severity)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("CRLF Injection vulnerability in '%s' parameter", param)

	if payload.InjectionType == crlf.InjectionHeader {
		finding.Description += " (Header Injection)"
	} else if payload.InjectionType == crlf.InjectionResponseSplit {
		finding.Description += " (Response Splitting)"
	}

	finding.Evidence = fmt.Sprintf("Payload: %s\n", payload.Value)
	finding.Evidence += fmt.Sprintf("Encoding: %s\n", payload.EncodingType)
	finding.Evidence += fmt.Sprintf("Description: %s\n", payload.Description)

	if payload.InjectedHeader != "" {
		finding.Evidence += fmt.Sprintf("Injected Header: %s\n", payload.InjectedHeader)
	}

	if resp != nil {
		// Show relevant response headers
		finding.Evidence += "\nResponse Headers:\n"
		for k, v := range resp.Headers {
			// Only show potentially affected headers
			kLower := strings.ToLower(k)
			if kLower == "set-cookie" || kLower == "location" ||
				strings.HasPrefix(kLower, "x-") ||
				strings.HasPrefix(kLower, "access-control") {
				finding.Evidence += fmt.Sprintf("  %s: %s\n", k, v)
			}
		}
	}

	finding.Tool = "crlf-detector"

	finding.Remediation = "Sanitize all user input before including it in HTTP headers. " +
		"Remove or encode CR (\\r, %0d) and LF (\\n, %0a) characters. " +
		"Use a web framework that automatically escapes header values. " +
		"Implement input validation to reject requests containing CRLF sequences."

	if payload.InjectionType == crlf.InjectionResponseSplit {
		finding.Remediation += " HTTP Response Splitting can lead to cache poisoning, " +
			"XSS, and session hijacking. Ensure proper input validation is in place."
	}

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-15"}, // HTTP Splitting/Smuggling
		[]string{"A03:2025"},     // Injection
		[]string{"CWE-93"},       // CRLF Injection
	)

	return finding
}
