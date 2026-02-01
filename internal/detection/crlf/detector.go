// Package crlf provides CRLF Injection vulnerability detection.
package crlf

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/crlf"
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

	// Check for injected headers in response
	if payload.InjectedHeader != "" {
		if d.hasInjectedHeader(resp, payload.InjectedHeader, baseline) {
			return true
		}
	}

	// Check for specific header injection indicators
	if d.hasHeaderInjectionIndicators(resp, baseline) {
		return true
	}

	// Check for response splitting (double CRLF)
	if payload.InjectionType == crlf.InjectionResponseSplit {
		if d.hasResponseSplitIndicators(resp) {
			return true
		}
	}

	// Check body for reflected CRLF patterns
	if d.hasReflectedCRLFPatterns(resp.Body, payload) {
		return true
	}

	return false
}

// hasInjectedHeader checks if an injected header appears in the response.
func (d *Detector) hasInjectedHeader(resp *http.Response, headerName string, baseline *http.Response) bool {
	headerLower := strings.ToLower(headerName)

	// Check if the header exists in response
	for k, v := range resp.Headers {
		if strings.ToLower(k) == headerLower {
			// Check if this header was NOT in baseline
			if baseline != nil {
				for baseK, baseV := range baseline.Headers {
					if strings.ToLower(baseK) == headerLower && baseV == v {
						// Same header with same value existed in baseline
						return false
					}
				}
			}
			return true
		}
	}

	// Special case: check for common injected values
	injectionPatterns := []string{
		"crlf=injection",
		"crlf=",
		"injection",
	}

	for _, header := range resp.Headers {
		for _, pattern := range injectionPatterns {
			if strings.Contains(strings.ToLower(header), pattern) {
				return true
			}
		}
	}

	return false
}

// hasHeaderInjectionIndicators checks for signs of header injection.
func (d *Detector) hasHeaderInjectionIndicators(resp, baseline *http.Response) bool {
	// Check for new Set-Cookie headers
	if d.hasNewCookieHeader(resp, baseline) {
		return true
	}

	// Check for injected custom headers
	for k := range resp.Headers {
		kLower := strings.ToLower(k)
		if strings.HasPrefix(kLower, "x-injected") ||
			strings.HasPrefix(kLower, "x-crlf") {
			return true
		}
	}

	// Check for unexpected headers that might indicate injection
	suspiciousHeaders := []string{
		"x-injected",
		"injected",
		"x-crlf",
	}

	for k := range resp.Headers {
		kLower := strings.ToLower(k)
		for _, suspicious := range suspiciousHeaders {
			if strings.Contains(kLower, suspicious) {
				return true
			}
		}
	}

	return false
}

// hasNewCookieHeader checks if there's a new Set-Cookie header.
func (d *Detector) hasNewCookieHeader(resp, baseline *http.Response) bool {
	respCookies := d.getCookieHeaders(resp)

	if baseline == nil {
		// If we have crlf-related cookie, it's likely injected
		for _, cookie := range respCookies {
			if strings.Contains(strings.ToLower(cookie), "crlf") {
				return true
			}
		}
		return false
	}

	baselineCookies := d.getCookieHeaders(baseline)

	// Check for new cookies that weren't in baseline
	for _, cookie := range respCookies {
		if strings.Contains(strings.ToLower(cookie), "crlf") {
			// Check if this cookie was NOT in baseline
			found := false
			for _, baseCookie := range baselineCookies {
				if cookie == baseCookie {
					found = true
					break
				}
			}
			if !found {
				return true
			}
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

// hasReflectedCRLFPatterns checks for reflected CRLF patterns in body.
func (d *Detector) hasReflectedCRLFPatterns(body string, payload crlf.Payload) bool {
	// Check for decoded CRLF sequences in body
	crlfIndicators := []string{
		"\r\nSet-Cookie:",
		"\r\nX-Injected:",
		"\r\nLocation:",
		"\nSet-Cookie:",
		"\nX-Injected:",
	}

	for _, indicator := range crlfIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	// Check for injected header name in body (might indicate partial injection)
	if payload.InjectedHeader != "" {
		// Header followed by value pattern
		headerPattern := payload.InjectedHeader + ":"
		if strings.Contains(body, headerPattern) {
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
		[]string{"A03:2021"},     // Injection
		[]string{"CWE-93"},       // CRLF Injection
	)

	return finding
}
