// Package cachepoisoning provides web cache poisoning vulnerability detection.
// It detects when unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, etc.)
// are reflected in responses that may be cached by intermediary proxies.
package cachepoisoning

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/cachepoisoning"
)

// Detector performs web cache poisoning vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Cache Poisoning Detector.
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
	return "cache-poisoning"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Web Cache Poisoning vulnerability detector that tests unkeyed headers for reflection in cached responses"
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	// MaxPayloads limits the number of payloads to test.
	MaxPayloads int
	// IncludeWAFBypass includes WAF bypass payload variants.
	IncludeWAFBypass bool
	// Timeout sets the per-request timeout.
	Timeout time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      30,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
	}
}

// DetectionResult contains cache poisoning detection results.
type DetectionResult struct {
	// Vulnerable indicates whether a cache poisoning vulnerability was found.
	Vulnerable bool
	// Findings contains the discovered vulnerabilities.
	Findings []*core.Finding
	// TestedPayloads is the number of payloads tested.
	TestedPayloads int
}

// Detect tests a target for web cache poisoning vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if target == "" {
		return result, fmt.Errorf("target URL is required")
	}

	// Get baseline response without any special headers
	baselineResp, err := d.client.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Collect header-based payloads
	payloads := d.collectPayloads(opts)

	// Test each unkeyed header
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Skip non-header payloads (path-based, parameter-based)
		if payload.HeaderName == "" {
			continue
		}

		result.TestedPayloads++

		// Send request with the unkeyed header
		headers := map[string]string{
			payload.HeaderName: payload.Value,
		}

		resp, err := d.client.Do(ctx, &http.Request{
			Method:  method,
			URL:     target,
			Headers: headers,
		})
		if err != nil {
			continue
		}

		// Check if header value is reflected in response body
		if d.hasValueReflection(payload.Value, resp.Body, baselineResp.Body) {
			finding := d.createFinding(target, payload, resp, "header-reflection")
			finding.Evidence = fmt.Sprintf("Header %s with value %q reflected in response body",
				payload.HeaderName, payload.Value)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}

		// Check for status code change (e.g., redirect caused by scheme header)
		if d.hasStatusCodeChange(baselineResp.StatusCode, resp.StatusCode) {
			finding := d.createFinding(target, payload, resp, "status-code-differential")
			finding.Evidence = fmt.Sprintf("Header %s caused status code change from %d to %d",
				payload.HeaderName, baselineResp.StatusCode, resp.StatusCode)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}

		// Check for new redirect location containing the injected value
		if location := resp.Headers["Location"]; location != "" {
			if strings.Contains(location, payload.Value) {
				finding := d.createFinding(target, payload, resp, "redirect-injection")
				finding.Evidence = fmt.Sprintf("Header %s value %q reflected in Location header: %s",
					payload.HeaderName, payload.Value, location)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return result, nil
			}
		}
	}

	return result, nil
}

// hasValueReflection checks if the injected value appears in the response
// but not in the baseline response.
func (d *Detector) hasValueReflection(injectedValue, responseBody, baselineBody string) bool {
	if responseBody == "" || injectedValue == "" {
		return false
	}

	// The injected value must be in the response but not in the baseline
	if strings.Contains(responseBody, injectedValue) && !strings.Contains(baselineBody, injectedValue) {
		return true
	}

	return false
}

// hasStatusCodeChange checks if the status code changed to indicate cache poisoning.
func (d *Detector) hasStatusCodeChange(baseline, current int) bool {
	// Redirect when baseline is not a redirect
	if baseline >= 200 && baseline < 300 && current >= 300 && current < 400 {
		return true
	}
	// Error when baseline is OK
	if baseline >= 200 && baseline < 300 && current >= 500 {
		return true
	}
	return false
}

// collectPayloads gathers all cache poisoning payloads.
func (d *Detector) collectPayloads(opts DetectOptions) []cachepoisoning.Payload {
	payloads := cachepoisoning.GetAllPayloads()

	if !opts.IncludeWAFBypass {
		var filtered []cachepoisoning.Payload
		for _, p := range payloads {
			if !p.WAFBypass {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	payloads = cachepoisoning.DeduplicatePayloads(payloads)

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	return payloads
}

// createFinding creates a Finding from a successful cache poisoning test.
func (d *Detector) createFinding(target string, payload cachepoisoning.Payload, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("Web Cache Poisoning", core.SeverityHigh)
	finding.URL = target
	finding.Description = fmt.Sprintf("%s Web Cache Poisoning vulnerability via %s header. %s",
		detectionType, payload.HeaderName, payload.Description)
	finding.Evidence = fmt.Sprintf("Header: %s\nValue: %s\nDescription: %s",
		payload.HeaderName, payload.Value, payload.Description)
	finding.Tool = "cachepoisoning-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Include all relevant headers in the cache key or strip unkeyed headers. " +
		"Disable caching for responses that vary based on user-controlled headers. " +
		"Use the Vary header to declare which headers affect the response. " +
		"Validate and sanitize all input from forwarded headers. " +
		"Configure CDN/cache to only forward expected headers to the origin. " +
		"Implement cache-control headers to restrict caching of sensitive responses."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-17"},
		[]string{"A05:2025"},
		[]string{"CWE-444"},
	)

	return finding
}
