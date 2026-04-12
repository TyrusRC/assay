package hpp

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
	hpppayloads "github.com/swiss-knife-for-web-security/skws/internal/payloads/hpp"
)

// Detector performs HTTP Parameter Pollution vulnerability detection.
type Detector struct {
	client  *internalhttp.Client
	verbose bool
}

// New creates a new HTTP Parameter Pollution Detector.
func New(client *internalhttp.Client) *Detector {
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
	return "hpp"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "HTTP Parameter Pollution vulnerability detector using duplicate parameter injection and response differential analysis"
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	// MaxPayloads limits the number of payloads tested.
	MaxPayloads int
	// Timeout is the per-request timeout.
	Timeout time.Duration
	// IncludeWAFBypass includes payloads designed to evade WAF detection.
	IncludeWAFBypass bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      20,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
	}
}

// DetectionResult contains HTTP Parameter Pollution detection results.
type DetectionResult struct {
	// Vulnerable indicates whether an HPP vulnerability was found.
	Vulnerable bool
	// Findings contains the discovered vulnerability details.
	Findings []*core.Finding
	// TestedPayloads is the number of payloads that were tested.
	TestedPayloads int
}

// Detect tests a parameter for HTTP Parameter Pollution vulnerabilities.
// It sends requests with duplicate parameters and compares the response
// against a baseline to detect differential behavior.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Handle empty parameter gracefully
	if param == "" {
		return result, nil
	}

	// Build the payload set
	allPayloads := hpppayloads.GetPayloads()
	payloads := filterPayloads(allPayloads, opts.IncludeWAFBypass)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response (single parameter, no pollution)
	baselineResp, err := d.client.SendPayload(ctx, target, param, getOriginalValue(target, param), method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline response: %w", err)
	}

	// Test each payload by injecting a duplicate parameter
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		// Build polluted URL with duplicate parameter
		pollutedURL, err := buildPollutedURL(target, param, payload.Value, method)
		if err != nil {
			continue
		}

		// Send the polluted request
		pollutedResp, err := d.sendPollutedRequest(ctx, pollutedURL, method)
		if err != nil {
			continue
		}

		// Compare responses for differential behavior
		if d.hasResponseDifference(baselineResp, pollutedResp) {
			finding := d.createFinding(target, param, payload, pollutedResp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// filterPayloads returns payloads based on WAF bypass preference.
func filterPayloads(all []hpppayloads.Payload, includeWAFBypass bool) []hpppayloads.Payload {
	if includeWAFBypass {
		return all
	}
	var filtered []hpppayloads.Payload
	for _, p := range all {
		if !p.WAFBypass {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// getOriginalValue extracts the current value of a parameter from the URL.
func getOriginalValue(target, param string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return "test"
	}
	val := parsed.Query().Get(param)
	if val == "" {
		return "test"
	}
	return val
}

// buildPollutedURL constructs a URL with a duplicate parameter appended.
// For GET requests this appends to the query string. For POST-like methods
// the duplicate is added to the query string so the body can carry the original.
func buildPollutedURL(target, param, payload, method string) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Add the duplicate parameter to the query string
	// This preserves the original parameter and appends a second occurrence.
	rawQuery := parsed.RawQuery
	if rawQuery != "" {
		rawQuery += "&"
	}
	rawQuery += url.QueryEscape(param) + "=" + url.QueryEscape(payload)
	parsed.RawQuery = rawQuery

	return parsed.String(), nil
}

// sendPollutedRequest sends the request with the polluted URL.
func (d *Detector) sendPollutedRequest(ctx context.Context, pollutedURL, method string) (*internalhttp.Response, error) {
	req := &internalhttp.Request{
		Method: method,
		URL:    pollutedURL,
	}

	if method == "POST" || method == "PUT" || method == "PATCH" {
		req.ContentType = "application/x-www-form-urlencoded"
	}

	return d.client.Do(ctx, req)
}

// hasResponseDifference detects if the polluted response differs significantly
// from the baseline response. Differences in status code, body length, or
// body content indicate the server handled the duplicate parameters differently.
func (d *Detector) hasResponseDifference(baseline, polluted *internalhttp.Response) bool {
	if baseline == nil || polluted == nil {
		return false
	}

	// Status code difference is a strong indicator
	if baseline.StatusCode != polluted.StatusCode {
		return true
	}

	// Significant body length difference indicates different processing
	baseLen := len(baseline.Body)
	pollutedLen := len(polluted.Body)

	if baseLen == 0 && pollutedLen == 0 {
		return false
	}

	// If lengths differ by more than 20% and at least 10 bytes, flag it
	if baseLen > 0 {
		diff := pollutedLen - baseLen
		if diff < 0 {
			diff = -diff
		}
		threshold := baseLen / 5 // 20%
		if threshold < 10 {
			threshold = 10
		}
		if diff > threshold {
			return true
		}
	}

	// Direct body content comparison: if the bodies are different at all
	// and the baseline is small enough to compare meaningfully
	if baseLen > 0 && baseLen < 4096 && baseline.Body != polluted.Body {
		return true
	}

	return false
}

// createFinding creates a Finding from a successful HPP detection.
func (d *Detector) createFinding(target, param string, payload hpppayloads.Payload, resp *internalhttp.Response) *core.Finding {
	finding := core.NewFinding("HTTP Parameter Pollution", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf(
		"HTTP Parameter Pollution vulnerability detected in '%s' parameter. "+
			"The server responds differently when duplicate parameters are submitted, "+
			"indicating that parameter handling may be exploitable.",
		param,
	)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "hpp-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Ensure the application handles duplicate HTTP parameters consistently. " +
		"Use the first occurrence of each parameter and reject or ignore subsequent duplicates. " +
		"Validate and sanitize all parameter values on the server side. " +
		"Implement strict input validation that is aware of parameter arrays. " +
		"Consider using a web application firewall (WAF) rule to detect parameter pollution attempts."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-04"}, // Testing for HTTP Parameter Pollution
		[]string{"A03:2025"},     // Injection
		[]string{"CWE-235"},      // Improper Handling of Extra Parameters
	)

	return finding
}
