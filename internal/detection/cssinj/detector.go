package cssinj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/cssinj"
)

// Detector performs CSS Injection vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new CSS Injection Detector.
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
	return "cssinj"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "CSS Injection vulnerability detector using expression(), url(), and @import analysis"
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
		MaxPayloads:      20,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
	}
}

// DetectionResult contains CSS injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a parameter for CSS Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if param == "" {
		return result, nil
	}

	payloads := cssinj.GetPayloads()

	if opts.IncludeWAFBypass {
		payloads = append(payloads, cssinj.GetWAFBypassPayloads()...)
	}

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response for false positive elimination
	baselineResp, err := d.client.SendPayload(ctx, target, param, "skws_css_baseline_safe", method)
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

		if d.isReflected(resp.Body, baselineBody, payload) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// isReflected checks whether the CSS payload marker appears in the response body
// but was not already present in the baseline response.
func (d *Detector) isReflected(body, baselineBody string, payload cssinj.Payload) bool {
	if body == "" || payload.Marker == "" {
		return false
	}

	if !strings.Contains(body, payload.Marker) {
		return false
	}

	// Exclude markers that already appear in the baseline to prevent false positives
	if strings.Contains(baselineBody, payload.Marker) {
		return false
	}

	return true
}

// createFinding creates a Finding from a successful CSS injection test.
func (d *Detector) createFinding(target, param string, payload cssinj.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("CSS Injection", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("CSS Injection vulnerability in '%s' parameter: injected CSS payload reflected unfiltered in response",
		param)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s\nMarker found in response: %s",
		payload.Value, payload.Description, payload.Marker)
	finding.Tool = "cssinj-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Sanitize user input before reflecting in CSS contexts. " +
		"Use allowlists for CSS values (e.g., only permit known-safe color names or hex codes). " +
		"Avoid reflecting user input inside style tags or style attributes. " +
		"Implement Content Security Policy (CSP) with strict style-src directives."

	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-05"},
		[]string{"A03:2025"},
		[]string{"CWE-1236"},
	)

	return finding
}
