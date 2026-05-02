package htmlinj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/htmlinj"
)

// Detector performs HTML Injection vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new HTML Injection Detector.
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
	return "htmlinj"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "HTML Injection vulnerability detector using tag reflection analysis"
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

// DetectionResult contains HTML injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a parameter for HTML Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if param == "" {
		return result, nil
	}

	payloads := htmlinj.GetPayloads()

	if opts.IncludeWAFBypass {
		payloads = append(payloads, htmlinj.GetWAFBypassPayloads()...)
	}

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response to ensure the target is reachable
	_, err := d.client.SendPayload(ctx, target, param, "skws_baseline_safe", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

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

		if d.isReflected(resp.Body, payload) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// isReflected checks whether the payload marker appears unencoded in the response body.
func (d *Detector) isReflected(body string, payload htmlinj.Payload) bool {
	if body == "" || payload.Marker == "" {
		return false
	}
	return strings.Contains(body, payload.Marker)
}

// createFinding creates a Finding from a successful HTML injection test.
func (d *Detector) createFinding(target, param string, payload htmlinj.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("HTML Injection", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("HTML Injection vulnerability in '%s' parameter: injected HTML tag reflected unencoded in response",
		param)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s\nMarker found in response: %s",
		payload.Value, payload.Description, payload.Marker)
	finding.Tool = "htmlinj-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Encode all user input before reflecting in HTML responses. " +
		"Use context-aware output encoding (HTML entity encoding for HTML context). " +
		"Implement Content Security Policy (CSP) headers. " +
		"Use templating engines with auto-escaping enabled."

	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-03"},
		[]string{"A03:2025"},
		[]string{"CWE-79"},
	)

	return finding
}
