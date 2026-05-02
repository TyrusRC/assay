package emailinj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/emailinj"
)

// Detector performs Email Header Injection vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Email Header Injection Detector.
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
	return "emailinj"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Email Header Injection vulnerability detector using CRLF injection analysis"
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

// DetectionResult contains email header injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a parameter for Email Header Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if param == "" {
		return result, nil
	}

	payloads := emailinj.GetPayloads()

	if opts.IncludeWAFBypass {
		payloads = append(payloads, emailinj.GetWAFBypassPayloads()...)
	}

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response for false positive elimination
	baselineResp, err := d.client.SendPayload(ctx, target, param, "skws_email_baseline@safe.example.com", method)
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

		if d.hasHeaderInjection(resp.Body, baselineBody, payload) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// hasHeaderInjection checks whether the response contains evidence of injected email headers.
// It verifies the marker is present in the response but absent from the baseline.
func (d *Detector) hasHeaderInjection(body, baselineBody string, payload emailinj.Payload) bool {
	if body == "" || payload.Marker == "" {
		return false
	}

	if !strings.Contains(body, payload.Marker) {
		return false
	}

	// Exclude markers already present in the baseline to prevent false positives
	if strings.Contains(baselineBody, payload.Marker) {
		return false
	}

	return true
}

// createFinding creates a Finding from a successful email header injection test.
func (d *Detector) createFinding(target, param string, payload emailinj.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("Email Header Injection", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("Email Header Injection vulnerability in '%s' parameter: CRLF sequences processed as additional email headers",
		param)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s\nMarker found: %s",
		payload.Value, payload.Description, payload.Marker)
	finding.Tool = "emailinj-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Validate and sanitize all user input used in email headers. " +
		"Strip or reject input containing CR (\\r) and LF (\\n) characters. " +
		"Use parameterized email APIs that separate headers from user data. " +
		"Implement allowlists for email address formats. " +
		"Never pass raw user input directly to mail functions."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-10"},
		[]string{"A03:2025"},
		[]string{"CWE-93"},
	)

	return finding
}
