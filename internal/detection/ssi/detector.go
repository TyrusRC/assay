package ssi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/ssi"
)

// Detector performs SSI Injection vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new SSI Injection Detector.
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
	return "ssi"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "SSI Injection vulnerability detector using exec, include, and echo directive analysis"
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

// DetectionResult contains SSI injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a parameter for SSI Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if param == "" {
		return result, nil
	}

	payloads := ssi.GetPayloads()

	if opts.IncludeWAFBypass {
		payloads = append(payloads, ssi.GetWAFBypassPayloads()...)
	}

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "skws_ssi_baseline_safe", method)
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

		if d.hasSSIExecution(resp.Body, baselineBody, payload) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// hasSSIExecution checks whether the response contains evidence of SSI directive execution.
// It verifies the marker is present in the payload response but absent from the baseline.
func (d *Detector) hasSSIExecution(body, baselineBody string, payload ssi.Payload) bool {
	if body == "" || payload.Marker == "" {
		return false
	}

	// The marker must appear in the response
	if !strings.Contains(body, payload.Marker) {
		return false
	}

	// The marker must NOT already be present in the baseline (to avoid false positives)
	if strings.Contains(baselineBody, payload.Marker) {
		return false
	}

	return true
}

// createFinding creates a Finding from a successful SSI injection test.
func (d *Detector) createFinding(target, param string, payload ssi.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("SSI Injection", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("SSI Injection vulnerability in '%s' parameter: server processed SSI directive from user input",
		param)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s\nMarker found: %s",
		payload.Value, payload.Description, payload.Marker)
	finding.Tool = "ssi-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Disable SSI processing on pages that include user input. " +
		"Sanitize all user input by removing or encoding SSI directive syntax (<!--# -->). " +
		"Use allowlists for valid inputs. " +
		"Configure the web server to disable SSI on dynamic content. " +
		"Apply least privilege principle for the web server process."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-08"},
		[]string{"A03:2025"},
		[]string{"CWE-97"},
	)

	return finding
}
