package protopollution

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/protopollution"
)

// errorPatterns matches response content that indicates prototype pollution
// was processed by the server, such as TypeError or property assignment errors.
var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Cannot set propert`),
	regexp.MustCompile(`(?i)Cannot read propert`),
	regexp.MustCompile(`(?i)prototype pollution`),
	regexp.MustCompile(`(?i)Object\.prototype`),
	regexp.MustCompile(`(?i)__proto__`),
	regexp.MustCompile(`(?i)TypeError.*prototype`),
	regexp.MustCompile(`(?i)constructor\.prototype`),
	regexp.MustCompile(`(?i)Prototype of.*is not`),
}

// Detector performs Prototype Pollution vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Prototype Pollution Detector.
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
	return "protopollution"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Prototype Pollution vulnerability detector using query parameter, JSON body, and dot notation injection techniques"
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

// DetectionResult contains prototype pollution detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a parameter for Prototype Pollution vulnerabilities.
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
func (d *Detector) gatherPayloads(opts DetectOptions) []protopollution.Payload {
	payloads := protopollution.GetPayloads()

	if !opts.IncludeWAFBypass {
		var filtered []protopollution.Payload
		for _, p := range payloads {
			if !p.WAFBypass {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	return d.deduplicatePayloads(payloads)
}

// analyzeResponse checks if the injected response shows signs of prototype pollution.
func (d *Detector) analyzeResponse(baseline, injected, payload string) bool {
	if baseline == "" && injected == "" {
		return false
	}

	// Check for error messages indicating prototype manipulation
	for _, pattern := range errorPatterns {
		if pattern.MatchString(injected) && !pattern.MatchString(baseline) {
			return true
		}
	}

	// Check if the marker value "skws" appeared in response when it was not in baseline
	if strings.Contains(payload, "skws") {
		if strings.Contains(injected, "skws") && !strings.Contains(baseline, "skws") {
			return true
		}
	}

	// Check if __proto__ key appeared in JSON response
	if strings.Contains(injected, "__proto__") && !strings.Contains(baseline, "__proto__") {
		return true
	}

	return false
}

// deduplicatePayloads removes duplicate payloads by value.
func (d *Detector) deduplicatePayloads(payloads []protopollution.Payload) []protopollution.Payload {
	seen := make(map[string]bool)
	var unique []protopollution.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful prototype pollution test.
func (d *Detector) createFinding(target, param string, payload protopollution.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("Prototype Pollution", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("Prototype Pollution vulnerability in '%s' parameter (Technique: %s)",
		param, payload.Technique)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "protopollution-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Freeze the Object prototype using Object.freeze(Object.prototype). " +
		"Use Map objects instead of plain objects for key-value storage. " +
		"Validate and sanitize all user input before merging into objects. " +
		"Use schema validation to reject __proto__, constructor, and prototype keys. " +
		"Avoid recursive merge functions that do not filter prototype properties."

	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-06"},
		[]string{"A03:2025"},
		[]string{"CWE-1321"},
	)

	return finding
}
