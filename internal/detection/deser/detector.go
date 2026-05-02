// Package deser provides insecure deserialization vulnerability detection.
// It supports detection for Java, PHP, Python, and .NET using serialized
// object markers, error-based detection, and status code analysis.
package deser

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/deser"
)

// Detector performs insecure deserialization vulnerability detection.
type Detector struct {
	client        *http.Client
	verbose       bool
	errorPatterns []*regexp.Regexp
}

// deserPayload is an internal payload representation used during detection.
type deserPayload struct {
	Value       string
	Technique   deser.Technique
	Variant     deser.Variant
	Description string
	WAFBypass   bool
}

// New creates a new Insecure Deserialization Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client: client,
	}
	d.initErrorPatterns()
	return d
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "deserialization"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Insecure Deserialization vulnerability detector using serialized object markers and error-based detection across Java, PHP, Python, and .NET"
}

// initErrorPatterns initializes platform-specific error patterns.
func (d *Detector) initErrorPatterns() {
	d.errorPatterns = []*regexp.Regexp{
		// Java deserialization errors
		regexp.MustCompile(`(?i)java\.io\.InvalidClassException`),
		regexp.MustCompile(`(?i)java\.lang\.ClassNotFoundException`),
		regexp.MustCompile(`(?i)java\.io\.StreamCorruptedException`),
		regexp.MustCompile(`(?i)ObjectInputStream`),
		regexp.MustCompile(`(?i)java\.io\.NotSerializableException`),
		regexp.MustCompile(`(?i)ClassCastException.*deserializ`),
		regexp.MustCompile(`(?i)java\.io\.EOFException.*ObjectInput`),

		// PHP deserialization errors
		regexp.MustCompile(`(?i)unserialize\(\).*[Ee]rror`),
		regexp.MustCompile(`(?i)__wakeup\(\)`),
		regexp.MustCompile(`(?i)__destruct\(\)`),
		regexp.MustCompile(`(?i)PHP Fatal error.*unserialize`),
		regexp.MustCompile(`(?i)allowed classes.*unserialize`),

		// Python deserialization errors
		regexp.MustCompile(`(?i)_pickle\.UnpicklingError`),
		regexp.MustCompile(`(?i)pickle\.UnpicklingError`),
		regexp.MustCompile(`(?i)could not.*unpickle`),
		regexp.MustCompile(`(?i)invalid load key`),
		regexp.MustCompile(`(?i)yaml\.constructor\.ConstructorError`),

		// .NET deserialization errors
		regexp.MustCompile(`(?i)System\.Runtime\.Serialization\.SerializationException`),
		regexp.MustCompile(`(?i)ViewState.*MAC.*validation.*failed`),
		regexp.MustCompile(`(?i)BinaryFormatter.*deserializ`),
		regexp.MustCompile(`(?i)TypeInitializationException.*serializ`),
		regexp.MustCompile(`(?i)ObjectStateFormatter.*error`),

		// Generic deserialization errors
		regexp.MustCompile(`(?i)deserializ.*error`),
		regexp.MustCompile(`(?i)invalid.*serializ.*data`),
		regexp.MustCompile(`(?i)malformed.*serializ`),
	}
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
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
	}
}

// DetectionResult contains deserialization detection results.
type DetectionResult struct {
	// Vulnerable indicates whether a deserialization vulnerability was found.
	Vulnerable bool
	// Findings contains the discovered vulnerabilities.
	Findings []*core.Finding
	// TestedPayloads is the number of payloads tested.
	TestedPayloads int
}

// AnalysisResult contains the result of response analysis.
type AnalysisResult struct {
	// IsVulnerable indicates whether the response shows vulnerability indicators.
	IsVulnerable bool
	// DetectionType describes the detection method that triggered.
	DetectionType string
	// Confidence is the confidence score from 0.0 to 1.0.
	Confidence float64
	// Evidence contains the matched error pattern.
	Evidence string
}

// Detect tests a parameter for insecure deserialization vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if param == "" {
		return result, nil
	}

	// Collect payloads from all variants
	payloads := d.collectPayloads(opts)

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "baseline_test_value", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}
	baselineStatus := baselineResp.StatusCode

	// Test each payload
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

		// Check for error-based detection
		analysis := d.AnalyzeResponse(resp.Body)
		if analysis.IsVulnerable {
			finding := d.createFinding(target, param, payload, resp, analysis.DetectionType)
			finding.Evidence = analysis.Evidence
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}

		// Check for status code change indicating processing of serialized data
		if d.hasStatusCodeChange(baselineStatus, resp.StatusCode) {
			analysis := d.AnalyzeResponse(resp.Body)
			if analysis.IsVulnerable {
				finding := d.createFinding(target, param, payload, resp, "status-code-differential")
				finding.Evidence = fmt.Sprintf("Status code changed from %d to %d. %s",
					baselineStatus, resp.StatusCode, analysis.Evidence)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return result, nil
			}
		}
	}

	return result, nil
}

// AnalyzeResponse analyzes an HTTP response for deserialization error indicators.
func (d *Detector) AnalyzeResponse(response string) *AnalysisResult {
	result := &AnalysisResult{
		IsVulnerable: false,
	}

	if response == "" {
		return result
	}

	for _, pattern := range d.errorPatterns {
		if pattern.MatchString(response) {
			result.IsVulnerable = true
			result.DetectionType = "error-based"
			result.Evidence = extractMatch(pattern, response)
			result.Confidence = 0.9
			return result
		}
	}

	return result
}

// collectPayloads gathers payloads from all variants and applies options.
func (d *Detector) collectPayloads(opts DetectOptions) []deserPayload {
	var payloads []deserPayload

	variants := []deser.Variant{deser.Java, deser.PHP, deser.Python, deser.DotNet, deser.Generic}
	for _, variant := range variants {
		for _, p := range deser.GetPayloads(variant) {
			if !opts.IncludeWAFBypass && p.WAFBypass {
				continue
			}
			payloads = append(payloads, deserPayload{
				Value:       p.Value,
				Technique:   p.Technique,
				Variant:     p.Variant,
				Description: p.Description,
				WAFBypass:   p.WAFBypass,
			})
		}
	}

	payloads = d.deduplicatePayloads(payloads)

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	return payloads
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []deserPayload) []deserPayload {
	seen := make(map[string]bool)
	var unique []deserPayload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// hasStatusCodeChange checks if the response status code indicates deserialization processing.
func (d *Detector) hasStatusCodeChange(baseline, current int) bool {
	// A 500 error when baseline is 200 may indicate the server tried to deserialize
	if baseline >= 200 && baseline < 300 && current >= 500 {
		return true
	}
	return false
}

// createFinding creates a Finding from a successful deserialization test.
func (d *Detector) createFinding(target, param string, payload deserPayload, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("Insecure Deserialization", core.SeverityCritical)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("%s Insecure Deserialization vulnerability in '%s' parameter (Platform: %s, Technique: %s)",
		detectionType, param, payload.Variant, payload.Technique)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "deser-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Never deserialize untrusted data. " +
		"Use safe serialization formats like JSON instead of native serialization. " +
		"If deserialization is required, use allowlists for permitted classes. " +
		"Implement integrity checks (digital signatures) on serialized data. " +
		"Monitor deserialization operations and log failures. " +
		"Apply the principle of least privilege to deserialization contexts."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},
		[]string{"A08:2025"},
		[]string{"CWE-502"},
	)

	return finding
}

// extractMatch extracts the matching portion from the response.
func extractMatch(pattern *regexp.Regexp, response string) string {
	match := pattern.FindString(response)
	if len(match) > 100 {
		return match[:100] + "..."
	}
	return match
}
