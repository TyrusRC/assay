package loginj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/loginj"
)

// Detector performs log injection vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Log Injection Detector.
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
	return "log-injection"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Log Injection vulnerability detector using CRLF, format string, and JNDI injection analysis"
}

// DetectOptions configures log injection detection behavior.
type DetectOptions struct {
	// MaxPayloads is the maximum number of payloads to test.
	MaxPayloads int
	// IncludeWAFBypass includes WAF bypass payloads.
	IncludeWAFBypass bool
	// Timeout is the timeout for each request.
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

// DetectionResult contains log injection detection results.
type DetectionResult struct {
	// Vulnerable indicates whether a log injection vulnerability was found.
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
}

// injectionHeaders are the headers used to inject payloads.
var injectionHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
}

// Detect tests a target for log injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	if target == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Collect payloads
	payloads := loginj.GetAllPayloads()

	// Filter WAF bypass payloads if not included
	if !opts.IncludeWAFBypass {
		filtered := make([]loginj.Payload, 0, len(payloads))
		for _, p := range payloads {
			if !p.WAFBypass {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	// Deduplicate
	payloads = loginj.DeduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayloadInHeader(ctx, target, "User-Agent", "SKWS/1.0", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	baselineBody := baselineResp.Body

	// Test each payload across injection headers
	for _, payload := range payloads {
		for _, header := range injectionHeaders {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			result.TestedPayloads++

			resp, err := d.client.SendPayloadInHeader(ctx, target, header, payload.Value, method)
			if err != nil {
				continue
			}

			// Check if payload is reflected in response
			if d.isReflected(resp, baselineBody, payload) {
				finding := d.createFinding(target, header, payload, resp)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true

				// Limit findings to avoid excessive testing
				if len(result.Findings) >= 3 {
					return result, nil
				}

				// Move to next payload (don't test same payload on other headers)
				break
			}
		}

		if len(result.Findings) >= 3 {
			break
		}
	}

	return result, nil
}

// isReflected checks if the payload is reflected in the response.
func (d *Detector) isReflected(resp *http.Response, baselineBody string, payload loginj.Payload) bool {
	if resp == nil || resp.Body == "" {
		return false
	}

	// Skip if response body is the same as baseline (no reflection)
	if resp.Body == baselineBody {
		return false
	}

	// Check if the payload value itself is reflected
	if strings.Contains(resp.Body, payload.Value) && !strings.Contains(baselineBody, payload.Value) {
		return true
	}

	// Check for partial reflection indicators based on category
	analysis := d.analyzeBody(resp.Body)
	if analysis.IsVulnerable {
		// Verify it's not in the baseline
		baselineAnalysis := d.analyzeBody(baselineBody)
		if !baselineAnalysis.IsVulnerable {
			return true
		}
	}

	return false
}

// AnalyzeResponse analyzes a response body for log injection indicators.
func (d *Detector) AnalyzeResponse(response string) *AnalysisResult {
	return d.analyzeBody(response)
}

// analyzeBody checks response body for log injection vulnerability indicators.
func (d *Detector) analyzeBody(body string) *AnalysisResult {
	result := &AnalysisResult{}

	if body == "" {
		return result
	}

	// Check for CRLF injection indicators
	if d.hasCRLFIndicators(body) {
		result.IsVulnerable = true
		result.DetectionType = "crlf-injection"
		result.Confidence = 0.8
		return result
	}

	// Check for Log4j JNDI patterns
	if d.hasJNDIPatterns(body) {
		result.IsVulnerable = true
		result.DetectionType = "jndi-injection"
		result.Confidence = 0.9
		return result
	}

	// Check for format string evidence
	if d.hasFormatStringEvidence(body) {
		result.IsVulnerable = true
		result.DetectionType = "format-string"
		result.Confidence = 0.7
		return result
	}

	return result
}

// hasCRLFIndicators checks for CRLF injection indicators in the body.
func (d *Detector) hasCRLFIndicators(body string) bool {
	indicators := []string{
		"\r\nINJECTED",
		"\nINJECTED",
		"INJECTED_LOG_ENTRY",
		"\r\n[INFO]",
		"\r\n[WARN]",
		"\r\n[ERROR]",
		"\r\n[CRITICAL]",
		"\r\n127.0.0.1",
	}

	for _, indicator := range indicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

// hasJNDIPatterns checks for Log4j JNDI lookup patterns in the body.
func (d *Detector) hasJNDIPatterns(body string) bool {
	patterns := []string{
		"${jndi:",
		"${env:",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// hasFormatStringEvidence checks for format string injection evidence.
func (d *Detector) hasFormatStringEvidence(body string) bool {
	patterns := []string{
		"%s%s%s",
		"%x%x%x",
		"%n%n%n",
		"%08x.",
		"%p%p%p",
		"%d%d%d",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// createFinding creates a Finding from a detected log injection vulnerability.
func (d *Detector) createFinding(target, header string, payload loginj.Payload, resp *http.Response) *core.Finding {
	finding := core.NewFinding("Log Injection", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = header
	finding.Description = fmt.Sprintf(
		"Log Injection vulnerability detected via '%s' header. "+
			"The application reflects unsanitized header values, "+
			"allowing an attacker to forge log entries or inject malicious content into logs.",
		header,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}

	finding.Evidence = fmt.Sprintf(
		"Header: %s\nPayload: %s\nCategory: %s\nDescription: %s\nResponse snippet: %s",
		header, payload.Value, payload.Category, payload.Description, body,
	)

	finding.Tool = "loginj-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Sanitize all user-controlled input before writing to log files. " +
		"Strip or encode CR (\\r) and LF (\\n) characters from header values. " +
		"Use structured logging frameworks that separate log metadata from user data. " +
		"Implement input validation to reject requests containing CRLF sequences or JNDI lookups. " +
		"Disable Log4j JNDI lookups if using Java-based logging."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-14"},
		[]string{"A09:2021"},
		[]string{"CWE-117"},
	)

	return finding
}
