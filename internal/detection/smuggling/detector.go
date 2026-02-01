// Package smuggling provides HTTP Request Smuggling vulnerability detection.
//
// HTTP Request Smuggling exploits discrepancies in how front-end and back-end
// servers parse HTTP request boundaries, allowing attackers to "smuggle" malicious
// requests that bypass security controls.
//
// The detector tests for three main vulnerability types:
//   - CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
//   - TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
//   - TE.TE: Both use Transfer-Encoding but process obfuscation differently
//
// Detection uses timing differentials and response comparison since standard
// http.Client normalizes headers, making raw socket communication necessary.
//
// OWASP References:
//   - WSTG-INPV-15: Testing for HTTP Request Smuggling
//   - CWE-444: Inconsistent Interpretation of HTTP Requests
package smuggling

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// Detector detects HTTP Request Smuggling vulnerabilities.
type Detector struct {
	config *Config
}

// NewDetector creates a new HTTP Request Smuggling detector with default config.
func NewDetector() *Detector {
	return &Detector{
		config: DefaultConfig(),
	}
}

// NewDetectorWithConfig creates a new detector with the specified config.
func NewDetectorWithConfig(config *Config) *Detector {
	return &Detector{
		config: config,
	}
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "http-request-smuggling"
}

// Description returns a description of what this detector does.
func (d *Detector) Description() string {
	return "HTTP Request Smuggling detector using timing and differential analysis to detect CL.TE, TE.CL, and TE.TE vulnerabilities"
}

// OWASPMapping returns the OWASP framework references for this vulnerability.
func (d *Detector) OWASPMapping() OWASPMapping {
	return OWASPMapping{
		WSTG:     []string{"WSTG-INPV-15"},
		Top10:    []string{"A05:2021-Security Misconfiguration"},
		APITop10: []string{"API8:2023-Security Misconfiguration"},
		CWE:      []string{"CWE-444"},
	}
}

// Detect runs all smuggling detection tests against the target.
func (d *Detector) Detect(ctx context.Context, target string, path string) []*Result {
	var results []*Result

	// Run each detection type
	clteResult := d.DetectCLTE(ctx, target, path)
	results = append(results, clteResult)

	teclResult := d.DetectTECL(ctx, target, path)
	results = append(results, teclResult)

	teteResult := d.DetectTETE(ctx, target, path)
	results = append(results, teteResult)

	return results
}

// DetectCLTE tests for CL.TE (Content-Length wins, Transfer-Encoding ignored by frontend).
func (d *Detector) DetectCLTE(ctx context.Context, target string, path string) *Result {
	result := &Result{
		Type: TypeCLTE,
	}

	host, port, err := ExtractHostPort(target)
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to parse target: %v", err)
		return result
	}
	addr := net.JoinHostPort(host, port)

	// First, get baseline timing with normal request
	baselineReq := BuildBaselineRequest(host, path)
	_, baselineDuration, err := SendRawRequest(ctx, addr, baselineReq, d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("Baseline request failed: %v", err)
		return result
	}

	// Send CL.TE probe
	probeReq := BuildCLTEPayload(host, path, int(d.config.TimingThreshold.Seconds()))
	result.Request = probeReq

	probeResp, probeDuration, err := SendRawRequest(ctx, addr, probeReq, d.config.Timeout+d.config.TimingThreshold)
	if err != nil {
		// Timeout might indicate vulnerability (backend waiting for more data)
		if isTimeoutError(err) {
			result.Vulnerable = true
			result.Confidence = 0.7
			result.Evidence = "Request timed out, suggesting backend is waiting for more chunked data"
			result.FrontendBehavior = "Uses Content-Length"
			result.BackendBehavior = "Uses Transfer-Encoding (chunked)"
			return result
		}
		result.Evidence = fmt.Sprintf("Probe request failed: %v", err)
		return result
	}

	result.Response = probeResp

	// Analyze timing differential
	diff, significant := CalculateTimingDifferential(baselineDuration, probeDuration, d.config.TimingThreshold)
	result.TimingDiff = diff

	if significant {
		result.Vulnerable = true
		result.Confidence = 0.85
		result.Evidence = fmt.Sprintf("Timing differential of %v detected (threshold: %v)", diff, d.config.TimingThreshold)
		result.FrontendBehavior = "Uses Content-Length"
		result.BackendBehavior = "Uses Transfer-Encoding (chunked)"
	}

	return result
}

// DetectTECL tests for TE.CL (Transfer-Encoding wins, Content-Length ignored by frontend).
func (d *Detector) DetectTECL(ctx context.Context, target string, path string) *Result {
	result := &Result{
		Type: TypeTECL,
	}

	host, port, err := ExtractHostPort(target)
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to parse target: %v", err)
		return result
	}
	addr := net.JoinHostPort(host, port)

	// Get baseline timing
	baselineReq := BuildBaselineRequest(host, path)
	_, baselineDuration, err := SendRawRequest(ctx, addr, baselineReq, d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("Baseline request failed: %v", err)
		return result
	}

	// Send TE.CL probe
	probeReq := BuildTECLPayload(host, path, int(d.config.TimingThreshold.Seconds()))
	result.Request = probeReq

	probeResp, probeDuration, err := SendRawRequest(ctx, addr, probeReq, d.config.Timeout+d.config.TimingThreshold)
	if err != nil {
		if isTimeoutError(err) {
			result.Vulnerable = true
			result.Confidence = 0.7
			result.Evidence = "Request timed out, suggesting backend is waiting for Content-Length bytes"
			result.FrontendBehavior = "Uses Transfer-Encoding (chunked)"
			result.BackendBehavior = "Uses Content-Length"
			return result
		}
		result.Evidence = fmt.Sprintf("Probe request failed: %v", err)
		return result
	}

	result.Response = probeResp

	// Analyze timing differential
	diff, significant := CalculateTimingDifferential(baselineDuration, probeDuration, d.config.TimingThreshold)
	result.TimingDiff = diff

	if significant {
		result.Vulnerable = true
		result.Confidence = 0.85
		result.Evidence = fmt.Sprintf("Timing differential of %v detected (threshold: %v)", diff, d.config.TimingThreshold)
		result.FrontendBehavior = "Uses Transfer-Encoding (chunked)"
		result.BackendBehavior = "Uses Content-Length"
	}

	return result
}

// DetectTETE tests for TE.TE (obfuscated Transfer-Encoding) vulnerabilities.
func (d *Detector) DetectTETE(ctx context.Context, target string, path string) *Result {
	result := &Result{
		Type: TypeTETE,
	}

	host, port, err := ExtractHostPort(target)
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to parse target: %v", err)
		return result
	}
	addr := net.JoinHostPort(host, port)

	// Test various TE obfuscation techniques
	payloads := BuildTETEPayloads(host, path, int(d.config.TimingThreshold.Seconds()))

	var detectedObfuscation string
	var maxDiff time.Duration

	// Get baseline
	baselineReq := BuildBaselineRequest(host, path)
	baselineResp, baselineDuration, err := SendRawRequest(ctx, addr, baselineReq, d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("Baseline request failed: %v", err)
		return result
	}

	baselineStatus := extractStatusCode(baselineResp)

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			result.Evidence = "Context cancelled during detection"
			return result
		default:
		}

		probeResp, probeDuration, err := SendRawRequest(ctx, addr, payload, d.config.Timeout+d.config.TimingThreshold)
		if err != nil {
			if isTimeoutError(err) {
				result.Vulnerable = true
				result.Confidence = 0.7
				result.Evidence = "TE obfuscation caused timeout"
				result.Request = payload
				return result
			}
			continue
		}

		probeStatus := extractStatusCode(probeResp)

		// Check for response difference
		if probeStatus != baselineStatus && probeStatus >= 400 {
			result.Vulnerable = true
			result.Confidence = 0.75
			result.Evidence = fmt.Sprintf("TE obfuscation caused status change: %d -> %d", baselineStatus, probeStatus)
			result.Request = payload
			result.Response = probeResp
			return result
		}

		// Check timing
		diff, significant := CalculateTimingDifferential(baselineDuration, probeDuration, d.config.TimingThreshold)
		if significant && diff > maxDiff {
			maxDiff = diff
			detectedObfuscation = "TE obfuscation variant"
			result.Request = payload
			result.Response = probeResp
		}
	}

	if maxDiff > d.config.TimingThreshold {
		result.Vulnerable = true
		result.Confidence = 0.8
		result.Evidence = fmt.Sprintf("Timing differential of %v with %s", maxDiff, detectedObfuscation)
		result.TimingDiff = maxDiff
	}

	return result
}

// CreateFinding creates a core.Finding from a smuggling Result.
func (d *Detector) CreateFinding(targetURL string, result *Result) *core.Finding {
	if !result.Vulnerable {
		return nil
	}

	mapping := d.OWASPMapping()
	severity := core.SeverityHigh

	// CL.TE and TE.CL are typically high severity
	// TE.TE can vary based on the specific obfuscation
	if result.Type == TypeTETE && result.Confidence < 0.8 {
		severity = core.SeverityMedium
	}

	finding := core.NewFinding("http-request-smuggling", severity)
	finding.Title = fmt.Sprintf("HTTP Request Smuggling (%s)", result.Type.String())
	finding.Description = fmt.Sprintf(
		"HTTP Request Smuggling vulnerability detected. Type: %s. "+
			"Frontend behavior: %s. Backend behavior: %s. %s",
		result.Type.String(),
		result.FrontendBehavior,
		result.BackendBehavior,
		result.Evidence,
	)
	finding.URL = targetURL
	finding.Evidence = result.Evidence
	finding.Request = result.Request
	finding.Response = result.Response
	finding.Confidence = confidenceFromFloat(result.Confidence)

	finding.WithOWASPMapping(mapping.WSTG, mapping.Top10, mapping.CWE)

	finding.Remediation = "Ensure consistent parsing of Content-Length and Transfer-Encoding headers " +
		"between frontend and backend servers. Normalize ambiguous requests. " +
		"Consider using HTTP/2 end-to-end which is not vulnerable to request smuggling."

	finding.References = []string{
		"https://portswigger.net/web-security/request-smuggling",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Incoming_Requests",
		"https://cwe.mitre.org/data/definitions/444.html",
	}

	finding.Metadata = map[string]interface{}{
		"smuggling_type": result.Type.String(),
		"timing_diff_ms": result.TimingDiff.Milliseconds(),
		"frontend":       result.FrontendBehavior,
		"backend":        result.BackendBehavior,
	}

	return finding
}
