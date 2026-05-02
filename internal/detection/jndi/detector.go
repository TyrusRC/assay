// Package jndi provides detection for Log4Shell/JNDI Injection vulnerabilities.
package jndi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/jndi"
)

// Detector performs JNDI Injection / Log4Shell detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new JNDI Injection Detector.
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

// DetectOptions configures JNDI detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
	CallbackHost     string   // OOB callback host for detection
	TestHeaders      bool     // Test via HTTP headers
	TestParams       bool     // Test via query parameters
	Params           []string // Specific parameters to test
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		TestHeaders:      true,
		TestParams:       true,
	}
}

// DetectionResult contains JNDI detection results.
type DetectionResult struct {
	Vulnerable      bool
	Findings        []*core.Finding
	TestedPayloads  int
	TestedHeaders   []string
	TestedParams    []string
	DetectionMethod string
}

// jndiErrorPatterns are error patterns indicating JNDI processing.
var jndiErrorPatterns = []string{
	"javax.naming.NamingException",
	"com.sun.jndi.ldap",
	"com.sun.jndi.rmi",
	"JNDI lookup",
	"jndi lookup",
	"InitialContext",
	"log4j",
	"Log4j",
	"JndiLookup",
	"JMSAppender",
	"lookup failed",
	"naming exception",
}

// Detect checks for JNDI Injection / Log4Shell vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		TestedHeaders: make([]string, 0),
		TestedParams:  make([]string, 0),
	}

	// Generate payloads with callback host
	callbackHost := opts.CallbackHost
	if callbackHost == "" {
		callbackHost = "log4j.callback.invalid"
	}

	payloads := d.generatePayloads(callbackHost, opts)

	// Get baseline response
	baselineResp, err := d.client.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test via HTTP headers
	if opts.TestHeaders {
		if err := d.testHeaders(ctx, target, payloads, baselineResp, result); err != nil {
			return result, err
		}
		if result.Vulnerable {
			return result, nil
		}
	}

	// Test via query parameters
	if opts.TestParams && len(opts.Params) > 0 {
		if err := d.testParams(ctx, target, payloads, baselineResp, opts.Params, result); err != nil {
			return result, err
		}
	}

	return result, nil
}

// testHeaders tests JNDI payloads via HTTP headers.
func (d *Detector) testHeaders(ctx context.Context, target string, payloads []string, baseline *http.Response, result *DetectionResult) error {
	headers := jndi.GetTargetHeaders()

	for _, header := range headers {
		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			result.TestedPayloads++
			result.TestedHeaders = append(result.TestedHeaders, header)

			// Send request with JNDI payload in header
			req := &http.Request{
				Method:  "GET",
				URL:     target,
				Headers: map[string]string{header: payload},
			}

			resp, err := d.client.Do(ctx, req)
			if err != nil {
				continue
			}

			// Check for error-based detection
			if d.hasJNDIError(resp.Body) && !d.hasJNDIError(baseline.Body) {
				result.DetectionMethod = "error-based"
				finding := d.createFinding(target, header, "header", payload, resp)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return nil
			}
		}
	}

	return nil
}

// testParams tests JNDI payloads via query parameters.
func (d *Detector) testParams(ctx context.Context, target string, payloads []string, baseline *http.Response, params []string, result *DetectionResult) error {
	for _, param := range params {
		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			result.TestedPayloads++
			result.TestedParams = append(result.TestedParams, param)

			resp, err := d.client.SendPayload(ctx, target, param, payload, "GET")
			if err != nil {
				continue
			}

			// Check for error-based detection
			if d.hasJNDIError(resp.Body) && !d.hasJNDIError(baseline.Body) {
				result.DetectionMethod = "error-based"
				finding := d.createFinding(target, param, "parameter", payload, resp)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return nil
			}
		}
	}

	return nil
}

// generatePayloads generates JNDI payloads with the callback host inserted.
func (d *Detector) generatePayloads(callbackHost string, opts DetectOptions) []string {
	srcPayloads := jndi.GetPayloads()
	if opts.IncludeWAFBypass {
		srcPayloads = append(srcPayloads, jndi.GetWAFBypassPayloads()...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var payloads []string
	for _, p := range srcPayloads {
		resolved := strings.ReplaceAll(p.Value, "{CALLBACK}", callbackHost)
		if !seen[resolved] {
			seen[resolved] = true
			payloads = append(payloads, resolved)
		}
	}

	// Limit
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	return payloads
}

// hasJNDIError checks if the response contains JNDI error patterns.
func (d *Detector) hasJNDIError(body string) bool {
	lowerBody := strings.ToLower(body)
	for _, pattern := range jndiErrorPatterns {
		if strings.Contains(lowerBody, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// createFinding creates a Finding from a detected JNDI injection.
func (d *Detector) createFinding(target, injPoint, injType, payload string, resp *http.Response) *core.Finding {
	finding := core.NewFinding("JNDI Injection (Log4Shell)", core.SeverityCritical)
	finding.URL = target
	finding.Parameter = injPoint
	finding.Description = fmt.Sprintf(
		"JNDI Injection (Log4Shell) detected via %s '%s'. "+
			"The application processes JNDI lookup expressions from user input, "+
			"allowing remote code execution through Log4j2 (CVE-2021-44228, CVE-2021-45046).",
		injType, injPoint,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("Injection point: %s (%s)\nPayload: %s\nResponse snippet: %s",
		injPoint, injType, payload, body)
	finding.Tool = "jndi-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Upgrade Log4j2 to version 2.17.0 or later immediately. " +
		"Set log4j2.formatMsgNoLookups=true as a temporary mitigation. " +
		"Remove JndiLookup class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class. " +
		"Implement WAF rules to block JNDI patterns. " +
		"Restrict outbound network access from application servers."

	finding.References = []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
	}

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},       // Testing for Code Injection
		[]string{"A06:2025"},           // Vulnerable and Outdated Components
		[]string{"CWE-917", "CWE-502"}, // Expression Language Injection, Deserialization
	)

	return finding
}
