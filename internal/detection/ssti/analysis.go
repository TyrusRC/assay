package ssti

import (
	"context"
	"fmt"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/ssti"
)

// containsMathResult checks if the response contains the expected mathematical result.
func (d *Detector) containsMathResult(body, expected, baseline string) bool {
	// The result should appear in the response
	if !strings.Contains(body, expected) {
		return false
	}

	// But it should NOT appear in the baseline (to avoid false positives)
	if strings.Contains(baseline, expected) {
		// Check if the count increased
		return strings.Count(body, expected) > strings.Count(baseline, expected)
	}

	return true
}

// isPayloadSuccessful checks if the SSTI payload was successful.
func (d *Detector) isPayloadSuccessful(body string, payload ssti.Payload, baseline *baselineResponse) bool {
	switch payload.DetectionMethod {
	case ssti.MethodMath:
		if payload.ExpectedOutput != "" {
			return d.containsMathResult(body, payload.ExpectedOutput, baseline.body)
		}
		// Check for common math results
		return d.containsMathResult(body, "49", baseline.body) ||
			d.containsMathResult(body, "14", baseline.body)

	case ssti.MethodReflection:
		if payload.ExpectedOutput != "" {
			return strings.Contains(body, payload.ExpectedOutput) &&
				!strings.Contains(baseline.body, payload.ExpectedOutput)
		}
		// Check for reflection patterns not present in baseline
		reflectionPatterns := []string{
			"__class__", "__mro__", "__subclasses__",
			"Template", "Config", "Environment",
		}
		for _, pattern := range reflectionPatterns {
			if strings.Contains(body, pattern) && !strings.Contains(baseline.body, pattern) {
				return true
			}
		}

	case ssti.MethodOutput:
		if payload.ExpectedOutput != "" {
			return strings.Contains(body, payload.ExpectedOutput) &&
				!strings.Contains(baseline.body, payload.ExpectedOutput)
		}
		// Check for command execution patterns not present in baseline
		commandPatterns := []string{
			"uid=", "root:", "www-data", "Process",
		}
		for _, pattern := range commandPatterns {
			if strings.Contains(body, pattern) && !strings.Contains(baseline.body, pattern) {
				return true
			}
		}

	case ssti.MethodError:
		// Check for error patterns
		for _, pattern := range payload.ErrorPatterns {
			if strings.Contains(body, pattern) {
				return true
			}
		}
	}

	return false
}

// createFinding creates a Finding from a successful SSTI test.
func (d *Detector) createFinding(target, param string, payload ssti.Payload, resp *http.Response, engine ssti.TemplateEngine) *core.Finding {
	severity := core.SeverityHigh
	if payload.Type == ssti.TypeRCE {
		severity = core.SeverityCritical
	}

	engineName := string(engine)
	if engine == ssti.EngineUnknown {
		engineName = "unknown"
	}

	finding := core.NewFinding("Server-Side Template Injection (SSTI)", severity)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("SSTI vulnerability in '%s' parameter (detected engine: %s, payload type: %s)",
		param, engineName, payload.Type)
	finding.Evidence = payload.Value
	finding.Tool = "ssti-detector"

	// Set confidence based on payload type
	switch payload.Type {
	case ssti.TypeRCE:
		finding.Confidence = core.ConfidenceConfirmed
	case ssti.TypeDetection, ssti.TypeFingerprint:
		finding.Confidence = core.ConfidenceHigh
	default:
		finding.Confidence = core.ConfidenceMedium
	}

	// Add remediation
	finding.Remediation = "Never pass user input directly to template engines. " +
		"Use a sandbox or restricted execution environment if dynamic templates are required. " +
		"Implement strict input validation and use parameterized templates instead."

	// Add references
	finding.References = []string{
		"https://portswigger.net/web-security/server-side-template-injection",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
		"https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
	}

	// Add metadata
	finding.Metadata["template_engine"] = engineName
	finding.Metadata["payload_type"] = string(payload.Type)
	finding.Metadata["detection_method"] = string(payload.DetectionMethod)

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-18"},       // Server-Side Template Injection
		[]string{"A03:2025"},           // Injection
		[]string{"CWE-94", "CWE-1336"}, // Code Injection, Template Injection
	)

	return finding
}

// VerifyRCE attempts to verify RCE capability after SSTI is confirmed.
func (d *Detector) VerifyRCE(ctx context.Context, target, param, method string, engine ssti.TemplateEngine) (bool, *core.Finding, error) {
	rcePayloads := ssti.GetRCEPayloads()

	// Filter by engine if known
	if engine != ssti.EngineUnknown {
		var filtered []ssti.Payload
		for _, p := range rcePayloads {
			if p.Engine == engine {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) > 0 {
			rcePayloads = filtered
		}
	}

	for _, payload := range rcePayloads {
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		default:
		}

		resp, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
		if err != nil {
			continue
		}

		// Check for command output patterns
		if payload.ExpectedOutput != "" && strings.Contains(resp.Body, payload.ExpectedOutput) {
			finding := d.createFinding(target, param, payload, resp, engine)
			finding.Severity = core.SeverityCritical
			finding.Confidence = core.ConfidenceConfirmed
			finding.Description = fmt.Sprintf("RCE verified via SSTI in '%s' parameter (engine: %s)",
				param, engine)
			return true, finding, nil
		}

		// Generic RCE indicators
		rceIndicators := []string{"uid=", "root:", "www-data", "apache", "nginx"}
		for _, indicator := range rceIndicators {
			if strings.Contains(resp.Body, indicator) {
				finding := d.createFinding(target, param, payload, resp, engine)
				finding.Severity = core.SeverityCritical
				finding.Confidence = core.ConfidenceConfirmed
				return true, finding, nil
			}
		}
	}

	return false, nil, nil
}
