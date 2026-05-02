package ssti

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/analysis"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/ssti"
)

// analysisStripEchoFn is an indirection over analysis.StripEcho so this
// package can substitute a cheaper/mock version in tests if needed.
var analysisStripEchoFn = analysis.StripEcho

// containsMathResult checks if the response contains the expected mathematical
// result — signalling real template-engine evaluation rather than payload
// reflection. When the raw expression is known, a response that echoes the
// expression literally is rejected as a false positive (see evaluatedMath).
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

// evaluatedMath is like containsMathResult but additionally rejects responses
// that echo the raw expression verbatim. A server that reflects `#{7*7}` into
// its response is NOT evaluating the template — it's just echoing user input.
// This kills a huge class of false positives (Origin headers echoed into HTML,
// CORS responses, debug pages) where the page also happens to contain the
// expected result (`49`) from unrelated content (pixel sizes, IDs, etc.).
func (d *Detector) evaluatedMath(body, expected, baseline, expression string) bool {
	if expression != "" && strings.Contains(body, expression) {
		return false
	}
	return d.containsMathResult(body, expected, baseline)
}

// isPayloadSuccessful checks if the SSTI payload was successful.
//
// For MethodMath, MethodReflection and MethodOutput we apply two
// anti-FP guards:
//  1. evaluatedMath rejects responses where the raw expression is echoed
//     verbatim (reflection, not evaluation).
//  2. If ExpectedOutput appears as a substring of the raw payload
//     itself (e.g. expected="Runtime" in payload "$class.inspect(
//     'java.lang.Runtime')"), the marker cannot reliably prove
//     evaluation — every echoing app trips it. Skip that payload.
func (d *Detector) isPayloadSuccessful(body string, payload ssti.Payload, baseline *baselineResponse) bool {
	selfEchoing := func(marker string) bool {
		return marker != "" && payload.Value != "" && strings.Contains(payload.Value, marker)
	}

	switch payload.DetectionMethod {
	case ssti.MethodMath:
		if payload.ExpectedOutput != "" {
			if selfEchoing(payload.ExpectedOutput) {
				return false
			}
			return d.evaluatedMath(body, payload.ExpectedOutput, baseline.body, payload.Value)
		}
		// Check for common math results — but reject if the raw payload
		// expression was echoed back verbatim.
		return d.evaluatedMath(body, "49", baseline.body, payload.Value) ||
			d.evaluatedMath(body, "14", baseline.body, payload.Value)

	case ssti.MethodReflection:
		if payload.ExpectedOutput != "" {
			if selfEchoing(payload.ExpectedOutput) {
				return false
			}
			return d.evaluatedMath(body, payload.ExpectedOutput, baseline.body, payload.Value)
		}
		// Check for reflection patterns not present in baseline — strip
		// echo first so that a payload containing e.g. "Template" in
		// its own body doesn't match against itself.
		stripped := stripPayloadEcho(body, payload.Value)
		reflectionPatterns := []string{
			"__class__", "__mro__", "__subclasses__",
			"Template", "Config", "Environment",
		}
		for _, pattern := range reflectionPatterns {
			if selfEchoing(pattern) {
				continue
			}
			if strings.Contains(stripped, pattern) && !strings.Contains(baseline.body, pattern) {
				return true
			}
		}

	case ssti.MethodOutput:
		if payload.ExpectedOutput != "" {
			if selfEchoing(payload.ExpectedOutput) {
				return false
			}
			return d.evaluatedMath(body, payload.ExpectedOutput, baseline.body, payload.Value)
		}
		// Check for command execution patterns not present in baseline.
		stripped := stripPayloadEcho(body, payload.Value)
		commandPatterns := []string{
			"uid=", "root:", "www-data", "Process",
		}
		for _, pattern := range commandPatterns {
			if selfEchoing(pattern) {
				continue
			}
			if strings.Contains(stripped, pattern) && !strings.Contains(baseline.body, pattern) {
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

// stripPayloadEcho thin-wraps analysis.StripEcho so every call site in
// this package uses the same encoding-aware stripping logic.
func stripPayloadEcho(body, payload string) string {
	return analysisStripEchoFn(body, payload)
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
