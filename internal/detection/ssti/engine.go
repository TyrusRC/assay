package ssti

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/payloads/ssti"
)

// detectMathExpression tests for SSTI using mathematical expressions.
// Each probe wraps its math expression with a unique alphanumeric sentinel
// (e.g. "st42..."). A response containing `st42...49st42...` is strong
// evidence that the template engine evaluated the expression in place.
// Incidental "49" / "14" occurrences in the response body (timestamps,
// widths, IDs) no longer produce false positives.
func (d *Detector) detectMathExpression(ctx context.Context, target, param, method string, baseline *baselineResponse) mathDetectionResult {
	result := mathDetectionResult{
		engine: ssti.EngineUnknown,
	}

	// Per-call sentinel — alphanumeric so it survives URL/header encoding
	// and doesn't accidentally trigger any template engine's syntax.
	sentinel := fmt.Sprintf("st%d", time.Now().UnixNano()%1000000000)
	wrap := func(expr string) string { return sentinel + expr + sentinel }
	expect := func(v string) string { return sentinel + v + sentinel }

	// Test mathematical expressions for different template engines
	mathTests := []struct {
		payload  string
		expected string
		engine   ssti.TemplateEngine
	}{
		// Jinja2/Twig/Pebble style
		{wrap("{{7*7}}"), expect("49"), ssti.EngineUnknown},
		{wrap("{{7+7}}"), expect("14"), ssti.EngineUnknown},

		// Freemarker/Thymeleaf/Mako style
		{wrap("${7*7}"), expect("49"), ssti.EngineUnknown},
		{wrap("${7+7}"), expect("14"), ssti.EngineUnknown},

		// ERB style
		{wrap("<%= 7*7 %>"), expect("49"), ssti.EngineERB},
		{wrap("<%= 7+7 %>"), expect("14"), ssti.EngineERB},

		// Velocity style
		{wrap("#set($x=7*7)$x"), expect("49"), ssti.EngineVelocity},

		// Smarty style
		{wrap("{7*7}"), expect("49"), ssti.EngineSmarty},

		// Freemarker numeric
		{wrap("#{7*7}"), expect("49"), ssti.EngineFreemarker},
	}

	for _, test := range mathTests {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		resp, err := d.client.SendPayload(ctx, target, param, test.payload, method)
		if err != nil {
			continue
		}

		// Check if the expected mathematical result appears in the response
		// AND the raw expression is not echoed verbatim (rejects FPs where
		// e.g. a request header value is mirrored into the response body).
		if d.evaluatedMath(resp.Body, test.expected, baseline.body, test.payload) {
			result.detected = true
			result.expression = test.payload
			result.result = test.expected
			result.engine = test.engine
			result.confidence = 0.85

			// Try to fingerprint the specific engine
			fingerprintedEngine := d.fingerprintEngine(ctx, target, param, method)
			if fingerprintedEngine != ssti.EngineUnknown {
				result.engine = fingerprintedEngine
				result.confidence = 0.95
			}

			return result
		}
	}

	return result
}

// detectByError tests for SSTI by analyzing error messages.
func (d *Detector) detectByError(ctx context.Context, target, param, method string) errorDetectionResult {
	result := errorDetectionResult{
		errorPatterns: make([]string, 0),
		engine:        ssti.EngineUnknown,
	}

	// Error-inducing payloads
	errorPayloads := []string{
		"{{",
		"}}",
		"${",
		"<%",
		"{#",
		"{{''.__class__}}",
		"{{undefined_var}}",
		"${undefined}",
		"<%= undefined %>",
		"#set($x=",
	}

	// Engine-specific error patterns
	engineErrors := map[ssti.TemplateEngine][]string{
		ssti.EngineJinja2: {
			"jinja2.exceptions",
			"UndefinedError",
			"TemplateSyntaxError",
			"TemplateAssertionError",
		},
		ssti.EngineTwig: {
			"Twig_Error",
			"Twig\\Error",
			"Twig_Error_Syntax",
			"TwigEnvironment",
		},
		ssti.EngineFreemarker: {
			"freemarker.template",
			"FreeMarkerError",
			"ParseException",
			"InvalidReferenceException",
		},
		ssti.EngineVelocity: {
			"org.apache.velocity",
			"VelocityException",
			"ParseErrorException",
		},
		ssti.EngineThymeleaf: {
			"org.thymeleaf",
			"TemplateProcessingException",
			"TemplateInputException",
		},
		ssti.EngineMako: {
			"mako.exceptions",
			"MakoException",
			"CompileException",
		},
		ssti.EngineSmarty: {
			"Smarty error",
			"SmartyCompilerException",
			"Smarty_Compiler",
		},
		ssti.EngineERB: {
			"ERB::Error",
			"SyntaxError",
			"NameError",
		},
	}

	for _, payload := range errorPayloads {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		resp, err := d.client.SendPayload(ctx, target, param, payload, method)
		if err != nil {
			continue
		}

		// Check for engine-specific error patterns
		for engine, patterns := range engineErrors {
			for _, pattern := range patterns {
				if strings.Contains(resp.Body, pattern) {
					result.errorPatterns = append(result.errorPatterns, pattern)
					result.engine = engine
					result.confidence = 0.9
				}
			}
		}
	}

	return result
}

// fingerprintEngine attempts to identify the specific template engine.
func (d *Detector) fingerprintEngine(ctx context.Context, target, param, method string) ssti.TemplateEngine {
	// Fingerprinting tests based on behavior differences
	fingerprints := []struct {
		payload string
		check   func(response string) bool
		engine  ssti.TemplateEngine
	}{
		// Jinja2: {{7*'7'}} returns '7777777' (string multiplication)
		{
			payload: "{{7*'7'}}",
			check: func(r string) bool {
				return strings.Contains(r, "7777777")
			},
			engine: ssti.EngineJinja2,
		},
		// Twig: {{7*'7'}} returns '49' (numeric)
		{
			payload: "{{7*'7'}}",
			check: func(r string) bool {
				return strings.Contains(r, "49") && !strings.Contains(r, "7777777")
			},
			engine: ssti.EngineTwig,
		},
		// Jinja2: {{config}}
		{
			payload: "{{config}}",
			check: func(r string) bool {
				return strings.Contains(r, "Config") || strings.Contains(r, "SECRET")
			},
			engine: ssti.EngineJinja2,
		},
		// Twig: {{_self}}
		{
			payload: "{{_self}}",
			check: func(r string) bool {
				return strings.Contains(r, "Template") || strings.Contains(r, "__TwigTemplate")
			},
			engine: ssti.EngineTwig,
		},
		// Mako: ${self}
		{
			payload: "${self}",
			check: func(r string) bool {
				return strings.Contains(r, "Namespace") || strings.Contains(r, "mako")
			},
			engine: ssti.EngineMako,
		},
		// Freemarker: ${.version}
		{
			payload: "${.version}",
			check: func(r string) bool {
				// Freemarker version string pattern
				return regexp.MustCompile(`\d+\.\d+\.\d+`).MatchString(r)
			},
			engine: ssti.EngineFreemarker,
		},
	}

	for _, fp := range fingerprints {
		select {
		case <-ctx.Done():
			return ssti.EngineUnknown
		default:
		}

		resp, err := d.client.SendPayload(ctx, target, param, fp.payload, method)
		if err != nil {
			continue
		}

		if fp.check(resp.Body) {
			return fp.engine
		}
	}

	return ssti.EngineUnknown
}

// DetectEngine attempts to detect the template engine without testing for vulnerabilities.
func (d *Detector) DetectEngine(ctx context.Context, target, param, method string) (ssti.TemplateEngine, float64, error) {
	// Try fingerprinting first
	engine := d.fingerprintEngine(ctx, target, param, method)
	if engine != ssti.EngineUnknown {
		return engine, 0.9, nil
	}

	// Try error-based detection
	errorResult := d.detectByError(ctx, target, param, method)
	if errorResult.engine != ssti.EngineUnknown {
		return errorResult.engine, errorResult.confidence, nil
	}

	return ssti.EngineUnknown, 0.0, nil
}
