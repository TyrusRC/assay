// Package ssti provides Server-Side Template Injection vulnerability detection.
// It uses context-aware analysis to determine the template engine in use
// and appropriate detection mechanisms based on response behavior.
package ssti

import (
	"context"
	"fmt"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/ssti"
)

// Detector performs SSTI vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new SSTI Detector.
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

// DetectOptions configures detection behavior.
type DetectOptions struct {
	// Maximum number of payloads to test
	MaxPayloads int
	// Include WAF bypass payloads
	IncludeWAFBypass bool
	// Timeout for each request
	Timeout time.Duration
	// Test all template engines or just detected
	TestAllEngines bool
	// Include RCE payloads (more aggressive)
	IncludeRCE bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      100,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}
}

// DetectionResult contains SSTI detection results.
type DetectionResult struct {
	Vulnerable       bool
	Findings         []*core.Finding
	TestedPayloads   int
	DetectedEngine   ssti.TemplateEngine
	EngineConfidence float64
	ErrorPatterns    []string
}

// baselineResponse holds baseline response information.
type baselineResponse struct {
	body          string
	statusCode    int
	contentLength int64
}

// mathDetectionResult holds the result of math expression detection.
type mathDetectionResult struct {
	detected   bool
	engine     ssti.TemplateEngine
	confidence float64
	expression string
	result     string
}

// errorDetectionResult holds the result of error-based detection.
type errorDetectionResult struct {
	errorPatterns []string
	engine        ssti.TemplateEngine
	confidence    float64
}

// Detect tests a parameter for SSTI vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:       make([]*core.Finding, 0),
		DetectedEngine: ssti.EngineUnknown,
		ErrorPatterns:  make([]string, 0),
	}

	// Phase 1: Initial probe to establish baseline
	baseline, err := d.establishBaseline(ctx, target, param, method)
	if err != nil {
		return result, fmt.Errorf("failed to establish baseline: %w", err)
	}

	// Phase 2: Mathematical expression detection
	mathResult := d.detectMathExpression(ctx, target, param, method, baseline)
	if mathResult.detected {
		result.Vulnerable = true
		result.DetectedEngine = mathResult.engine
		result.EngineConfidence = mathResult.confidence
	}

	// Phase 3: Error-based detection
	errorResult := d.detectByError(ctx, target, param, method)
	if len(errorResult.errorPatterns) > 0 {
		result.ErrorPatterns = errorResult.errorPatterns
		if errorResult.engine != ssti.EngineUnknown {
			result.DetectedEngine = errorResult.engine
			result.EngineConfidence = errorResult.confidence
		}
	}

	// Phase 4: Get appropriate payloads
	var payloads []ssti.Payload
	if opts.TestAllEngines || result.DetectedEngine == ssti.EngineUnknown {
		payloads = ssti.GetDetectionPayloads()
	} else {
		payloads = ssti.GetPayloads(result.DetectedEngine)
	}

	// Add WAF bypass payloads if requested
	if opts.IncludeWAFBypass {
		payloads = append(payloads, ssti.GetWAFBypassPayloads()...)
	}

	// Add RCE payloads if requested (for verification)
	if opts.IncludeRCE && result.Vulnerable {
		payloads = append(payloads, ssti.GetRCEPayloads()...)
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Phase 5: Test each payload
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		// Send payload
		resp, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
		if err != nil {
			continue
		}

		// Check if payload triggered SSTI
		if d.isPayloadSuccessful(resp.Body, payload, baseline) {
			finding := d.createFinding(target, param, payload, resp, result.DetectedEngine)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true

			// Update engine detection if we have higher confidence
			if payload.Engine != ssti.EngineUnknown {
				result.DetectedEngine = payload.Engine
				result.EngineConfidence = 0.9
			}

			// For efficiency, stop after finding first vulnerability (unless testing all)
			if !opts.TestAllEngines && !opts.IncludeRCE {
				break
			}
		}
	}

	return result, nil
}

// establishBaseline sends a normal request to establish baseline response.
func (d *Detector) establishBaseline(ctx context.Context, target, param, method string) (*baselineResponse, error) {
	probeValue := "sstiprobe" + fmt.Sprintf("%d", time.Now().UnixNano()%10000)
	resp, err := d.client.SendPayload(ctx, target, param, probeValue, method)
	if err != nil {
		return nil, err
	}

	return &baselineResponse{
		body:          resp.Body,
		statusCode:    resp.StatusCode,
		contentLength: resp.ContentLength,
	}, nil
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []ssti.Payload) []ssti.Payload {
	seen := make(map[string]bool)
	var unique []ssti.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}
