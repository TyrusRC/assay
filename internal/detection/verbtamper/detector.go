package verbtamper

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// httpMethods lists HTTP methods to test for verb tampering.
var httpMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"}

// methodOverrideHeaders lists headers used to override the HTTP method.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-Method-Override",
	"X-HTTP-Method",
}

// overrideMethods lists methods to try via override headers.
var overrideMethods = []string{"PUT", "DELETE", "PATCH"}

// Detector performs HTTP Verb Tampering vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Verb Tampering Detector.
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
	MaxPayloads          int
	IncludeOverrideTests bool
	Timeout              time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:          20,
		IncludeOverrideTests: true,
		Timeout:              10 * time.Second,
	}
}

// DetectionResult contains verb tampering detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "verbtamper-detector"
}

// Detect tests a target URL for HTTP Verb Tampering vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if target == "" {
		return result, fmt.Errorf("target URL cannot be empty")
	}

	// First, get baseline response with the original method
	baselineResp, err := d.client.Do(ctx, &http.Request{
		Method: method,
		URL:    target,
	})
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	baselineStatus := baselineResp.StatusCode
	baselineIsRestricted := baselineStatus == 401 || baselineStatus == 403

	payloadCount := 0

	// Test different HTTP methods
	for _, testMethod := range httpMethods {
		if testMethod == method {
			continue // Skip the original method
		}

		if opts.MaxPayloads > 0 && payloadCount >= opts.MaxPayloads {
			break
		}

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		payloadCount++
		result.TestedPayloads++

		resp, err := d.client.Do(ctx, &http.Request{
			Method: testMethod,
			URL:    target,
		})
		if err != nil {
			continue
		}

		// Verb tampering: restricted on original method but allowed on alternative
		if baselineIsRestricted && resp.StatusCode == 200 {
			finding := d.createFinding(target, method, testMethod, baselineResp, resp, "verb-tampering")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	// Test method override headers
	if opts.IncludeOverrideTests {
		for _, header := range methodOverrideHeaders {
			for _, overrideMethod := range overrideMethods {
				if opts.MaxPayloads > 0 && payloadCount >= opts.MaxPayloads {
					break
				}

				select {
				case <-ctx.Done():
					return result, ctx.Err()
				default:
				}

				payloadCount++
				result.TestedPayloads++

				resp, err := d.client.Do(ctx, &http.Request{
					Method:  method,
					URL:     target,
					Headers: map[string]string{header: overrideMethod},
				})
				if err != nil {
					continue
				}

				// Check if override header changed behavior
				if d.isOverrideBehaviorChange(baselineResp, resp) {
					finding := d.createOverrideFinding(target, method, header, overrideMethod, baselineResp, resp)
					result.Findings = append(result.Findings, finding)
					result.Vulnerable = true
					return result, nil
				}
			}
		}
	}

	return result, nil
}

// isOverrideBehaviorChange checks if the method override caused a significant behavior change.
func (d *Detector) isOverrideBehaviorChange(baseline, override *http.Response) bool {
	if baseline == nil || override == nil {
		return false
	}

	// Status code changed from restricted to allowed
	baselineRestricted := baseline.StatusCode == 401 || baseline.StatusCode == 403
	if baselineRestricted && override.StatusCode == 200 {
		return true
	}

	// Significant content length difference (more than 50% change) with same status
	if baseline.StatusCode == override.StatusCode {
		baselineLen := len(baseline.Body)
		overrideLen := len(override.Body)

		if baselineLen > 0 && overrideLen > 0 {
			diff := overrideLen - baselineLen
			if diff < 0 {
				diff = -diff
			}
			// More than 50% content change suggests different behavior
			if float64(diff)/float64(baselineLen) > 0.5 && overrideLen > 100 {
				return true
			}
		}
	}

	return false
}

// createFinding creates a Finding from a verb tampering bypass.
func (d *Detector) createFinding(target, originalMethod, bypassMethod string, baseline, bypass *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("HTTP Verb Tampering", core.SeverityHigh)
	finding.URL = target
	finding.Description = fmt.Sprintf("%s: URL returns %d on %s but %d on %s, indicating authentication bypass via HTTP method",
		detectionType, baseline.StatusCode, originalMethod, bypass.StatusCode, bypassMethod)
	finding.Evidence = fmt.Sprintf("Original Method: %s (Status: %d)\nBypass Method: %s (Status: %d)\nDetection: %s",
		originalMethod, baseline.StatusCode, bypassMethod, bypass.StatusCode, detectionType)
	finding.Tool = "verbtamper-detector"

	if len(bypass.Body) > 0 {
		body := bypass.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nBypass response snippet: %s", body)
	}

	finding.Remediation = "Configure the web server and application to enforce authorization consistently across all HTTP methods. " +
		"Use allowlists for permitted HTTP methods. " +
		"Disable unnecessary HTTP methods (TRACE, OPTIONS) in production."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-03"},
		[]string{"A01:2021"},
		[]string{"CWE-650"},
	)

	return finding
}

// createOverrideFinding creates a Finding from a method override header bypass.
func (d *Detector) createOverrideFinding(target, originalMethod, header, overrideMethod string, baseline, override *http.Response) *core.Finding {
	finding := core.NewFinding("HTTP Method Override Bypass", core.SeverityHigh)
	finding.URL = target
	finding.Description = fmt.Sprintf("Method override bypass: %s header with value '%s' changes server behavior (baseline status: %d, override status: %d)",
		header, overrideMethod, baseline.StatusCode, override.StatusCode)
	finding.Evidence = fmt.Sprintf("Original Method: %s (Status: %d, Content-Length: %d)\nOverride Header: %s: %s\nOverride Status: %d, Content-Length: %d",
		originalMethod, baseline.StatusCode, len(baseline.Body),
		header, overrideMethod,
		override.StatusCode, len(override.Body))
	finding.Tool = "verbtamper-detector"

	bodySnippet := override.Body
	if len(bodySnippet) > 500 {
		bodySnippet = bodySnippet[:500] + "..."
	}
	if len(bodySnippet) > 0 {
		finding.Evidence += fmt.Sprintf("\nOverride response snippet: %s", bodySnippet)
	}

	finding.Remediation = "Disable support for X-HTTP-Method-Override and similar headers. " +
		"If method override is required, enforce the same authorization checks regardless of the effective method. " +
		strings.Join([]string{
			"Configure the web server to ignore method override headers from untrusted sources.",
		}, " ")

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-03"},
		[]string{"A01:2021"},
		[]string{"CWE-650"},
	)

	return finding
}
