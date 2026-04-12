// Package massassign provides mass assignment vulnerability detection.
// It detects when applications accept and process extra JSON fields in
// PUT/POST requests that should be protected from user modification.
package massassign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/massassign"
)

// Detector performs mass assignment vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Mass Assignment Detector.
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
	return "mass-assignment"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Mass Assignment vulnerability detector that tests for unprotected object property binding via extra JSON fields in PUT/POST requests"
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
		MaxPayloads:      30,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
	}
}

// DetectionResult contains mass assignment detection results.
type DetectionResult struct {
	// Vulnerable indicates whether a mass assignment vulnerability was found.
	Vulnerable bool
	// Findings contains the discovered vulnerabilities.
	Findings []*core.Finding
	// TestedPayloads is the number of payloads tested.
	TestedPayloads int
}

// Detect tests an endpoint for mass assignment vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if param == "" {
		return result, nil
	}

	// Ensure method is POST or PUT for mass assignment testing
	if method != "POST" && method != "PUT" && method != "PATCH" {
		method = "POST"
	}

	// Get baseline response with legitimate data
	baselineBody := `{"name": "testuser", "email": "test@example.com"}`
	baselineResp, err := d.client.SendRawBody(ctx, target, method, baselineBody, "application/json")
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Collect payloads
	payloads := d.collectPayloads(opts)

	// Test each payload by injecting extra fields into the base JSON
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		resp, err := d.client.SendRawBody(ctx, target, method, payload.Value, "application/json")
		if err != nil {
			continue
		}

		// Check if extra fields were reflected in response
		if d.hasFieldReflection(payload.Value, resp.Body) {
			finding := d.createFinding(target, payload, resp, "field-reflection")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}

		// Check if response structure changed significantly
		if d.hasResponseChange(baselineResp.Body, resp.Body) {
			finding := d.createFinding(target, payload, resp, "response-differential")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// hasFieldReflection checks if injected extra fields appear in the response.
func (d *Detector) hasFieldReflection(requestBody, responseBody string) bool {
	if responseBody == "" {
		return false
	}

	var reqData map[string]interface{}
	if err := json.Unmarshal([]byte(requestBody), &reqData); err != nil {
		return false
	}

	var respData map[string]interface{}
	if err := json.Unmarshal([]byte(responseBody), &respData); err != nil {
		return false
	}

	// Check for sensitive fields that should not be accepted
	sensitiveFields := []string{
		"isAdmin", "admin", "role", "permissions",
		"is_staff", "is_superuser", "access_level",
		"group", "verified", "active",
	}

	for _, field := range sensitiveFields {
		if reqVal, reqHas := reqData[field]; reqHas {
			if respVal, respHas := respData[field]; respHas {
				// Field was both sent and reflected
				if fmt.Sprintf("%v", reqVal) == fmt.Sprintf("%v", respVal) {
					return true
				}
			}
		}
	}

	return false
}

// hasResponseChange detects if the response changed in a way that indicates
// the extra fields were processed.
func (d *Detector) hasResponseChange(baseline, injected string) bool {
	if baseline == "" || injected == "" {
		return false
	}

	var baseData, injData map[string]interface{}

	if err := json.Unmarshal([]byte(baseline), &baseData); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(injected), &injData); err != nil {
		return false
	}

	// Check if new privileged fields appeared in the response
	privilegedFields := []string{"isAdmin", "admin", "role", "permissions", "is_staff", "is_superuser"}
	for _, field := range privilegedFields {
		if _, baseHas := baseData[field]; !baseHas {
			if val, injHas := injData[field]; injHas {
				// Check if the value indicates escalation
				if isEscalationValue(val) {
					return true
				}
			}
		}
	}

	return false
}

// isEscalationValue checks if a value indicates privilege escalation.
func isEscalationValue(val interface{}) bool {
	switch v := val.(type) {
	case bool:
		return v
	case string:
		lower := strings.ToLower(v)
		return lower == "admin" || lower == "administrator" || lower == "true"
	case float64:
		return v > 0
	}
	return false
}

// collectPayloads gathers all mass assignment payloads.
func (d *Detector) collectPayloads(opts DetectOptions) []massassign.Payload {
	payloads := massassign.GetAllPayloads()

	if !opts.IncludeWAFBypass {
		var filtered []massassign.Payload
		for _, p := range payloads {
			if !p.WAFBypass {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	payloads = massassign.DeduplicatePayloads(payloads)

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	return payloads
}

// createFinding creates a Finding from a successful mass assignment test.
func (d *Detector) createFinding(target string, payload massassign.Payload, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("Mass Assignment", core.SeverityHigh)
	finding.URL = target
	finding.Description = fmt.Sprintf("%s Mass Assignment vulnerability detected. The application accepts extra fields: %s",
		detectionType, payload.Description)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "massassign-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Use allowlists (whitelists) for accepted fields in request binding. " +
		"Never blindly bind request data to internal objects. " +
		"Use DTOs (Data Transfer Objects) with explicit field mapping. " +
		"Implement proper access controls for sensitive fields. " +
		"Disable mass assignment for sensitive attributes like role, permissions, and admin flags. " +
		"Review framework documentation for mass assignment protection features."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-20"},
		[]string{"A01:2023-API"},
		[]string{"CWE-915"},
	)

	return finding
}
