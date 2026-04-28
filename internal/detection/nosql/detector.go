// Package nosql provides NoSQL injection vulnerability detection.
// It supports detection for MongoDB, CouchDB, Elasticsearch, and Redis
// using operator injection, JavaScript injection, and response-based techniques.
package nosql

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/nosql"
)

// Detector performs NoSQL Injection vulnerability detection.
type Detector struct {
	client        *http.Client
	verbose       bool
	errorPatterns map[nosql.DBType][]*regexp.Regexp
}

// New creates a new NoSQL Injection Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client:        client,
		errorPatterns: make(map[nosql.DBType][]*regexp.Regexp),
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
	return "nosqli"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "NoSQL Injection vulnerability detector using operator injection, JavaScript injection, and response-based techniques"
}

// initErrorPatterns initializes database-specific error patterns.
func (d *Detector) initErrorPatterns() {
	// MongoDB error patterns
	d.errorPatterns[nosql.MongoDB] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)MongoError`),
		regexp.MustCompile(`(?i)mongo.*error`),
		regexp.MustCompile(`(?i)unknown operator`),
		regexp.MustCompile(`(?i)\$where is disabled`),
		regexp.MustCompile(`(?i)FailedToParse`),
		regexp.MustCompile(`(?i)BadValue`),
		regexp.MustCompile(`(?i)cannot apply.*to.*type`),
		regexp.MustCompile(`(?i)invalid operator`),
		regexp.MustCompile(`(?i)unrecognized expression`),
		regexp.MustCompile(`(?i)Command failed.*errmsg`),
		regexp.MustCompile(`(?i)cannot index parallel arrays`),
		regexp.MustCompile(`(?i)Projection cannot have a mix`),
	}

	// CouchDB error patterns
	d.errorPatterns[nosql.CouchDB] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)invalid_selector`),
		regexp.MustCompile(`(?i)bad_request`),
		regexp.MustCompile(`(?i)invalid UTF-8 JSON`),
		regexp.MustCompile(`(?i)invalid selector`),
		regexp.MustCompile(`(?i)compilation_error`),
		regexp.MustCompile(`(?i)No matching index found`),
		regexp.MustCompile(`(?i)"reason":\s*"[^"]*selector`),
	}

	// Elasticsearch error patterns
	d.errorPatterns[nosql.Elasticsearch] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)parsing_exception`),
		regexp.MustCompile(`(?i)script_exception`),
		regexp.MustCompile(`(?i)search_phase_execution_exception`),
		regexp.MustCompile(`(?i)query_parsing_exception`),
		regexp.MustCompile(`(?i)illegal_argument_exception`),
		regexp.MustCompile(`(?i)root_cause.*type.*exception`),
		regexp.MustCompile(`(?i)unknown query`),
		regexp.MustCompile(`(?i)SearchParseException`),
	}

	// Redis error patterns
	d.errorPatterns[nosql.Redis] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^ERR `),
		regexp.MustCompile(`(?i)ERR unknown command`),
		regexp.MustCompile(`(?i)ERR syntax error`),
		regexp.MustCompile(`(?i)WRONGTYPE`),
		regexp.MustCompile(`(?i)ERR invalid`),
		regexp.MustCompile(`(?i)NOSCRIPT`),
	}

	// Generic NoSQL error patterns
	d.errorPatterns[nosql.Generic] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)query.*error`),
		regexp.MustCompile(`(?i)parse.*error`),
		regexp.MustCompile(`(?i)syntax.*error`),
		regexp.MustCompile(`(?i)invalid.*query`),
		regexp.MustCompile(`(?i)Query parsing failed`),
		regexp.MustCompile(`(?i)malformed.*query`),
	}
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
	DBType           nosql.DBType
	EnableTimeBased  bool
	TimeBasedDelay   time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		DBType:           nosql.Generic,
		EnableTimeBased:  true,
		TimeBasedDelay:   5 * time.Second,
	}
}

// DetectionResult contains NoSQL injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
	DetectedDBType nosql.DBType
}

// AnalysisResult contains the result of response analysis.
type AnalysisResult struct {
	IsVulnerable  bool
	DetectionType string
	Confidence    float64
	Evidence      string
	DatabaseType  nosql.DBType
}

// Detect tests a parameter for NoSQL Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:       make([]*core.Finding, 0),
		DetectedDBType: opts.DBType,
	}

	// Handle empty parameter gracefully
	if param == "" {
		return result, nil
	}

	// Get payloads based on database type
	payloads := nosql.GetPayloads(opts.DBType)

	// Add WAF bypass payloads if requested
	if opts.IncludeWAFBypass {
		payloads = append(payloads, nosql.GetWAFBypassPayloads(opts.DBType)...)
	}

	// Add generic payloads for broader coverage
	if opts.DBType != nosql.Generic {
		payloads = append(payloads, nosql.GetPayloads(nosql.Generic)...)
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "baseline_test_value", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}
	baselineTime := baselineResp.Duration
	baselineBody := baselineResp.Body

	// Test error-based and response-based payloads first (faster)
	for _, payload := range payloads {
		if payload.Technique == nosql.TechTimeBased {
			continue // Skip time-based for now
		}

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

		// Check for error-based detection. Gate on baseline-diff: if the
		// baseline already contains the same NoSQL error string (e.g.
		// docs page shipping a "Query parsing failed" example), the
		// pattern is not evidence of injection.
		if analysis := d.AnalyzeResponse(resp.Body); analysis.IsVulnerable {
			if base := d.AnalyzeResponse(baselineBody); !base.IsVulnerable {
				finding := d.createFinding(target, param, payload, resp, analysis.DetectionType)
				finding.Evidence = analysis.Evidence
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				result.DetectedDBType = analysis.DatabaseType
				return result, nil
			}
		}

		// Check for response-based detection (JSON structure changes)
		if d.HasJSONStructureChange(baselineBody, resp.Body) {
			finding := d.createFinding(target, param, payload, resp, "response-based")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	// Test time-based payloads if enabled
	if opts.EnableTimeBased {
		timePayloads := nosql.GetByTechnique(opts.DBType, nosql.TechTimeBased)
		for _, payload := range timePayloads {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			result.TestedPayloads++

			start := time.Now()
			_, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
			elapsed := time.Since(start)

			if err != nil {
				continue
			}

			// Check if response was significantly delayed
			expectedDelay := opts.TimeBasedDelay
			tolerance := time.Second * 2

			if elapsed > baselineTime+expectedDelay-tolerance && elapsed < baselineTime+expectedDelay+tolerance*2 {
				finding := d.createFinding(target, param, payload, nil, "time-based")
				finding.Evidence = fmt.Sprintf("Response delayed by %v (baseline: %v, expected delay: %v)",
					elapsed, baselineTime, expectedDelay)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				result.DetectedDBType = payload.DBType
				return result, nil
			}
		}
	}

	return result, nil
}

// AnalyzeResponse analyzes an HTTP response for NoSQL injection indicators.
func (d *Detector) AnalyzeResponse(response string) *AnalysisResult {
	result := &AnalysisResult{
		IsVulnerable: false,
		DatabaseType: nosql.Generic,
	}

	if response == "" {
		return result
	}

	// Check database-specific patterns
	for dbType, patterns := range d.errorPatterns {
		for _, pattern := range patterns {
			if pattern.MatchString(response) {
				result.IsVulnerable = true
				result.DetectionType = "error-based"
				result.DatabaseType = dbType
				result.Evidence = extractMatch(pattern, response)
				result.Confidence = 0.9
				return result
			}
		}
	}

	return result
}

// DetectDBType detects the NoSQL database type from response content.
func (d *Detector) DetectDBType(response string) nosql.DBType {
	responseLower := strings.ToLower(response)

	// Check for MongoDB indicators
	if strings.Contains(responseLower, "mongo") ||
		strings.Contains(response, "MongoError") ||
		strings.Contains(response, "$where") {
		return nosql.MongoDB
	}

	// Check for CouchDB indicators
	if strings.Contains(responseLower, "couchdb") ||
		strings.Contains(response, "bad_request") ||
		strings.Contains(response, "invalid_selector") ||
		(strings.Contains(response, "error") && strings.Contains(response, "reason")) {
		return nosql.CouchDB
	}

	// Check for Elasticsearch indicators
	if strings.Contains(responseLower, "elasticsearch") ||
		strings.Contains(response, "root_cause") ||
		strings.Contains(response, "parsing_exception") ||
		strings.Contains(response, "search_phase_execution_exception") {
		return nosql.Elasticsearch
	}

	// Check for Redis indicators
	if strings.HasPrefix(strings.TrimSpace(response), "ERR") ||
		strings.Contains(responseLower, "redis") ||
		strings.Contains(response, "WRONGTYPE") {
		return nosql.Redis
	}

	return nosql.Generic
}

// HasJSONStructureChange detects if the JSON response structure changed significantly.
func (d *Detector) HasJSONStructureChange(baseline, injected string) bool {
	if baseline == "" || injected == "" {
		return false
	}

	// Try to parse both as JSON
	var baselineData, injectedData interface{}

	if err := json.Unmarshal([]byte(baseline), &baselineData); err != nil {
		return false
	}

	if err := json.Unmarshal([]byte(injected), &injectedData); err != nil {
		return false
	}

	// Compare array lengths (common indicator of injection success)
	baselineLen := getArrayLength(baselineData)
	injectedLen := getArrayLength(injectedData)

	// Significant change in array length indicates possible injection
	if baselineLen == 0 && injectedLen > 0 {
		return true
	}

	if injectedLen > baselineLen*2 && injectedLen > 5 {
		return true
	}

	// Check for new fields that indicate bypass
	if hasAuthBypassIndicators(baselineData, injectedData) {
		return true
	}

	return false
}

// getArrayLength returns the length of arrays in JSON data.
func getArrayLength(data interface{}) int {
	switch v := data.(type) {
	case []interface{}:
		return len(v)
	case map[string]interface{}:
		for _, val := range v {
			if arr, ok := val.([]interface{}); ok {
				return len(arr)
			}
		}
	}
	return 0
}

// hasAuthBypassIndicators checks if the response shows authentication bypass indicators.
func hasAuthBypassIndicators(baseline, injected interface{}) bool {
	baselineMap, baselineOk := baseline.(map[string]interface{})
	injectedMap, injectedOk := injected.(map[string]interface{})

	if !baselineOk || !injectedOk {
		return false
	}

	// Check for common auth bypass indicators
	authFields := []string{"authenticated", "auth", "logged_in", "loggedIn", "success", "admin", "role"}

	for _, field := range authFields {
		baseVal, baseHas := baselineMap[field]
		injVal, injHas := injectedMap[field]

		if injHas {
			// Check if field changed from false to true
			if !baseHas || baseVal == false || baseVal == "false" {
				if injVal == true || injVal == "true" {
					return true
				}
			}

			// Check if role changed to admin
			if field == "role" {
				if injStr, ok := injVal.(string); ok {
					if strings.ToLower(injStr) == "admin" || strings.ToLower(injStr) == "administrator" {
						return true
					}
				}
			}
		}
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []nosql.Payload) []nosql.Payload {
	seen := make(map[string]bool)
	var unique []nosql.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful NoSQL injection test.
func (d *Detector) createFinding(target, param string, payload nosql.Payload, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("NoSQL Injection", core.SeverityCritical)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("%s NoSQL Injection vulnerability in '%s' parameter (Database: %s, Technique: %s)",
		detectionType, param, payload.DBType, payload.Technique)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "nosqli-detector"

	if resp != nil && len(resp.Body) > 0 {
		// Truncate evidence if too long
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Use parameterized queries or prepared statements. " +
		"Never construct queries from user input directly. " +
		"Validate and sanitize all user input. " +
		"Use allowlists for valid inputs. " +
		"Disable JavaScript execution in MongoDB ($where, $function) if not needed. " +
		"Apply least privilege principle for database users."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-05"}, // Testing for NoSQL Injection
		[]string{"A03:2025"},     // Injection
		[]string{"CWE-943"},      // Improper Neutralization of Special Elements in Data Query Logic
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
