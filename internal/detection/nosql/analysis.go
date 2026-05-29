package nosql

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/payloads/nosql"
)

// AnalyzeResponse inspects the response for error-based NoSQLi signals.
// Returns an AnalysisResult flagged Vulnerable=true if any per-DB error
// pattern matches.
func (d *Detector) AnalyzeResponse(response string) *AnalysisResult {
	result := &AnalysisResult{
		IsVulnerable: false,
		DatabaseType: nosql.Generic,
	}

	if response == "" {
		return result
	}

	// Check database-specific patterns.
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
// Used as a fingerprint preflight so payloads for the wrong DB don't
// get fired against a server that won't process them anyway.
func (d *Detector) DetectDBType(response string) nosql.DBType {
	responseLower := strings.ToLower(response)

	if strings.Contains(responseLower, "mongo") ||
		strings.Contains(response, "MongoError") ||
		strings.Contains(response, "$where") {
		return nosql.MongoDB
	}

	if strings.Contains(responseLower, "couchdb") ||
		strings.Contains(response, "bad_request") ||
		strings.Contains(response, "invalid_selector") ||
		(strings.Contains(response, "error") && strings.Contains(response, "reason")) {
		return nosql.CouchDB
	}

	if strings.Contains(responseLower, "elasticsearch") ||
		strings.Contains(response, "root_cause") ||
		strings.Contains(response, "parsing_exception") ||
		strings.Contains(response, "search_phase_execution_exception") {
		return nosql.Elasticsearch
	}

	if strings.HasPrefix(strings.TrimSpace(response), "ERR") ||
		strings.Contains(responseLower, "redis") ||
		strings.Contains(response, "WRONGTYPE") {
		return nosql.Redis
	}

	return nosql.Generic
}

// HasJSONStructureChange detects if the JSON response structure changed
// significantly between baseline and injected response. Used by the
// boolean-based injection arm of Detect.
func (d *Detector) HasJSONStructureChange(baseline, injected string) bool {
	if baseline == "" || injected == "" {
		return false
	}

	var baselineData, injectedData interface{}
	if err := json.Unmarshal([]byte(baseline), &baselineData); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(injected), &injectedData); err != nil {
		return false
	}

	baselineLen := getArrayLength(baselineData)
	injectedLen := getArrayLength(injectedData)

	// Empty-to-nonempty transition: classic boolean-based hit.
	if baselineLen == 0 && injectedLen > 0 {
		return true
	}
	// Result-set blow-up: doubled length above a small floor.
	if injectedLen > baselineLen*2 && injectedLen > 5 {
		return true
	}
	if hasAuthBypassIndicators(baselineData, injectedData) {
		return true
	}
	return false
}

// getArrayLength returns the length of the first top-level array
// encountered in a parsed JSON value. Returns 0 for scalars / missing.
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

// hasAuthBypassIndicators looks for auth-related fields that flipped
// from negative to positive between baseline and injected responses.
// Returns true on any `{auth: false}` → `{auth: true}` style transition
// or `{role: "user"}` → `{role: "admin"}`.
func hasAuthBypassIndicators(baseline, injected interface{}) bool {
	baselineMap, baselineOk := baseline.(map[string]interface{})
	injectedMap, injectedOk := injected.(map[string]interface{})
	if !baselineOk || !injectedOk {
		return false
	}

	authFields := []string{"authenticated", "auth", "logged_in", "loggedIn", "success", "admin", "role"}
	for _, field := range authFields {
		baseVal, baseHas := baselineMap[field]
		injVal, injHas := injectedMap[field]
		if !injHas {
			continue
		}
		// Field flipped from false (or absent) to true.
		if !baseHas || baseVal == false || baseVal == "false" {
			if injVal == true || injVal == "true" {
				return true
			}
		}
		// Role changed to admin.
		if field == "role" {
			if injStr, ok := injVal.(string); ok {
				lower := strings.ToLower(injStr)
				if lower == "admin" || lower == "administrator" {
					return true
				}
			}
		}
	}
	return false
}

// extractMatch extracts the matching portion from the response.
// Truncated at 100 chars for compact Evidence strings.
func extractMatch(pattern *regexp.Regexp, response string) string {
	match := pattern.FindString(response)
	if len(match) > 100 {
		return match[:100] + "..."
	}
	return match
}
