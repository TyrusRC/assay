package idor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// extractIDParameters extracts potential ID parameters from URL and body.
func (d *Detector) extractIDParameters(targetURL, body, contentType string) []IDParameter {
	var params []IDParameter

	// Parse URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return params
	}

	// Extract from query parameters
	query := parsedURL.Query()
	for key, values := range query {
		if len(values) > 0 {
			value := values[0]
			if d.isLikelyID(key, value) {
				params = append(params, IDParameter{
					Name:     key,
					Value:    value,
					Type:     d.detectIDType(value),
					Location: LocationQuery,
				})
			}
		}
	}

	// Extract from URL path (numeric IDs in path segments)
	pathParts := strings.Split(parsedURL.Path, "/")
	for _, part := range pathParts {
		if part == "" {
			continue
		}
		if d.idPatterns[IDTypeNumeric].MatchString(part) {
			params = append(params, IDParameter{
				Name:     part,
				Value:    part,
				Type:     IDTypeNumeric,
				Location: LocationPath,
			})
		} else if d.idPatterns[IDTypeUUID].MatchString(part) {
			params = append(params, IDParameter{
				Name:     part,
				Value:    part,
				Type:     IDTypeUUID,
				Location: LocationPath,
			})
		}
	}

	// Extract from body
	if body != "" {
		bodyParams := d.extractIDsFromBody(body, contentType)
		params = append(params, bodyParams...)
	}

	return params
}

// extractIDsFromBody extracts ID parameters from request body.
func (d *Detector) extractIDsFromBody(body, contentType string) []IDParameter {
	var params []IDParameter

	if strings.Contains(contentType, "application/json") {
		// Parse JSON body
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			params = d.extractIDsFromJSON(jsonData, "")
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// Parse form data
		formData, err := url.ParseQuery(body)
		if err == nil {
			for key, values := range formData {
				if len(values) > 0 {
					value := values[0]
					if d.isLikelyID(key, value) {
						params = append(params, IDParameter{
							Name:     key,
							Value:    value,
							Type:     d.detectIDType(value),
							Location: LocationBody,
						})
					}
				}
			}
		}
	}

	return params
}

// extractIDsFromJSON recursively extracts ID parameters from JSON.
func (d *Detector) extractIDsFromJSON(data map[string]interface{}, prefix string) []IDParameter {
	var params []IDParameter

	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case float64:
			// Numeric value
			strValue := strconv.FormatFloat(v, 'f', -1, 64)
			// Remove decimal point if it's a whole number
			if v == float64(int64(v)) {
				strValue = strconv.FormatInt(int64(v), 10)
			}
			if d.isLikelyID(key, strValue) {
				params = append(params, IDParameter{
					Name:     key,
					Value:    strValue,
					Type:     IDTypeNumeric,
					Location: LocationBody,
				})
			}
		case string:
			if d.isLikelyID(key, v) {
				params = append(params, IDParameter{
					Name:     key,
					Value:    v,
					Type:     d.detectIDType(v),
					Location: LocationBody,
				})
			}
		case map[string]interface{}:
			// Recurse into nested objects
			nested := d.extractIDsFromJSON(v, fullKey)
			params = append(params, nested...)
		}
	}

	return params
}

// isLikelyID determines if a parameter is likely an object reference.
func (d *Detector) isLikelyID(name, value string) bool {
	if value == "" {
		return false
	}

	nameLower := strings.ToLower(name)

	// Check if parameter name suggests it's an ID
	for _, idName := range d.idParameterNames {
		if strings.Contains(nameLower, strings.ToLower(idName)) {
			return true
		}
	}

	// Check if value looks like an ID
	if d.idPatterns[IDTypeNumeric].MatchString(value) {
		return true
	}
	if d.idPatterns[IDTypeUUID].MatchString(value) {
		return true
	}

	return false
}

// detectIDType determines the type of an ID value.
func (d *Detector) detectIDType(value string) IDType {
	if d.idPatterns[IDTypeNumeric].MatchString(value) {
		return IDTypeNumeric
	}
	if d.idPatterns[IDTypeUUID].MatchString(value) {
		return IDTypeUUID
	}
	if d.idPatterns[IDTypeHex].MatchString(value) && len(value) >= 12 {
		return IDTypeHex
	}
	// Check for base64
	if d.isBase64(value) {
		return IDTypeBase64
	}
	return IDTypeAlphanumeric
}

// isBase64 checks if a value is likely base64 encoded.
func (d *Detector) isBase64(value string) bool {
	if len(value) < 4 {
		return false
	}
	// Check for base64 characters and padding
	if !d.base64Pattern.MatchString(value) {
		return false
	}
	// Try to decode
	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

// buildTestURL builds a URL with a manipulated ID.
func (d *Detector) buildTestURL(originalURL *url.URL, param IDParameter, newID string) string {
	testURL := *originalURL

	switch param.Location {
	case LocationQuery:
		query := testURL.Query()
		query.Set(param.Name, newID)
		testURL.RawQuery = query.Encode()
	case LocationPath:
		// Replace the ID in the path
		testURL.Path = strings.Replace(testURL.Path, param.Value, newID, 1)
	}

	return testURL.String()
}

// buildTestBody builds a request body with a manipulated ID.
func (d *Detector) buildTestBody(body, contentType string, param IDParameter, newID string) string {
	if strings.Contains(contentType, "application/json") {
		// For JSON, handle both string and numeric values
		// Try replacing as string first
		result := strings.Replace(body, `"`+param.Value+`"`, `"`+newID+`"`, 1)
		if result != body {
			return result
		}
		// Try replacing as numeric value (handles: "key": 123)
		// Match patterns like "user_id": 1 or "user_id":1
		numPattern := regexp.MustCompile(`("` + regexp.QuoteMeta(param.Name) + `"\s*:\s*)` + regexp.QuoteMeta(param.Value) + `(\s*[,}])`)
		if numPattern.MatchString(body) {
			return numPattern.ReplaceAllString(body, "${1}"+newID+"${2}")
		}
		return body
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// For form data, parse and rebuild
		formData, err := url.ParseQuery(body)
		if err != nil {
			return body
		}
		formData.Set(param.Name, newID)
		return formData.Encode()
	}
	return body
}

// analyzeForIDOR analyzes responses for IDOR indicators.
func (d *Detector) analyzeForIDOR(baseline, test *http.Response, originalID, testID string) *IDOREvidence {
	if baseline == nil || test == nil {
		return nil
	}

	evidence := &IDOREvidence{
		OriginalID:            originalID,
		TestedID:              testID,
		OriginalStatusCode:    baseline.StatusCode,
		TestedStatusCode:      test.StatusCode,
		OriginalContentLength: len(baseline.Body),
		TestedContentLength:   len(test.Body),
	}

	// Analyze status codes
	statusAnalysis := d.analyzeStatusCodes(baseline.StatusCode, test.StatusCode)
	evidence.StatusCodeIndicatesAccess = statusAnalysis.PotentialIDOR

	// Compare responses
	comparison := d.compareResponses(baseline, test)
	evidence.ContentDifferent = comparison.HasSignificantDifference

	// Check for sensitive data
	evidence.SensitiveDataExposed = d.containsSensitiveData(test.Body)

	// Store response snippet
	if len(test.Body) > 500 {
		evidence.ResponseSnippet = test.Body[:500] + "..."
	} else {
		evidence.ResponseSnippet = test.Body
	}

	return evidence
}

// isIDORVulnerable determines if evidence indicates an IDOR vulnerability.
func (d *Detector) isIDORVulnerable(evidence *IDOREvidence) bool {
	// Must have successful access (2xx status)
	if evidence.TestedStatusCode < 200 || evidence.TestedStatusCode >= 300 {
		return false
	}

	// Must have different content (not just same error page)
	if !evidence.ContentDifferent {
		return false
	}

	// Strong indicator if sensitive data is exposed
	if evidence.SensitiveDataExposed {
		return true
	}

	// Status code indicates access was granted
	if evidence.StatusCodeIndicatesAccess {
		return true
	}

	return false
}

// compareResponses compares two HTTP responses for significant differences.
func (d *Detector) compareResponses(resp1, resp2 *http.Response) *ResponseComparison {
	comparison := &ResponseComparison{}

	if resp1 == nil || resp2 == nil {
		return comparison
	}

	// Compare status codes
	if resp1.StatusCode != resp2.StatusCode {
		comparison.StatusCodeDiff = true
		comparison.HasSignificantDifference = true
	}

	// Compare content lengths
	comparison.ContentLengthDiff = len(resp2.Body) - len(resp1.Body)
	if d.hasSignificantLengthDiff(len(resp1.Body), len(resp2.Body)) {
		comparison.HasSignificantDifference = true
	}

	// Compare content (simple approach - check if bodies are different)
	if resp1.Body != resp2.Body {
		comparison.HasSignificantDifference = true
	}

	// Check for sensitive data in response
	comparison.SensitiveDataFound = d.containsSensitiveData(resp2.Body)

	return comparison
}

// analyzeStatusCodes analyzes status code changes for IDOR indicators.
func (d *Detector) analyzeStatusCodes(baselineCode, testCode int) *StatusCodeAnalysis {
	analysis := &StatusCodeAnalysis{}

	// Both successful - potential IDOR if content differs
	if baselineCode >= 200 && baselineCode < 300 &&
		testCode >= 200 && testCode < 300 {
		analysis.PotentialIDOR = true
		analysis.Reason = "Both requests returned success status"
		return analysis
	}

	// Authorization bypass: baseline was forbidden/unauthorized, test succeeded
	if (baselineCode == 401 || baselineCode == 403) &&
		(testCode >= 200 && testCode < 300) {
		analysis.PotentialIDOR = true
		analysis.Reason = "Authorization bypass detected"
		return analysis
	}

	// Test returned auth error - proper authorization in place
	if testCode == 401 || testCode == 403 {
		analysis.PotentialIDOR = false
		analysis.Reason = "Proper authorization check"
		return analysis
	}

	// Test returned not found - resource doesn't exist
	if testCode == 404 {
		analysis.PotentialIDOR = false
		analysis.Reason = "Resource not found"
		return analysis
	}

	return analysis
}

// hasSignificantLengthDiff checks if content length difference is significant.
func (d *Detector) hasSignificantLengthDiff(len1, len2 int) bool {
	if len1 == 0 && len2 > 0 {
		return true
	}
	if len1 == 0 {
		return false
	}

	// More than 50% difference
	diff := float64(len2-len1) / float64(len1)
	if diff > 0.5 || diff < -0.5 {
		return true
	}

	// Absolute difference threshold
	absDiff := len2 - len1
	if absDiff < 0 {
		absDiff = -absDiff
	}
	return absDiff > 200
}

// containsSensitiveData checks if response body contains sensitive information.
func (d *Detector) containsSensitiveData(body string) bool {
	for _, pattern := range d.sensitivePatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// calculateConfidence calculates confidence level based on evidence.
func (d *Detector) calculateConfidence(evidence *IDOREvidence) core.Confidence {
	score := 0

	if evidence.StatusCodeIndicatesAccess {
		score++
	}
	if evidence.ContentDifferent {
		score++
	}
	if evidence.SensitiveDataExposed {
		score += 2
	}

	switch {
	case score >= 3:
		return core.ConfidenceHigh
	case score >= 2:
		return core.ConfidenceMedium
	default:
		return core.ConfidenceLow
	}
}

// createFinding creates a Finding from IDOR detection evidence.
func (d *Detector) createFinding(targetURL string, param IDParameter, evidence *IDOREvidence, resp *http.Response) *core.Finding {
	severity := core.SeverityHigh
	if evidence.SensitiveDataExposed {
		severity = core.SeverityCritical
	}

	finding := core.NewFinding("Insecure Direct Object Reference (IDOR)", severity)
	finding.URL = targetURL
	finding.Parameter = param.Name
	finding.Tool = "idor-detector"
	finding.Confidence = d.calculateConfidence(evidence)

	finding.Description = fmt.Sprintf(
		"IDOR/BOLA vulnerability detected in parameter '%s' (Location: %s, Type: %s). "+
			"Successfully accessed resource with ID '%s' instead of original ID '%s'.",
		param.Name, param.Location, param.Type, evidence.TestedID, evidence.OriginalID)

	finding.Evidence = fmt.Sprintf(
		"Original ID: %s\nTested ID: %s\n"+
			"Original Status: %d\nTest Status: %d\n"+
			"Content Length Diff: %d bytes\n"+
			"Sensitive Data Exposed: %v\n\n"+
			"Response Snippet:\n%s",
		evidence.OriginalID, evidence.TestedID,
		evidence.OriginalStatusCode, evidence.TestedStatusCode,
		evidence.TestedContentLength-evidence.OriginalContentLength,
		evidence.SensitiveDataExposed,
		evidence.ResponseSnippet)

	finding.Remediation = "Implement proper authorization checks for all object references. " +
		"Verify that the authenticated user has permission to access the requested resource. " +
		"Use indirect references or access control lists (ACLs) instead of direct object IDs. " +
		"Consider using UUIDs instead of sequential IDs to make enumeration harder. " +
		"Log and monitor access attempts to detect potential attacks."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"}, // Testing for Insecure Direct Object References
		[]string{"A01:2021"},     // Broken Access Control
		[]string{"CWE-639"},      // Authorization Bypass Through User-Controlled Key
	)

	// Add API Top 10 mapping
	finding.APITop10 = []string{"API1:2023"} // Broken Object Level Authorization

	finding.References = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
		"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		"https://cwe.mitre.org/data/definitions/639.html",
	}

	return finding
}
