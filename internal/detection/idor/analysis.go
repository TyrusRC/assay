// Package idor provides IDOR / BOLA detection. The file layout splits
// responsibilities so each concern lives in its own file:
//
//	detector.go      — types, constructor, top-level Detect loop
//	extract.go       — ID extraction from URL / path / body / JSON
//	build.go         — test-URL and test-body construction
//	analysis.go      — IDOR signal analysis on response pairs (this file)
//	findings.go      — confidence scoring + finding builder
package idor

import (
	"github.com/TyrusRC/assay/internal/http"
)

// analyzeForIDOR compares the baseline and test responses and assembles
// the IDOREvidence record consumed by isIDORVulnerable / createFinding.
// Returns nil if either response is missing.
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

	statusAnalysis := d.analyzeStatusCodes(baseline.StatusCode, test.StatusCode)
	evidence.StatusCodeIndicatesAccess = statusAnalysis.PotentialIDOR

	comparison := d.compareResponses(baseline, test)
	evidence.ContentDifferent = comparison.HasSignificantDifference

	evidence.SensitiveDataExposed = d.containsSensitiveData(test.Body)

	// 500-byte snippet — keeps the report compact while preserving
	// enough context for the operator to spot the leak.
	if len(test.Body) > 500 {
		evidence.ResponseSnippet = test.Body[:500] + "..."
	} else {
		evidence.ResponseSnippet = test.Body
	}
	return evidence
}

// isIDORVulnerable determines if the evidence indicates an IDOR
// vulnerability. Required: 2xx test status, content different from
// baseline. Sufficient: sensitive data leaked OR status-code analysis
// flagged the bypass.
func (d *Detector) isIDORVulnerable(evidence *IDOREvidence) bool {
	if evidence.TestedStatusCode < 200 || evidence.TestedStatusCode >= 300 {
		return false
	}
	if !evidence.ContentDifferent {
		return false
	}
	if evidence.SensitiveDataExposed {
		return true
	}
	return evidence.StatusCodeIndicatesAccess
}

// compareResponses compares two HTTP responses for significant differences.
// Significance dimensions: status-code mismatch, content-length delta
// over the threshold, body-content inequality.
func (d *Detector) compareResponses(resp1, resp2 *http.Response) *ResponseComparison {
	comparison := &ResponseComparison{}

	if resp1 == nil || resp2 == nil {
		return comparison
	}

	if resp1.StatusCode != resp2.StatusCode {
		comparison.StatusCodeDiff = true
		comparison.HasSignificantDifference = true
	}

	comparison.ContentLengthDiff = len(resp2.Body) - len(resp1.Body)
	if d.hasSignificantLengthDiff(len(resp1.Body), len(resp2.Body)) {
		comparison.HasSignificantDifference = true
	}

	if resp1.Body != resp2.Body {
		comparison.HasSignificantDifference = true
	}

	comparison.SensitiveDataFound = d.containsSensitiveData(resp2.Body)
	return comparison
}

// analyzeStatusCodes analyzes status code changes for IDOR indicators.
// Interesting cases:
//   - 2xx → 2xx: potential IDOR if content also differs
//   - 401/403 → 2xx: authorization bypass (strong signal)
//   - 2xx → 401/403: proper authorization check (no IDOR)
//   - 2xx → 404: resource doesn't exist (no IDOR)
func (d *Detector) analyzeStatusCodes(baselineCode, testCode int) *StatusCodeAnalysis {
	analysis := &StatusCodeAnalysis{}

	if baselineCode >= 200 && baselineCode < 300 &&
		testCode >= 200 && testCode < 300 {
		analysis.PotentialIDOR = true
		analysis.Reason = "Both requests returned success status"
		return analysis
	}
	if (baselineCode == 401 || baselineCode == 403) &&
		(testCode >= 200 && testCode < 300) {
		analysis.PotentialIDOR = true
		analysis.Reason = "Authorization bypass detected"
		return analysis
	}
	if testCode == 401 || testCode == 403 {
		analysis.PotentialIDOR = false
		analysis.Reason = "Proper authorization check"
		return analysis
	}
	if testCode == 404 {
		analysis.PotentialIDOR = false
		analysis.Reason = "Resource not found"
		return analysis
	}
	return analysis
}

// hasSignificantLengthDiff checks if content length difference is
// significant. >50% relative change OR >200 absolute bytes triggers.
func (d *Detector) hasSignificantLengthDiff(len1, len2 int) bool {
	if len1 == 0 && len2 > 0 {
		return true
	}
	if len1 == 0 {
		return false
	}

	diff := float64(len2-len1) / float64(len1)
	if diff > 0.5 || diff < -0.5 {
		return true
	}

	absDiff := len2 - len1
	if absDiff < 0 {
		absDiff = -absDiff
	}
	return absDiff > 200
}

// containsSensitiveData checks if response body contains sensitive
// information by matching against d.sensitivePatterns.
func (d *Detector) containsSensitiveData(body string) bool {
	for _, pattern := range d.sensitivePatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}
