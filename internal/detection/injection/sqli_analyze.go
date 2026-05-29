package injection

import (
	"regexp"
	"strings"
)

// AnalyzeResponse analyzes an HTTP response for SQL injection
// indicators. Returns an AnalysisResult flagged Vulnerable=true if
// either a per-database pattern or a generic SQL-error pattern matches.
// Per-DB matches yield Confidence 0.9; generic matches yield 0.7.
func (d *SQLiDetector) AnalyzeResponse(response string) *AnalysisResult {
	result := &AnalysisResult{
		IsVulnerable: false,
		DatabaseType: DBUnknown,
	}

	if response == "" {
		return result
	}

	// Check database-specific patterns first — they let us tag the
	// finding with a concrete DatabaseType.
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

	// Fallback: generic SQL patterns. Lower confidence (0.7) because
	// they don't disambiguate the database.
	for _, pattern := range genericSQLPatterns {
		if pattern.MatchString(response) {
			result.IsVulnerable = true
			result.DetectionType = "error-based"
			result.Evidence = extractMatch(pattern, response)
			result.Confidence = 0.7
			return result
		}
	}
	return result
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

// DetectDBType detects the database type from response content.
// Used as a fingerprint preflight so payloads for the wrong DB don't
// get fired against a server that won't process them anyway.
func (d *SQLiDetector) DetectDBType(response string) DatabaseType {
	responseLower := strings.ToLower(response)

	if strings.Contains(responseLower, "mysql") ||
		strings.Contains(response, "MariaDB") {
		return DBMySQL
	}
	if strings.Contains(responseLower, "postgresql") ||
		strings.Contains(responseLower, "pg_") ||
		strings.Contains(response, "ERROR: syntax error at or near") {
		return DBPostgreSQL
	}
	if strings.Contains(responseLower, "microsoft sql server") ||
		strings.Contains(responseLower, "mssql") ||
		strings.Contains(responseLower, "sql server") {
		return DBMSSQL
	}
	if strings.Contains(response, "ORA-") ||
		strings.Contains(responseLower, "oracle") {
		return DBOracle
	}
	if strings.Contains(response, "SQLITE") ||
		strings.Contains(responseLower, "sqlite") {
		return DBSQLite
	}
	return DBUnknown
}
