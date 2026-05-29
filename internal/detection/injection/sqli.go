// Package injection covers SQL-injection detection. The file layout
// splits responsibilities:
//
//	sqli.go               — types (PayloadContext, DatabaseType,
//	                        AnalysisResult, BooleanResult, SQLiDetector)
//	                        and constructor
//	sqli_errorpatterns.go — per-database regex tables (initErrorPatterns)
//	                        and the genericSQLPatterns fallback set
//	sqli_boolean.go       — DetectBoolean + extractParamValue + the
//	                        booleanPayloadPairs table
//	sqli_analyze.go       — AnalyzeResponse, DetectDBType, extractMatch
//	sqli_payloads.go      — GetPayloads + GetContextPayloads
package injection

import "regexp"

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

// BooleanResult contains the result of boolean-based blind SQLi
// detection. Populated by DetectBoolean. TruePayload / FalsePayload
// identify the pair that produced the differential, so callers can
// report and re-prove it.
type BooleanResult struct {
	IsVulnerable  bool
	DetectionType string
	Confidence    float64
	TruePayload   string
	FalsePayload  string
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
