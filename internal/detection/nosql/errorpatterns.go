package nosql

import (
	"regexp"

	"github.com/TyrusRC/assay/internal/payloads/nosql"
)

// initErrorPatterns populates d.errorPatterns with the per-database
// regex set used to identify error-based injection. Kept in its own
// file so adding patterns to a new DB type doesn't churn detector.go.
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
