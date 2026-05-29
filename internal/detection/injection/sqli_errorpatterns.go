package injection

import "regexp"

// initErrorPatterns populates d.errorPatterns with the per-database
// regex set used to identify error-based SQL injection. Kept in its own
// file so adding patterns to a new DB type doesn't churn sqli.go.
func (d *SQLiDetector) initErrorPatterns() {
	d.errorPatterns[DBMySQL] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)you have an error in your sql syntax`),
		regexp.MustCompile(`(?i)check the manual that corresponds to your (mysql|mariadb) server version`),
		regexp.MustCompile(`(?i)mysql.*error`),
		regexp.MustCompile(`(?i)warning.*mysql`),
	}

	d.errorPatterns[DBPostgreSQL] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ERROR:\s*syntax error at or near`),
		regexp.MustCompile(`(?i)pg_query\(\).*failed`),
		regexp.MustCompile(`(?i)unterminated quoted string`),
		regexp.MustCompile(`(?i)postgresql.*error`),
	}

	d.errorPatterns[DBMSSQL] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)unclosed quotation mark`),
		regexp.MustCompile(`(?i)microsoft sql server`),
		regexp.MustCompile(`(?i)mssql.*error`),
		regexp.MustCompile(`(?i)sql server.*error`),
	}

	d.errorPatterns[DBOracle] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ORA-\d{5}`),
		regexp.MustCompile(`(?i)oracle.*error`),
		regexp.MustCompile(`(?i)quoted string not properly terminated`),
	}

	d.errorPatterns[DBSQLite] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)SQLITE_ERROR`),
		regexp.MustCompile(`(?i)sqlite3\..*Error`),
		regexp.MustCompile(`(?i)SQLite.*syntax`),
	}
}

// genericSQLPatterns returns patterns that indicate SQL errors
// regardless of database type. Used by AnalyzeResponse as a fallback
// when no per-DB pattern matched.
var genericSQLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)sql\s*syntax.*error`),
	regexp.MustCompile(`(?i)syntax\s*error.*sql`),
	regexp.MustCompile(`(?i)unexpected\s*end\s*of\s*sql`),
	regexp.MustCompile(`(?i)invalid\s*sql`),
	regexp.MustCompile(`(?i)sql\s*command`),
}
