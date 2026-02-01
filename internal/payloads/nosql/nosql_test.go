package nosql

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name   string
		dbType DBType
	}{
		{"MongoDB", MongoDB},
		{"CouchDB", CouchDB},
		{"Elasticsearch", Elasticsearch},
		{"Redis", Redis},
		{"Generic", Generic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.dbType)
			if len(payloads) == 0 {
				t.Errorf("GetPayloads(%s) returned no payloads", tt.dbType)
			}
		})
	}
}

func TestGetByTechnique(t *testing.T) {
	techniques := []Technique{TechOperator, TechJavaScript, TechJSON, TechBlind, TechTimeBased}

	for _, tech := range techniques {
		t.Run(string(tech), func(t *testing.T) {
			payloads := GetByTechnique(MongoDB, tech)
			for _, p := range payloads {
				if p.Technique != tech {
					t.Errorf("GetByTechnique(%s) returned payload with technique %s", tech, p.Technique)
				}
			}
		})
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads(MongoDB)
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", p.Value)
		}
	}
}

func TestGetAuthBypassPayloads(t *testing.T) {
	payloads := GetAuthBypassPayloads()
	if len(payloads) == 0 {
		t.Error("GetAuthBypassPayloads returned no payloads")
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()
	if len(payloads) == 0 {
		t.Error("GetAllPayloads returned no payloads")
	}

	// Verify we have payloads from multiple database types
	dbTypes := make(map[DBType]bool)
	for _, p := range payloads {
		dbTypes[p.DBType] = true
	}

	expectedDBTypes := []DBType{MongoDB, CouchDB, Elasticsearch, Generic}
	for _, expected := range expectedDBTypes {
		if !dbTypes[expected] {
			t.Errorf("GetAllPayloads missing payloads for %s", expected)
		}
	}
}

func TestPayloadFields(t *testing.T) {
	payloads := GetAllPayloads()
	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Description == "" {
			truncated := p.Value
			if len(truncated) > 20 {
				truncated = truncated[:20]
			}
			t.Errorf("Payload %q has empty Description", truncated)
		}
	}
}

func TestDBType_String(t *testing.T) {
	tests := []struct {
		dbType DBType
		want   string
	}{
		{MongoDB, "mongodb"},
		{CouchDB, "couchdb"},
		{Elasticsearch, "elasticsearch"},
		{Redis, "redis"},
		{Generic, "generic"},
	}

	for _, tt := range tests {
		t.Run(string(tt.dbType), func(t *testing.T) {
			if string(tt.dbType) != tt.want {
				t.Errorf("DBType = %q, want %q", string(tt.dbType), tt.want)
			}
		})
	}
}

func TestTechnique_String(t *testing.T) {
	tests := []struct {
		tech Technique
		want string
	}{
		{TechOperator, "operator"},
		{TechJavaScript, "javascript"},
		{TechJSON, "json"},
		{TechBlind, "blind"},
		{TechTimeBased, "time"},
	}

	for _, tt := range tests {
		t.Run(string(tt.tech), func(t *testing.T) {
			if string(tt.tech) != tt.want {
				t.Errorf("Technique = %q, want %q", string(tt.tech), tt.want)
			}
		})
	}
}

func TestMongoDBOperatorPayloads(t *testing.T) {
	payloads := GetPayloads(MongoDB)

	// Check that key MongoDB operators are included
	operators := []string{"$ne", "$gt", "$regex", "$where"}
	for _, op := range operators {
		found := false
		for _, p := range payloads {
			if containsSubstring(p.Value, op) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected MongoDB operator %q not found in payloads", op)
		}
	}
}

func TestMongoDBJavaScriptPayloads(t *testing.T) {
	payloads := GetByTechnique(MongoDB, TechJavaScript)
	if len(payloads) == 0 {
		t.Error("Expected JavaScript injection payloads for MongoDB")
	}

	// Check for $where clause payloads
	hasWhere := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "$where") || containsSubstring(p.Value, "function") {
			hasWhere = true
			break
		}
	}
	if !hasWhere {
		t.Error("Expected $where or function-based JavaScript payloads")
	}
}

func TestCouchDBPayloads(t *testing.T) {
	payloads := GetPayloads(CouchDB)
	if len(payloads) == 0 {
		t.Error("Expected CouchDB payloads")
	}

	// Check for CouchDB-specific patterns
	hasMango := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "selector") || containsSubstring(p.Value, "_all_docs") {
			hasMango = true
			break
		}
	}
	if !hasMango {
		t.Error("Expected CouchDB Mango query payloads")
	}
}

func TestElasticsearchPayloads(t *testing.T) {
	payloads := GetPayloads(Elasticsearch)
	if len(payloads) == 0 {
		t.Error("Expected Elasticsearch payloads")
	}

	// Check for Elasticsearch-specific patterns
	hasQuery := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "query") || containsSubstring(p.Value, "script") {
			hasQuery = true
			break
		}
	}
	if !hasQuery {
		t.Error("Expected Elasticsearch query payloads")
	}
}

func TestDeduplicatePayloads(t *testing.T) {
	payloads := []Payload{
		{Value: "test1", DBType: MongoDB},
		{Value: "test2", DBType: MongoDB},
		{Value: "test1", DBType: MongoDB}, // duplicate
		{Value: "test3", DBType: MongoDB},
		{Value: "test2", DBType: CouchDB}, // different db, same value
	}

	deduped := DeduplicatePayloads(payloads)

	// Should have 4 unique payloads (test1 deduped, test2 with different DB kept)
	if len(deduped) != 4 {
		t.Errorf("DeduplicatePayloads() returned %d payloads, want 4", len(deduped))
	}
}

func TestGetOperatorPayloads(t *testing.T) {
	payloads := GetOperatorPayloads()
	if len(payloads) == 0 {
		t.Error("GetOperatorPayloads returned no payloads")
	}

	for _, p := range payloads {
		if p.Technique != TechOperator {
			t.Errorf("GetOperatorPayloads returned non-operator payload: %s", p.Value)
		}
	}
}

func TestGetJSONStructurePayloads(t *testing.T) {
	payloads := GetJSONStructurePayloads()
	if len(payloads) == 0 {
		t.Error("GetJSONStructurePayloads returned no payloads")
	}

	for _, p := range payloads {
		if p.Technique != TechJSON {
			t.Errorf("GetJSONStructurePayloads returned non-JSON payload: %s", p.Value)
		}
	}
}

// containsSubstring checks if a string contains a substring.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestGetPayloads_UnknownDBType(t *testing.T) {
	// Unknown DB type should return generic payloads
	payloads := GetPayloads(DBType("unknown"))
	genericPayloads := GetPayloads(Generic)

	if len(payloads) != len(genericPayloads) {
		t.Errorf("Unknown DB type should return generic payloads, got %d, want %d", len(payloads), len(genericPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		// Key is value + db type to allow same payload for different DBs
		key := p.Value + "|" + string(p.DBType)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (DB: %s)", truncate(p.Value, 40), p.DBType)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestGetWAFBypassPayloads_NonEmpty(t *testing.T) {
	payloads := GetWAFBypassPayloads(MongoDB)
	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads(MongoDB) returned no payloads")
	}
}

func TestAllTechniquesRepresented(t *testing.T) {
	all := GetAllPayloads()
	techniques := make(map[Technique]bool)

	for _, p := range all {
		techniques[p.Technique] = true
	}

	expectedTechniques := []Technique{TechOperator, TechJavaScript, TechJSON}
	for _, expected := range expectedTechniques {
		if !techniques[expected] {
			t.Errorf("No payloads found for technique %s", expected)
		}
	}
}

func TestRedisPayloads(t *testing.T) {
	payloads := GetPayloads(Redis)
	if len(payloads) == 0 {
		t.Error("Expected Redis payloads")
	}

	// Check for Redis-specific commands
	hasInfo := false
	hasKeys := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "INFO") {
			hasInfo = true
		}
		if containsSubstring(p.Value, "KEYS") {
			hasKeys = true
		}
	}

	if !hasInfo {
		t.Error("Expected Redis INFO command payload")
	}
	if !hasKeys {
		t.Error("Expected Redis KEYS command payload")
	}
}

func TestGetByTechnique_EmptyResult(t *testing.T) {
	// TechBlind for MongoDB should return empty if no blind payloads exist
	payloads := GetByTechnique(MongoDB, TechBlind)
	// This test just ensures the function handles missing technique gracefully
	t.Logf("GetByTechnique(MongoDB, TechBlind) returned %d payloads", len(payloads))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
