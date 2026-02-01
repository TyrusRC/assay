package sqli

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		dbType   DBType
		minCount int
	}{
		{"MySQL", MySQL, 10},
		{"PostgreSQL", PostgreSQL, 5},
		{"MSSQL", MSSQL, 5},
		{"Oracle", Oracle, 5},
		{"SQLite", SQLite, 5},
		{"Generic", Generic, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.dbType)
			if len(payloads) < tt.minCount {
				t.Errorf("GetPayloads(%s) returned %d payloads, want at least %d", tt.dbType, len(payloads), tt.minCount)
			}

			// Verify each payload has required fields
			for _, p := range payloads {
				if p.Value == "" {
					t.Error("Payload has empty Value")
				}
				if p.Description == "" {
					t.Error("Payload has empty Description")
				}
			}
		})
	}
}

func TestGetPayloads_UnknownDBType(t *testing.T) {
	// Unknown DB type should return generic payloads
	payloads := GetPayloads(DBType("unknown"))
	genericPayloads := GetPayloads(Generic)

	if len(payloads) != len(genericPayloads) {
		t.Errorf("Unknown DB type should return generic payloads, got %d, want %d", len(payloads), len(genericPayloads))
	}
}

func TestGetByTechnique(t *testing.T) {
	techniques := []Technique{TechUnion, TechError, TechBlind, TechTimeBased, TechStacked}

	for _, tech := range techniques {
		t.Run(string(tech), func(t *testing.T) {
			payloads := GetByTechnique(MySQL, tech)
			for _, p := range payloads {
				if p.Technique != tech {
					t.Errorf("GetByTechnique(%s) returned payload with technique %s", tech, p.Technique)
				}
			}
		})
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads(MySQL)
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

func TestPayloadFields(t *testing.T) {
	payloads := GetAllPayloads()
	for _, p := range payloads {
		if p.Value == "" {
			t.Error("Payload has empty Value")
		}
		if p.Description == "" {
			t.Errorf("Payload %q has empty Description", p.Value[:min(20, len(p.Value))])
		}
	}
}

func TestGetAllPayloads(t *testing.T) {
	all := GetAllPayloads()
	if len(all) == 0 {
		t.Error("GetAllPayloads returned no payloads")
	}

	// Verify we have payloads from multiple database types
	dbTypes := make(map[DBType]bool)
	for _, p := range all {
		dbTypes[p.DBType] = true
	}

	expectedDBTypes := []DBType{MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Generic}
	for _, expected := range expectedDBTypes {
		if !dbTypes[expected] {
			t.Errorf("GetAllPayloads missing payloads for %s", expected)
		}
	}
}

func TestGetWAFBypassPayloads_NonEmpty(t *testing.T) {
	// Test WAF bypass payloads for multiple DB types
	dbTypes := []DBType{MySQL, Generic}
	for _, dbType := range dbTypes {
		payloads := GetWAFBypassPayloads(dbType)
		if len(payloads) == 0 {
			t.Errorf("GetWAFBypassPayloads(%s) returned no payloads", dbType)
		}
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
			// Only report first few duplicates to avoid spam
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

func TestPayloadValidTechniques(t *testing.T) {
	all := GetAllPayloads()
	validTechniques := map[Technique]bool{
		TechUnion:     true,
		TechError:     true,
		TechBlind:     true,
		TechTimeBased: true,
		TechStacked:   true,
	}

	for _, p := range all {
		if !validTechniques[p.Technique] {
			t.Errorf("Invalid technique %s for payload %s", p.Technique, truncate(p.Value, 30))
		}
	}
}

func TestPayloadValidDBTypes(t *testing.T) {
	all := GetAllPayloads()
	validDBTypes := map[DBType]bool{
		MySQL:      true,
		PostgreSQL: true,
		MSSQL:      true,
		Oracle:     true,
		SQLite:     true,
		Generic:    true,
	}

	for _, p := range all {
		if !validDBTypes[p.DBType] {
			t.Errorf("Invalid DB type %s for payload %s", p.DBType, truncate(p.Value, 30))
		}
	}
}

func TestGetByTechnique_AllTechniques(t *testing.T) {
	techniques := []Technique{TechUnion, TechError, TechBlind, TechTimeBased, TechStacked}

	// At least one technique should have payloads for MySQL
	hasPayloads := false
	for _, tech := range techniques {
		payloads := GetByTechnique(MySQL, tech)
		if len(payloads) > 0 {
			hasPayloads = true
		}
	}

	if !hasPayloads {
		t.Error("Expected at least one technique to have payloads for MySQL")
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
