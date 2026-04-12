package massassign

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		category Category
	}{
		{"Privilege", Privilege},
		{"Identity", Identity},
		{"Status", Status},
		{"Generic", Generic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.category)
			if len(payloads) == 0 {
				t.Errorf("GetPayloads(%s) returned no payloads", tt.category)
			}
		})
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()
	if len(payloads) == 0 {
		t.Error("GetAllPayloads returned no payloads")
	}

	// Verify we have payloads from multiple categories
	categories := make(map[Category]bool)
	for _, p := range payloads {
		categories[p.Category] = true
	}

	expectedCategories := []Category{Privilege, Identity, Status, Generic}
	for _, expected := range expectedCategories {
		if !categories[expected] {
			t.Errorf("GetAllPayloads missing payloads for %s", expected)
		}
	}
}

func TestGetExtraFields(t *testing.T) {
	fields := GetExtraFields()
	if len(fields) == 0 {
		t.Error("GetExtraFields returned no fields")
	}

	// Check that key privilege escalation fields are included
	expectedFields := []string{"isAdmin", "role", "admin", "id", "user_id", "email", "permissions", "verified"}
	for _, expected := range expectedFields {
		found := false
		for _, f := range fields {
			if f.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected extra field %q not found", expected)
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
			if len(truncated) > 30 {
				truncated = truncated[:30]
			}
			t.Errorf("Payload %q has empty Description", truncated)
		}
	}
}

func TestExtraFieldFields(t *testing.T) {
	fields := GetExtraFields()
	for i, f := range fields {
		if f.Name == "" {
			t.Errorf("ExtraField %d has empty Name", i)
		}
		if f.Value == nil {
			t.Errorf("ExtraField %d (%s) has nil Value", i, f.Name)
		}
	}
}

func TestCategory_String(t *testing.T) {
	tests := []struct {
		category Category
		want     string
	}{
		{Privilege, "privilege"},
		{Identity, "identity"},
		{Status, "status"},
		{Generic, "generic"},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			if string(tt.category) != tt.want {
				t.Errorf("Category = %q, want %q", string(tt.category), tt.want)
			}
		})
	}
}

func TestPrivilegePayloads(t *testing.T) {
	payloads := GetPayloads(Privilege)

	// Check for privilege escalation fields
	hasAdmin := false
	hasRole := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "admin") || containsSubstring(p.Value, "isAdmin") {
			hasAdmin = true
		}
		if containsSubstring(p.Value, "role") {
			hasRole = true
		}
	}

	if !hasAdmin {
		t.Error("Expected admin-related privilege escalation payloads")
	}
	if !hasRole {
		t.Error("Expected role-related privilege escalation payloads")
	}
}

func TestIdentityPayloads(t *testing.T) {
	payloads := GetPayloads(Identity)
	if len(payloads) == 0 {
		t.Error("Expected identity payloads")
	}

	hasID := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "id") || containsSubstring(p.Value, "user_id") || containsSubstring(p.Value, "email") {
			hasID = true
			break
		}
	}
	if !hasID {
		t.Error("Expected identity-related payloads")
	}
}

func TestDeduplicatePayloads(t *testing.T) {
	payloads := []Payload{
		{Value: `{"isAdmin": true}`, Category: Privilege},
		{Value: `{"role": "admin"}`, Category: Privilege},
		{Value: `{"isAdmin": true}`, Category: Privilege}, // duplicate
		{Value: `{"id": 1}`, Category: Identity},
		{Value: `{"isAdmin": true}`, Category: Identity}, // different category
	}

	deduped := DeduplicatePayloads(payloads)

	if len(deduped) != 4 {
		t.Errorf("DeduplicatePayloads() returned %d payloads, want 4", len(deduped))
	}
}

func TestGetPayloads_UnknownCategory(t *testing.T) {
	payloads := GetPayloads(Category("unknown"))
	genericPayloads := GetPayloads(Generic)

	if len(payloads) != len(genericPayloads) {
		t.Errorf("Unknown category should return generic payloads, got %d, want %d", len(payloads), len(genericPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		key := p.Value + "|" + string(p.Category)
		if seen[key] {
			duplicates++
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", p.Value)
		}
	}
}

// containsSubstring checks if a string contains a substring.
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
