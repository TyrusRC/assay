package ldap

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	payloads := GetPayloads()
	if len(payloads) == 0 {
		t.Error("GetPayloads returned no payloads")
	}

	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Type == "" {
			t.Errorf("Payload %d has empty Type", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty Description", i)
		}
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads returned no payloads")
	}
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", truncate(p.Value, 40))
		}
	}
}

func TestGetByType(t *testing.T) {
	tests := []struct {
		name     string
		injType  InjectionType
		minCount int
	}{
		{"filter_bypass", TypeFilterBypass, 3},
		{"wildcard", TypeWildcard, 1},
		{"bool_based", TypeBoolBased, 2},
		{"error_based", TypeErrorBased, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetByType(tt.injType)
			if len(payloads) < tt.minCount {
				t.Errorf("GetByType(%s) returned %d payloads, want at least %d", tt.injType, len(payloads), tt.minCount)
			}
			for _, p := range payloads {
				if p.Type != tt.injType {
					t.Errorf("GetByType(%s) returned payload with Type %s", tt.injType, p.Type)
				}
			}
		})
	}
}

func TestGetByType_UnknownType(t *testing.T) {
	payloads := GetByType(InjectionType("unknown"))
	if len(payloads) != 0 {
		t.Errorf("GetByType with unknown type returned %d payloads, want 0", len(payloads))
	}
}

func TestGetErrorPatterns(t *testing.T) {
	patterns := GetErrorPatterns()
	if len(patterns) == 0 {
		t.Error("GetErrorPatterns returned no patterns")
	}

	for i, p := range patterns {
		if p == "" {
			t.Errorf("ErrorPattern %d is empty", i)
		}
	}
}

func TestErrorPatternsContainLDAPReferences(t *testing.T) {
	patterns := GetErrorPatterns()
	ldapCount := 0
	for _, p := range patterns {
		if containsIgnoreCase(p, "ldap") {
			ldapCount++
		}
	}

	if ldapCount == 0 {
		t.Error("ErrorPatterns do not contain any LDAP-related patterns")
	}
}

func TestPayloadValidTypes(t *testing.T) {
	payloads := GetPayloads()
	validTypes := map[InjectionType]bool{
		TypeFilterBypass: true,
		TypeWildcard:     true,
		TypeBoolBased:    true,
		TypeErrorBased:   true,
	}

	for _, p := range payloads {
		if !validTypes[p.Type] {
			t.Errorf("Invalid type %s for payload %s", p.Type, truncate(p.Value, 30))
		}
	}
}

func TestFilterBypassPayloadsContainLDAPChars(t *testing.T) {
	payloads := GetByType(TypeFilterBypass)
	ldapChars := []string{"*", "(", ")", "&", "|", "%26", "%28", "%29", "%2a"}
	for _, p := range payloads {
		if p.WAFBypass {
			continue // WAF bypass payloads may be URL-encoded
		}
		found := false
		for _, ch := range ldapChars {
			if containsStr(p.Value, ch) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Filter bypass payload does not contain LDAP special chars: %s", truncate(p.Value, 40))
		}
	}
}

func TestAllTypesHavePayloads(t *testing.T) {
	types := []InjectionType{TypeFilterBypass, TypeWildcard, TypeBoolBased, TypeErrorBased}
	for _, injType := range types {
		payloads := GetByType(injType)
		if len(payloads) == 0 {
			t.Errorf("Type %s has no payloads", injType)
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		key := p.Value + "|" + string(p.Type)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (Type: %s)", truncate(p.Value, 40), p.Type)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestNoDuplicateErrorPatterns(t *testing.T) {
	patterns := GetErrorPatterns()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range patterns {
		if seen[p] {
			duplicates++
			t.Logf("Duplicate error pattern: %s", p)
		}
		seen[p] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate error patterns", duplicates)
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			tc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 'a' - 'A'
			}
			if tc >= 'A' && tc <= 'Z' {
				tc += 'a' - 'A'
			}
			if sc != tc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
