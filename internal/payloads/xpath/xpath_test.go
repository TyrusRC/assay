package xpath

import (
	"strings"
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
		{"bool_based", TypeBoolBased, 5},
		{"error_based", TypeErrorBased, 3},
		{"union_based", TypeUnionBased, 3},
		{"blind_based", TypeBlindBased, 2},
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

func TestErrorPatternsContainXPathReferences(t *testing.T) {
	patterns := GetErrorPatterns()
	xpathCount := 0
	for _, p := range patterns {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "xpath") {
			xpathCount++
		}
	}

	if xpathCount == 0 {
		t.Error("ErrorPatterns do not contain any XPath-related patterns")
	}
}

func TestBoolBasedPayloadsContainOrCondition(t *testing.T) {
	payloads := GetByType(TypeBoolBased)
	for _, p := range payloads {
		if p.WAFBypass {
			continue // WAF bypass payloads may be encoded
		}
		lower := strings.ToLower(p.Value)
		if !strings.Contains(lower, "or") && !strings.Contains(lower, "||") && !strings.Contains(lower, "true()") {
			t.Errorf("Bool-based payload does not contain OR/true condition: %s", truncate(p.Value, 50))
		}
	}
}

func TestUnionBasedPayloadsContainXPathSyntax(t *testing.T) {
	payloads := GetByType(TypeUnionBased)
	xpathMarkers := []string{"|", "//", "name()", "contains("}
	for _, p := range payloads {
		found := false
		for _, marker := range xpathMarkers {
			if strings.Contains(p.Value, marker) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Union-based payload does not contain XPath syntax: %s", truncate(p.Value, 50))
		}
	}
}

func TestBlindBasedPayloadsContainXPathFunctions(t *testing.T) {
	payloads := GetByType(TypeBlindBased)
	xpathFunctions := []string{"substring(", "string-length(", "starts-with(", "contains(", "name()"}
	for _, p := range payloads {
		found := false
		for _, fn := range xpathFunctions {
			if strings.Contains(p.Value, fn) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Blind-based payload does not contain XPath function: %s", truncate(p.Value, 50))
		}
	}
}

func TestPayloadValidTypes(t *testing.T) {
	payloads := GetPayloads()
	validTypes := map[InjectionType]bool{
		TypeBoolBased:  true,
		TypeErrorBased: true,
		TypeUnionBased: true,
		TypeBlindBased: true,
	}

	for _, p := range payloads {
		if !validTypes[p.Type] {
			t.Errorf("Invalid type %s for payload %s", p.Type, truncate(p.Value, 30))
		}
	}
}

func TestAllTypesHavePayloads(t *testing.T) {
	types := []InjectionType{TypeBoolBased, TypeErrorBased, TypeUnionBased, TypeBlindBased}
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
