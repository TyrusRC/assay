package headerinj

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
		{"newline", TypeNewline, 3},
		{"host_header", TypeHostHeader, 2},
		{"response_split", TypeResponseSplit, 1},
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

func TestPayloadValidTypes(t *testing.T) {
	payloads := GetPayloads()
	validTypes := map[InjectionType]bool{
		TypeNewline:       true,
		TypeHostHeader:    true,
		TypeResponseSplit: true,
	}

	for _, p := range payloads {
		if !validTypes[p.Type] {
			t.Errorf("Invalid type %s for payload %s", p.Type, truncate(p.Value, 30))
		}
	}
}

func TestNewlinePayloadsContainCRLF(t *testing.T) {
	payloads := GetByType(TypeNewline)
	for _, p := range payloads {
		hasCRLF := false
		crlfVariants := []string{"\r\n", "%0d%0a", "%0a", "%0d", "%E5%98%8A", "%c0%8d"}
		for _, variant := range crlfVariants {
			if containsIgnoreCase(p.Value, variant) {
				hasCRLF = true
				break
			}
		}
		// Unicode char variants
		if !hasCRLF && (containsRune(p.Value, '\u560d') || containsRune(p.Value, '\u560a')) {
			hasCRLF = true
		}
		if !hasCRLF {
			t.Errorf("Newline payload does not contain CRLF variant: %s", truncate(p.Value, 50))
		}
	}
}

func TestAllTypesHavePayloads(t *testing.T) {
	types := []InjectionType{TypeNewline, TypeHostHeader, TypeResponseSplit}
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

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
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
