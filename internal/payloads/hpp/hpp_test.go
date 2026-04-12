package hpp

import (
	"testing"
)

func TestGetPayloads_ReturnsNonEmpty(t *testing.T) {
	payloads := GetPayloads()
	if len(payloads) == 0 {
		t.Error("GetPayloads() returned empty slice, want non-empty")
	}
}

func TestGetPayloads_AllFieldsPopulated(t *testing.T) {
	payloads := GetPayloads()
	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("payload[%d].Value is empty", i)
		}
		if p.Description == "" {
			t.Errorf("payload[%d].Description is empty", i)
		}
	}
}

func TestGetPayloads_ContainsDuplicateParamPayloads(t *testing.T) {
	payloads := GetPayloads()
	found := false
	for _, p := range payloads {
		if !p.WAFBypass && p.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetPayloads() should contain at least one non-WAF-bypass payload")
	}
}

func TestGetPayloads_ContainsWAFBypassPayloads(t *testing.T) {
	payloads := GetPayloads()
	found := false
	for _, p := range payloads {
		if p.WAFBypass {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetPayloads() should contain at least one WAF bypass payload")
	}
}

func TestPayload_StructFields(t *testing.T) {
	p := Payload{
		Value:       "injected_value",
		Description: "Test payload for duplicate parameter",
		WAFBypass:   true,
	}

	if p.Value != "injected_value" {
		t.Errorf("Payload.Value = %q, want %q", p.Value, "injected_value")
	}
	if p.Description != "Test payload for duplicate parameter" {
		t.Errorf("Payload.Description = %q, want %q", p.Description, "Test payload for duplicate parameter")
	}
	if !p.WAFBypass {
		t.Error("Payload.WAFBypass should be true")
	}
}

func TestGetPayloads_NoDuplicateValues(t *testing.T) {
	payloads := GetPayloads()
	seen := make(map[string]bool)
	for _, p := range payloads {
		if seen[p.Value] {
			t.Errorf("duplicate payload value: %q", p.Value)
		}
		seen[p.Value] = true
	}
}

func TestGetPayloads_ContainsArrayStylePayloads(t *testing.T) {
	payloads := GetPayloads()
	found := false
	for _, p := range payloads {
		if contains(p.Value, "[]") || contains(p.Description, "array") {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetPayloads() should contain at least one array-style parameter payload")
	}
}

func TestGetPayloads_ContainsEncodingVariants(t *testing.T) {
	payloads := GetPayloads()
	found := false
	for _, p := range payloads {
		if contains(p.Value, "%") || contains(p.Description, "encod") {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetPayloads() should contain at least one encoding variant payload")
	}
}

// contains is a helper that checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

// searchSubstring performs a simple substring search.
func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
