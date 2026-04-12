package ssi

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	payloads := GetPayloads()
	if len(payloads) == 0 {
		t.Error("GetPayloads() returned no payloads")
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads() returned no payloads")
	}
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads() returned payload without WAFBypass flag: %s", p.Value)
		}
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()
	if len(payloads) == 0 {
		t.Error("GetAllPayloads() returned no payloads")
	}

	hasStandard := false
	hasWAF := false
	for _, p := range payloads {
		if p.WAFBypass {
			hasWAF = true
		} else {
			hasStandard = true
		}
	}
	if !hasStandard {
		t.Error("GetAllPayloads() should contain standard payloads")
	}
	if !hasWAF {
		t.Error("GetAllPayloads() should contain WAF bypass payloads")
	}
}

func TestPayloadFields(t *testing.T) {
	payloads := GetAllPayloads()
	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d (%q) has empty Description", i, truncate(p.Value, 30))
		}
		if p.Marker == "" {
			t.Errorf("Payload %d (%q) has empty Marker", i, truncate(p.Value, 30))
		}
	}
}

func TestCorePayloadsPresent(t *testing.T) {
	payloads := GetPayloads()

	// Verify SSI directive types are present
	expectedSubstrings := []string{
		"#exec",
		"#include",
		"#echo",
	}

	for _, expected := range expectedSubstrings {
		found := false
		for _, p := range payloads {
			if containsSubstring(p.Value, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected SSI directive containing %q not found", expected)
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	payloads := GetAllPayloads()
	seen := make(map[string]bool)
	for _, p := range payloads {
		if seen[p.Value] {
			t.Errorf("Duplicate payload found: %s", truncate(p.Value, 40))
		}
		seen[p.Value] = true
	}
}

func TestPayloadMarkers(t *testing.T) {
	payloads := GetPayloads()
	for _, p := range payloads {
		if p.Marker == "" {
			t.Errorf("Payload %q has empty Marker", truncate(p.Value, 30))
		}
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
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
