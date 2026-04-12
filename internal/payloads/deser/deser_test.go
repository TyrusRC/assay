package deser

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name    string
		variant Variant
	}{
		{"Java", Java},
		{"PHP", PHP},
		{"Python", Python},
		{"DotNet", DotNet},
		{"Generic", Generic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.variant)
			if len(payloads) == 0 {
				t.Errorf("GetPayloads(%s) returned no payloads", tt.variant)
			}
		})
	}
}

func TestGetByTechnique(t *testing.T) {
	techniques := []Technique{TechMarker, TechError, TechTimeBased, TechBlind}

	for _, tech := range techniques {
		t.Run(string(tech), func(t *testing.T) {
			payloads := GetByTechnique(Java, tech)
			for _, p := range payloads {
				if p.Technique != tech {
					t.Errorf("GetByTechnique(%s) returned payload with technique %s", tech, p.Technique)
				}
			}
		})
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads(Java)
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", p.Value)
		}
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()
	if len(payloads) == 0 {
		t.Error("GetAllPayloads returned no payloads")
	}

	// Verify we have payloads from multiple variants
	variants := make(map[Variant]bool)
	for _, p := range payloads {
		variants[p.Variant] = true
	}

	expectedVariants := []Variant{Java, PHP, Python, DotNet, Generic}
	for _, expected := range expectedVariants {
		if !variants[expected] {
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

func TestVariant_String(t *testing.T) {
	tests := []struct {
		variant Variant
		want    string
	}{
		{Java, "java"},
		{PHP, "php"},
		{Python, "python"},
		{DotNet, "dotnet"},
		{Generic, "generic"},
	}

	for _, tt := range tests {
		t.Run(string(tt.variant), func(t *testing.T) {
			if string(tt.variant) != tt.want {
				t.Errorf("Variant = %q, want %q", string(tt.variant), tt.want)
			}
		})
	}
}

func TestTechnique_String(t *testing.T) {
	tests := []struct {
		tech Technique
		want string
	}{
		{TechMarker, "marker"},
		{TechError, "error"},
		{TechTimeBased, "time"},
		{TechBlind, "blind"},
	}

	for _, tt := range tests {
		t.Run(string(tt.tech), func(t *testing.T) {
			if string(tt.tech) != tt.want {
				t.Errorf("Technique = %q, want %q", string(tt.tech), tt.want)
			}
		})
	}
}

func TestJavaPayloads(t *testing.T) {
	payloads := GetPayloads(Java)

	// Check that key Java serialization markers are included
	markers := []string{"rO0AB", "aced0005"}
	for _, marker := range markers {
		found := false
		for _, p := range payloads {
			if containsSubstring(p.Value, marker) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Java serialization marker %q not found in payloads", marker)
		}
	}
}

func TestPHPPayloads(t *testing.T) {
	payloads := GetPayloads(PHP)
	if len(payloads) == 0 {
		t.Error("Expected PHP payloads")
	}

	// Check for PHP serialization patterns
	hasSerialize := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "O:") || containsSubstring(p.Value, "a:") {
			hasSerialize = true
			break
		}
	}
	if !hasSerialize {
		t.Error("Expected PHP serialize format payloads")
	}
}

func TestPythonPayloads(t *testing.T) {
	payloads := GetPayloads(Python)
	if len(payloads) == 0 {
		t.Error("Expected Python payloads")
	}

	// Check for Python pickle markers
	hasPickle := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "pickle") || containsSubstring(p.Value, "cos") || containsSubstring(p.Value, "\\x80") {
			hasPickle = true
			break
		}
	}
	if !hasPickle {
		t.Error("Expected Python pickle payloads")
	}
}

func TestDotNetPayloads(t *testing.T) {
	payloads := GetPayloads(DotNet)
	if len(payloads) == 0 {
		t.Error("Expected .NET payloads")
	}

	// Check for .NET ViewState or ObjectStateFormatter markers
	hasViewState := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "VIEWSTATE") || containsSubstring(p.Value, "TypeConfuseDelegate") || containsSubstring(p.Value, "ObjectDataProvider") {
			hasViewState = true
			break
		}
	}
	if !hasViewState {
		t.Error("Expected .NET ViewState or serialization payloads")
	}
}

func TestDeduplicatePayloads(t *testing.T) {
	payloads := []Payload{
		{Value: "test1", Variant: Java},
		{Value: "test2", Variant: Java},
		{Value: "test1", Variant: Java},  // duplicate
		{Value: "test3", Variant: Java},
		{Value: "test2", Variant: PHP}, // different variant, same value
	}

	deduped := DeduplicatePayloads(payloads)

	if len(deduped) != 4 {
		t.Errorf("DeduplicatePayloads() returned %d payloads, want 4", len(deduped))
	}
}

func TestGetPayloads_UnknownVariant(t *testing.T) {
	payloads := GetPayloads(Variant("unknown"))
	genericPayloads := GetPayloads(Generic)

	if len(payloads) != len(genericPayloads) {
		t.Errorf("Unknown variant should return generic payloads, got %d, want %d", len(payloads), len(genericPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		key := p.Value + "|" + string(p.Variant)
		if seen[key] {
			duplicates++
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestAllTechniquesRepresented(t *testing.T) {
	all := GetAllPayloads()
	techniques := make(map[Technique]bool)

	for _, p := range all {
		techniques[p.Technique] = true
	}

	expectedTechniques := []Technique{TechMarker, TechError}
	for _, expected := range expectedTechniques {
		if !techniques[expected] {
			t.Errorf("No payloads found for technique %s", expected)
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
