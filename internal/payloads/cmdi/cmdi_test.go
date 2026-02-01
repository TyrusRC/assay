package cmdi

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		platform Platform
		minCount int
	}{
		{"Linux", PlatformLinux, 10},
		{"Windows", PlatformWindows, 10},
		{"Both", PlatformBoth, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.platform)
			if len(payloads) < tt.minCount {
				t.Errorf("GetPayloads(%s) returned %d payloads, want at least %d",
					tt.platform, len(payloads), tt.minCount)
			}

			for _, p := range payloads {
				if p.Value == "" {
					t.Error("Payload has empty value")
				}
				if p.Description == "" {
					t.Error("Payload has empty description")
				}
			}
		})
	}
}

func TestGetByType(t *testing.T) {
	tests := []struct {
		name     string
		platform Platform
		injType  InjectionType
		minCount int
	}{
		{"Linux Chained", PlatformLinux, TypeChained, 5},
		{"Linux TimeBased", PlatformLinux, TypeTimeBased, 3},
		{"Windows Chained", PlatformWindows, TypeChained, 5},
		{"Windows TimeBased", PlatformWindows, TypeTimeBased, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetByType(tt.platform, tt.injType)
			if len(payloads) < tt.minCount {
				t.Errorf("GetByType(%s, %s) returned %d payloads, want at least %d",
					tt.platform, tt.injType, len(payloads), tt.minCount)
			}

			for _, p := range payloads {
				if p.Type != tt.injType {
					t.Errorf("Payload type = %s, want %s", p.Type, tt.injType)
				}
			}
		})
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads() returned empty slice")
	}

	for _, p := range payloads {
		if !p.WAFBypass {
			t.Error("GetWAFBypassPayloads() returned non-bypass payload")
		}
	}
}

func TestGetAllPayloads(t *testing.T) {
	all := GetAllPayloads()

	linuxCount := len(linuxPayloads)
	windowsCount := len(windowsPayloads)
	bothCount := len(bothPayloads)
	expected := linuxCount + windowsCount + bothCount

	if len(all) != expected {
		t.Errorf("GetAllPayloads() returned %d payloads, want %d", len(all), expected)
	}
}

func TestPayloadCategories(t *testing.T) {
	// Verify all payloads have valid categories
	all := GetAllPayloads()

	for _, p := range all {
		switch p.Platform {
		case PlatformLinux, PlatformWindows, PlatformBoth:
			// Valid
		default:
			t.Errorf("Invalid platform: %s", p.Platform)
		}

		switch p.Type {
		case TypeDirect, TypeChained, TypeTimeBased, TypeBlind:
			// Valid
		default:
			t.Errorf("Invalid injection type: %s", p.Type)
		}
	}
}

func TestGetPayloads_UnknownPlatform(t *testing.T) {
	// Unknown platform should return "both" payloads (default)
	payloads := GetPayloads(Platform("unknown"))
	bothPayloads := GetPayloads(PlatformBoth)

	if len(payloads) != len(bothPayloads) {
		t.Errorf("Unknown platform should return both payloads, got %d, want %d", len(payloads), len(bothPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		// Key is value + platform to allow same payload for different platforms
		key := p.Value + "|" + string(p.Platform)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (Platform: %s)", truncate(p.Value, 40), p.Platform)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestPayloadFieldsComplete(t *testing.T) {
	all := GetAllPayloads()

	for i, p := range all {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty Description", i)
		}
		if p.Platform == "" {
			t.Errorf("Payload %d has empty Platform", i)
		}
		if p.Type == "" {
			t.Errorf("Payload %d has empty Type", i)
		}
	}
}

func TestAllPlatformsHavePayloads(t *testing.T) {
	platforms := []Platform{PlatformLinux, PlatformWindows, PlatformBoth}

	for _, platform := range platforms {
		payloads := GetPayloads(platform)
		if len(payloads) == 0 {
			t.Errorf("Platform %s has no payloads", platform)
		}
	}
}

func TestAllInjectionTypesHavePayloads(t *testing.T) {
	all := GetAllPayloads()
	types := make(map[InjectionType]bool)

	for _, p := range all {
		types[p.Type] = true
	}

	expectedTypes := []InjectionType{TypeDirect, TypeChained, TypeTimeBased, TypeBlind}
	for _, expected := range expectedTypes {
		if !types[expected] {
			t.Errorf("No payloads found for injection type %s", expected)
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
