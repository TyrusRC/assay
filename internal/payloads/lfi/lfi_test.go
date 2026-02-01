package lfi

import (
	"strings"
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		platform Platform
		minCount int
	}{
		{"Linux", PlatformLinux, 30},
		{"Windows", PlatformWindows, 10},
		{"Both", PlatformBoth, 40},
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

func TestGetByTechnique(t *testing.T) {
	tests := []struct {
		name      string
		technique Technique
		minCount  int
	}{
		{"Basic", TechBasic, 20},
		{"Encoding", TechEncoding, 5},
		{"Wrapper", TechWrapper, 10},
		{"NullByte", TechNullByte, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetByTechnique(tt.technique)
			if len(payloads) < tt.minCount {
				t.Errorf("GetByTechnique(%s) returned %d payloads, want at least %d",
					tt.technique, len(payloads), tt.minCount)
			}

			for _, p := range payloads {
				if p.Technique != tt.technique {
					t.Errorf("Payload technique = %s, want %s", p.Technique, tt.technique)
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
	if len(all) == 0 {
		t.Error("GetAllPayloads() returned empty slice")
	}

	// Verify we have payloads for both platforms
	hasLinux := false
	hasWindows := false
	for _, p := range all {
		if p.Platform == PlatformLinux {
			hasLinux = true
		}
		if p.Platform == PlatformWindows {
			hasWindows = true
		}
	}

	if !hasLinux {
		t.Error("No Linux payloads found")
	}
	if !hasWindows {
		t.Error("No Windows payloads found")
	}
}

func TestGenerateTraversalPayloads(t *testing.T) {
	payloads := GenerateTraversalPayloads("etc/passwd", 5)

	if len(payloads) != 5 {
		t.Errorf("GenerateTraversalPayloads() returned %d payloads, want 5", len(payloads))
	}

	// Verify increasing depth
	for i, p := range payloads {
		expectedPrefix := strings.Repeat("../", i+1)
		if !strings.HasPrefix(p.Value, expectedPrefix) {
			t.Errorf("Payload %d doesn't have expected prefix %s", i, expectedPrefix)
		}
	}
}

func TestPayloadCategories(t *testing.T) {
	all := GetAllPayloads()

	for _, p := range all {
		switch p.Platform {
		case PlatformLinux, PlatformWindows, PlatformBoth:
			// Valid
		default:
			t.Errorf("Invalid platform: %s", p.Platform)
		}

		switch p.Technique {
		case TechBasic, TechNullByte, TechEncoding, TechWrapper, TechFilter:
			// Valid
		default:
			t.Errorf("Invalid technique: %s", p.Technique)
		}
	}
}

func TestLinuxPayloadsContainEtcPasswd(t *testing.T) {
	payloads := GetPayloads(PlatformLinux)

	hasPasswd := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "etc/passwd") || strings.Contains(p.Value, "etc%2fpasswd") {
			hasPasswd = true
			break
		}
	}

	if !hasPasswd {
		t.Error("Linux payloads should include /etc/passwd traversal")
	}
}

func TestWindowsPayloadsContainWinIni(t *testing.T) {
	payloads := GetPayloads(PlatformWindows)

	hasWinIni := false
	for _, p := range payloads {
		if strings.Contains(strings.ToLower(p.Value), "win.ini") {
			hasWinIni = true
			break
		}
	}

	if !hasWinIni {
		t.Error("Windows payloads should include win.ini traversal")
	}
}

func TestGetPayloads_BothPlatforms(t *testing.T) {
	payloads := GetPayloads(PlatformBoth)

	// Should include both Linux and Windows payloads
	hasLinux := false
	hasWindows := false

	for _, p := range payloads {
		if p.Platform == PlatformLinux {
			hasLinux = true
		}
		if p.Platform == PlatformWindows {
			hasWindows = true
		}
	}

	if !hasLinux {
		t.Error("PlatformBoth should include Linux payloads")
	}
	if !hasWindows {
		t.Error("PlatformBoth should include Windows payloads")
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
		if p.Technique == "" {
			t.Errorf("Payload %d has empty Technique", i)
		}
	}
}

func TestAllTechniquesHavePayloads(t *testing.T) {
	all := GetAllPayloads()
	techniques := make(map[Technique]bool)

	for _, p := range all {
		techniques[p.Technique] = true
	}

	expectedTechniques := []Technique{TechBasic, TechEncoding, TechWrapper}
	for _, expected := range expectedTechniques {
		if !techniques[expected] {
			t.Errorf("No payloads found for technique %s", expected)
		}
	}
}

func TestGenerateTraversalPayloads_ZeroDepth(t *testing.T) {
	payloads := GenerateTraversalPayloads("etc/passwd", 0)
	if len(payloads) != 0 {
		t.Errorf("Zero depth should return empty slice, got %d", len(payloads))
	}
}

func TestGenerateTraversalPayloads_SingleDepth(t *testing.T) {
	payloads := GenerateTraversalPayloads("etc/passwd", 1)
	if len(payloads) != 1 {
		t.Errorf("Single depth should return 1 payload, got %d", len(payloads))
	}
	if payloads[0].Value != "../etc/passwd" {
		t.Errorf("Expected '../etc/passwd', got %s", payloads[0].Value)
	}
}

func TestWrapperPayloadsExist(t *testing.T) {
	payloads := GetByTechnique(TechWrapper)

	hasPhpFilter := false
	hasDataWrapper := false

	for _, p := range payloads {
		if strings.Contains(p.Value, "php://filter") {
			hasPhpFilter = true
		}
		if strings.Contains(p.Value, "data://") {
			hasDataWrapper = true
		}
	}

	if !hasPhpFilter {
		t.Error("Wrapper payloads should include php://filter")
	}
	if !hasDataWrapper {
		t.Error("Wrapper payloads should include data://")
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
