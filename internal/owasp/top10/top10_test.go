package top10

import (
	"testing"
)

func TestGetCategory(t *testing.T) {
	tests := []struct {
		id       string
		expected bool
	}{
		{"A01:2021", true},
		{"A03:2021", true},
		{"A10:2021", true},
		{"A01:2025", true},
		{"A03:2025", true},
		{"A10:2025", true},
		{"A11:2021", false},
		{"A11:2025", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			cat := GetCategory(tt.id)
			if tt.expected && cat == nil {
				t.Errorf("Expected category for %s", tt.id)
			}
			if !tt.expected && cat != nil {
				t.Errorf("Expected nil for %s", tt.id)
			}
		})
	}
}

func TestGetCategory_Fields(t *testing.T) {
	cat := GetCategory("A03:2021")
	if cat == nil {
		t.Fatal("Expected non-nil category")
	}

	if cat.ID != "A03:2021" {
		t.Errorf("Expected ID 'A03:2021', got '%s'", cat.ID)
	}
	if cat.Name != "Injection" {
		t.Errorf("Expected name 'Injection', got '%s'", cat.Name)
	}
	if cat.Description == "" {
		t.Error("Expected non-empty description")
	}
	if len(cat.CWEs) == 0 {
		t.Error("Expected non-empty CWEs list")
	}
	if cat.Remediation == "" {
		t.Error("Expected non-empty remediation")
	}
}

func TestGetCategory_2025Fields(t *testing.T) {
	cat := GetCategory("A03:2025")
	if cat == nil {
		t.Fatal("Expected non-nil category for A03:2025")
	}

	if cat.ID != "A03:2025" {
		t.Errorf("Expected ID 'A03:2025', got '%s'", cat.ID)
	}
	if cat.Version != "2025" {
		t.Errorf("Expected Version '2025', got '%s'", cat.Version)
	}
	if cat.Name != "Injection" {
		t.Errorf("Expected name 'Injection', got '%s'", cat.Name)
	}
	if cat.Description == "" {
		t.Error("Expected non-empty description")
	}
	if len(cat.CWEs) == 0 {
		t.Error("Expected non-empty CWEs list")
	}
	if cat.Remediation == "" {
		t.Error("Expected non-empty remediation")
	}
}

func TestGetCategory_2021HasVersion(t *testing.T) {
	cat := GetCategory("A03:2021")
	if cat == nil {
		t.Fatal("Expected non-nil category")
	}
	if cat.Version != "2021" {
		t.Errorf("Expected Version '2021', got '%s'", cat.Version)
	}
}

func TestGetRisk(t *testing.T) {
	tests := []struct {
		id       string
		expected bool
	}{
		{"A01:2021", true},
		{"A03:2021", true},
		{"A10:2021", true},
		{"A01:2025", true},
		{"A03:2025", true},
		{"A10:2025", true},
		{"A04:2021", false}, // Not all categories have risk metadata
		{"A04:2025", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			risk := GetRisk(tt.id)
			if tt.expected && risk == nil {
				t.Errorf("Expected risk for %s", tt.id)
			}
			if !tt.expected && risk != nil {
				t.Errorf("Expected nil for %s", tt.id)
			}
		})
	}
}

func TestGetRisk_Fields(t *testing.T) {
	risk := GetRisk("A01:2021")
	if risk == nil {
		t.Fatal("Expected non-nil risk")
	}

	if risk.Rank != 1 {
		t.Errorf("Expected rank 1, got %d", risk.Rank)
	}
	if risk.IncidenceRate == "" {
		t.Error("Expected non-empty incidence rate")
	}
	if risk.AvgCVSS <= 0 {
		t.Error("Expected positive AvgCVSS")
	}
	if risk.MaxCVSS <= 0 {
		t.Error("Expected positive MaxCVSS")
	}
	if len(risk.CommonCWEs) == 0 {
		t.Error("Expected non-empty CommonCWEs")
	}
}

func TestGetAllCategories(t *testing.T) {
	cats := GetAllCategories()

	if len(cats) != 20 {
		t.Errorf("Expected 20 categories (10 for 2021 + 10 for 2025), got %d", len(cats))
	}

	// Verify all 2021 categories are present
	expectedIDs := []string{
		"A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
		"A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
	}

	for _, id := range expectedIDs {
		if _, ok := cats[id]; !ok {
			t.Errorf("Missing category %s", id)
		}
	}

	// Verify all 2025 categories are present
	expected2025IDs := []string{
		"A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025",
		"A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025",
	}

	for _, id := range expected2025IDs {
		if _, ok := cats[id]; !ok {
			t.Errorf("Missing category %s", id)
		}
	}
}

func TestGetTop10ForVulnerability(t *testing.T) {
	tests := []struct {
		vulnType string
		expected string
	}{
		{"SQL Injection", "A03:2025"},
		{"XSS", "A03:2025"},
		{"Command Injection", "A03:2025"},
		{"SSRF", "A10:2025"},
		{"LFI", "A01:2025"},
		{"XXE", "A05:2025"},
		{"Broken Access Control", "A01:2025"},
		{"Unknown Vuln", ""},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType, func(t *testing.T) {
			id := GetTop10ForVulnerability(tt.vulnType)
			if id != tt.expected {
				t.Errorf("Expected '%s' for '%s', got '%s'", tt.expected, tt.vulnType, id)
			}
		})
	}
}

func TestVulnerabilityMapping(t *testing.T) {
	// Verify all mapped Top 10 IDs exist
	for vuln, id := range VulnerabilityMapping {
		cat := GetCategory(id)
		if cat == nil {
			t.Errorf("Vulnerability '%s' maps to non-existent category '%s'", vuln, id)
		}
	}
}

func TestVulnerabilityMappingPointsTo2025(t *testing.T) {
	// Verify all mapped IDs point to 2025 versions
	for vuln, id := range VulnerabilityMapping {
		if !isValid2025ID(id) {
			t.Errorf("Vulnerability '%s' maps to '%s', expected a 2025 ID", vuln, id)
		}
	}
}

func isValid2025ID(id string) bool {
	valid2025IDs := map[string]bool{
		"A01:2025": true, "A02:2025": true, "A03:2025": true, "A04:2025": true,
		"A05:2025": true, "A06:2025": true, "A07:2025": true, "A08:2025": true,
		"A09:2025": true, "A10:2025": true,
	}
	return valid2025IDs[id]
}

func TestGetSeverityForCategory(t *testing.T) {
	tests := []struct {
		id       string
		expected string
	}{
		{"A01:2021", "medium"}, // AvgCVSS 6.92
		{"A03:2021", "high"},   // AvgCVSS 7.25
		{"A10:2021", "high"},   // AvgCVSS 8.28
		{"A01:2025", "medium"}, // Same stats as 2021
		{"A03:2025", "high"},
		{"A10:2025", "high"},
		{"invalid", "medium"}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			sev := GetSeverityForCategory(tt.id)
			if sev != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, sev)
			}
		})
	}
}

func TestCWE_Fields(t *testing.T) {
	risk := GetRisk("A03:2021")
	if risk == nil {
		t.Fatal("Expected non-nil risk")
	}

	for _, cwe := range risk.CommonCWEs {
		if cwe.ID == "" {
			t.Error("CWE ID should not be empty")
		}
		if cwe.Name == "" {
			t.Error("CWE Name should not be empty")
		}
		if cwe.Description == "" {
			t.Error("CWE Description should not be empty")
		}
	}
}

func TestCategoryHasCorrectCWEs(t *testing.T) {
	// A03:2021 (Injection) should include SQL Injection CWE
	cat := GetCategory("A03:2021")
	if cat == nil {
		t.Fatal("Expected non-nil category")
	}

	hasSQLiCWE := false
	for _, cwe := range cat.CWEs {
		if cwe == "CWE-89" {
			hasSQLiCWE = true
			break
		}
	}

	if !hasSQLiCWE {
		t.Error("A03:2021 should include CWE-89 (SQL Injection)")
	}

	// A10:2021 (SSRF) should include CWE-918
	catSSRF := GetCategory("A10:2021")
	if catSSRF == nil {
		t.Fatal("Expected non-nil category")
	}

	hasSSRFCWE := false
	for _, cwe := range catSSRF.CWEs {
		if cwe == "CWE-918" {
			hasSSRFCWE = true
			break
		}
	}

	if !hasSSRFCWE {
		t.Error("A10:2021 should include CWE-918 (SSRF)")
	}
}

func TestGetLatestCategory(t *testing.T) {
	tests := []struct {
		baseID   string
		expected string
	}{
		{"A01", "A01:2025"},
		{"A03", "A03:2025"},
		{"A10", "A10:2025"},
		{"A00", ""},   // Invalid
		{"A11", ""},   // Invalid
		{"", ""},      // Empty
		{"ZZZ", ""},   // Nonsense
	}

	for _, tt := range tests {
		t.Run(tt.baseID, func(t *testing.T) {
			cat := GetLatestCategory(tt.baseID)
			if tt.expected == "" {
				if cat != nil {
					t.Errorf("Expected nil for '%s', got %+v", tt.baseID, cat)
				}
			} else {
				if cat == nil {
					t.Fatalf("Expected non-nil category for '%s'", tt.baseID)
				}
				if cat.ID != tt.expected {
					t.Errorf("Expected ID '%s', got '%s'", tt.expected, cat.ID)
				}
				if cat.Version != "2025" {
					t.Errorf("Expected Version '2025', got '%s'", cat.Version)
				}
			}
		})
	}
}

func TestGetRisk_2025(t *testing.T) {
	tests := []struct {
		id2021   string
		id2025   string
		wantRank int
	}{
		{"A01:2021", "A01:2025", 1},
		{"A02:2021", "A02:2025", 2},
		{"A03:2021", "A03:2025", 3},
		{"A10:2021", "A10:2025", 10},
	}

	for _, tt := range tests {
		t.Run(tt.id2025, func(t *testing.T) {
			risk2025 := GetRisk(tt.id2025)
			if risk2025 == nil {
				t.Fatalf("Expected non-nil risk for %s", tt.id2025)
			}
			if risk2025.Rank != tt.wantRank {
				t.Errorf("Expected rank %d for %s, got %d", tt.wantRank, tt.id2025, risk2025.Rank)
			}

			// 2025 risk should have same stats as 2021
			risk2021 := GetRisk(tt.id2021)
			if risk2021 == nil {
				t.Fatalf("Expected non-nil risk for %s", tt.id2021)
			}
			if risk2025.AvgCVSS != risk2021.AvgCVSS {
				t.Errorf("Expected same AvgCVSS for %s and %s", tt.id2021, tt.id2025)
			}
		})
	}
}

func TestCategory2025HasSameDataAs2021(t *testing.T) {
	pairs := []struct {
		id2021 string
		id2025 string
	}{
		{"A01:2021", "A01:2025"},
		{"A02:2021", "A02:2025"},
		{"A03:2021", "A03:2025"},
		{"A04:2021", "A04:2025"},
		{"A05:2021", "A05:2025"},
		{"A06:2021", "A06:2025"},
		{"A07:2021", "A07:2025"},
		{"A08:2021", "A08:2025"},
		{"A09:2021", "A09:2025"},
		{"A10:2021", "A10:2025"},
	}

	for _, pair := range pairs {
		t.Run(pair.id2025, func(t *testing.T) {
			cat2021 := GetCategory(pair.id2021)
			cat2025 := GetCategory(pair.id2025)
			if cat2021 == nil {
				t.Fatalf("Missing %s", pair.id2021)
			}
			if cat2025 == nil {
				t.Fatalf("Missing %s", pair.id2025)
			}
			if cat2021.Name != cat2025.Name {
				t.Errorf("Name mismatch: %s vs %s", cat2021.Name, cat2025.Name)
			}
			if cat2021.Description != cat2025.Description {
				t.Errorf("Description mismatch for %s", pair.id2025)
			}
			if cat2021.Remediation != cat2025.Remediation {
				t.Errorf("Remediation mismatch for %s", pair.id2025)
			}
			if len(cat2021.CWEs) != len(cat2025.CWEs) {
				t.Errorf("CWEs length mismatch for %s: %d vs %d", pair.id2025, len(cat2021.CWEs), len(cat2025.CWEs))
			}
		})
	}
}
