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
		{"A11:2021", false},
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

func TestGetRisk(t *testing.T) {
	tests := []struct {
		id       string
		expected bool
	}{
		{"A01:2021", true},
		{"A03:2021", true},
		{"A10:2021", true},
		{"A04:2021", false}, // Not all categories have risk metadata
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

	if len(cats) != 10 {
		t.Errorf("Expected 10 categories, got %d", len(cats))
	}

	// Verify all categories are present
	expectedIDs := []string{
		"A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
		"A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
	}

	for _, id := range expectedIDs {
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
		{"SQL Injection", "A03:2021"},
		{"XSS", "A03:2021"},
		{"Command Injection", "A03:2021"},
		{"SSRF", "A10:2021"},
		{"LFI", "A01:2021"},
		{"XXE", "A05:2021"},
		{"Broken Access Control", "A01:2021"},
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

func TestGetSeverityForCategory(t *testing.T) {
	tests := []struct {
		id       string
		expected string
	}{
		{"A01:2021", "medium"}, // AvgCVSS 6.92
		{"A03:2021", "high"},   // AvgCVSS 7.25
		{"A10:2021", "high"},   // AvgCVSS 8.28
		{"invalid", "medium"},  // Default
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
