package wstg

import (
	"testing"
)

func TestGetTestCase(t *testing.T) {
	tests := []struct {
		id       string
		expected bool
	}{
		{"WSTG-INPV-05", true},
		{"WSTG-INPV-01", true},
		{"WSTG-INPV-12", true},
		{"WSTG-INVALID", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			tc := GetTestCase(tt.id)
			if tt.expected && tc == nil {
				t.Errorf("Expected test case for %s", tt.id)
			}
			if !tt.expected && tc != nil {
				t.Errorf("Expected nil for %s", tt.id)
			}
		})
	}
}

func TestGetTestCase_Fields(t *testing.T) {
	tc := GetTestCase("WSTG-INPV-05")
	if tc == nil {
		t.Fatal("Expected non-nil test case")
	}

	if tc.ID != "WSTG-INPV-05" {
		t.Errorf("Expected ID 'WSTG-INPV-05', got '%s'", tc.ID)
	}
	if tc.Name == "" {
		t.Error("Expected non-empty name")
	}
	if tc.Category != CategoryInputVal {
		t.Errorf("Expected category INPV, got %s", tc.Category)
	}
	if tc.Description == "" {
		t.Error("Expected non-empty description")
	}
	if tc.Remediation == "" {
		t.Error("Expected non-empty remediation")
	}
}

func TestGetByCategory(t *testing.T) {
	tests := []struct {
		category Category
		minCount int
	}{
		{CategoryInputVal, 5},
		{CategorySession, 1},
		{CategoryAuthz, 1},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			cases := GetByCategory(tt.category)
			if len(cases) < tt.minCount {
				t.Errorf("Expected at least %d test cases for %s, got %d",
					tt.minCount, tt.category, len(cases))
			}
		})
	}
}

func TestGetAllTestCases(t *testing.T) {
	allCases := GetAllTestCases()

	if len(allCases) == 0 {
		t.Error("Expected non-empty test cases map")
	}

	// Verify all have required fields
	for id, tc := range allCases {
		if tc.ID != id {
			t.Errorf("ID mismatch: map key %s, value %s", id, tc.ID)
		}
		if tc.Name == "" {
			t.Errorf("Test case %s has empty name", id)
		}
		if tc.Category == "" {
			t.Errorf("Test case %s has empty category", id)
		}
	}
}

func TestGetWSTGForVulnerability(t *testing.T) {
	tests := []struct {
		vulnType string
		expected []string
	}{
		{"SQL Injection", []string{"WSTG-INPV-05"}},
		{"XSS", []string{"WSTG-INPV-01", "WSTG-INPV-02"}},
		{"Command Injection", []string{"WSTG-INPV-12"}},
		{"SSRF", []string{"WSTG-INPV-19"}},
		{"LFI", []string{"WSTG-INPV-11"}},
		{"XXE", []string{"WSTG-INPV-07"}},
		{"Unknown Vuln Type", nil},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType, func(t *testing.T) {
			ids := GetWSTGForVulnerability(tt.vulnType)
			if tt.expected == nil && ids != nil {
				t.Errorf("Expected nil for '%s'", tt.vulnType)
			}
			if tt.expected != nil {
				if len(ids) != len(tt.expected) {
					t.Errorf("Expected %d IDs, got %d", len(tt.expected), len(ids))
				}
				for i, id := range ids {
					if id != tt.expected[i] {
						t.Errorf("Expected %s, got %s", tt.expected[i], id)
					}
				}
			}
		})
	}
}

func TestVulnerabilityMapping(t *testing.T) {
	// Verify all mapped WSTG IDs exist
	for vuln, ids := range VulnerabilityMapping {
		for _, id := range ids {
			tc := GetTestCase(id)
			if tc == nil {
				t.Errorf("Vulnerability '%s' maps to non-existent WSTG ID '%s'", vuln, id)
			}
		}
	}
}

func TestCategoryConstants(t *testing.T) {
	categories := []Category{
		CategoryInfoGathering,
		CategoryConfig,
		CategoryIdentity,
		CategoryAuthn,
		CategoryAuthz,
		CategorySession,
		CategoryInputVal,
		CategoryErrorHandling,
		CategoryCrypto,
		CategoryBusLogic,
		CategoryClientSide,
		CategoryAPI,
	}

	for _, cat := range categories {
		if cat == "" {
			t.Error("Category should not be empty")
		}
	}
}

func TestNewCoverageReport(t *testing.T) {
	report := NewCoverageReport()

	if report == nil {
		t.Fatal("Expected non-nil report")
	}
	if report.TotalTests == 0 {
		t.Error("Expected non-zero total tests")
	}
	if report.Findings == nil {
		t.Error("Expected non-nil findings map")
	}
	if report.Categories == nil {
		t.Error("Expected non-nil categories map")
	}
}

func TestCoverageReport_AddFinding(t *testing.T) {
	report := NewCoverageReport()

	report.AddFinding("WSTG-INPV-05")
	if report.Findings["WSTG-INPV-05"] != 1 {
		t.Error("Expected finding count to be 1")
	}
	if report.TestedCount != 1 {
		t.Error("Expected tested count to be 1")
	}

	report.AddFinding("WSTG-INPV-05")
	if report.Findings["WSTG-INPV-05"] != 2 {
		t.Error("Expected finding count to be 2")
	}
	// TestedCount should still be 1 (same test case)
}

func TestCoverageReport_CalculateCoverage(t *testing.T) {
	report := NewCoverageReport()

	report.AddFinding("WSTG-INPV-05")
	report.AddFinding("WSTG-INPV-01")
	report.CalculateCoverage()

	inpvCoverage, ok := report.Categories[CategoryInputVal]
	if !ok {
		t.Fatal("Expected INPV category coverage")
	}
	if inpvCoverage.TestedCount != 2 {
		t.Errorf("Expected 2 tested in INPV, got %d", inpvCoverage.TestedCount)
	}
	if inpvCoverage.Percentage <= 0 {
		t.Error("Expected positive coverage percentage")
	}
}
