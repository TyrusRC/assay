package api

import (
	"testing"
)

func TestGetCategory(t *testing.T) {
	tests := []struct {
		id       string
		expected bool
	}{
		{"API1:2023", true},
		{"API3:2023", true},
		{"API10:2023", true},
		{"API11:2023", false},
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
	cat := GetCategory("API1:2023")
	if cat == nil {
		t.Fatal("Expected non-nil category")
	}

	if cat.ID != "API1:2023" {
		t.Errorf("Expected ID 'API1:2023', got '%s'", cat.ID)
	}
	if cat.Name != "Broken Object Level Authorization" {
		t.Errorf("Expected name 'Broken Object Level Authorization', got '%s'", cat.Name)
	}
	if cat.Description == "" {
		t.Error("Expected non-empty description")
	}
	if cat.Impact == "" {
		t.Error("Expected non-empty impact")
	}
	if len(cat.Prevention) == 0 {
		t.Error("Expected non-empty prevention list")
	}
	if len(cat.CWEs) == 0 {
		t.Error("Expected non-empty CWEs list")
	}
}

func TestGetAllCategories(t *testing.T) {
	cats := GetAllCategories()

	if len(cats) != 10 {
		t.Errorf("Expected 10 categories, got %d", len(cats))
	}

	// Verify all categories are present
	for i := 1; i <= 10; i++ {
		id := "API" + string(rune('0'+i)) + ":2023"
		if i == 10 {
			id = "API10:2023"
		}
		if _, ok := cats[id]; !ok {
			t.Errorf("Missing category %s", id)
		}
	}
}

func TestGetAPITop10ForVulnerability(t *testing.T) {
	tests := []struct {
		vulnType string
		expected string
	}{
		{"BOLA", "API1:2023"},
		{"IDOR", "API1:2023"},
		{"Broken Authentication", "API2:2023"},
		{"Mass Assignment", "API3:2023"},
		{"Rate Limiting Missing", "API4:2023"},
		{"Privilege Escalation", "API5:2023"},
		{"SSRF", "API7:2023"},
		{"CORS Misconfiguration", "API8:2023"},
		{"Shadow API", "API9:2023"},
		{"Unknown Vuln", ""},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType, func(t *testing.T) {
			id := GetAPITop10ForVulnerability(tt.vulnType)
			if id != tt.expected {
				t.Errorf("Expected '%s' for '%s', got '%s'", tt.expected, tt.vulnType, id)
			}
		})
	}
}

func TestVulnerabilityMapping(t *testing.T) {
	// Verify all mapped API Top 10 IDs exist
	for vuln, id := range VulnerabilityMapping {
		cat := GetCategory(id)
		if cat == nil {
			t.Errorf("Vulnerability '%s' maps to non-existent category '%s'", vuln, id)
		}
	}
}

func TestAssessEndpointRisks(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		method       string
		hasAuth      bool
		hasRateLimit bool
		exposesData  bool
		minRisks     int
	}{
		{
			name:         "no auth no rate limit",
			endpoint:     "/api/data",
			method:       "GET",
			hasAuth:      false,
			hasRateLimit: false,
			exposesData:  false,
			minRisks:     2, // API2 and API4
		},
		{
			name:         "fully secured",
			endpoint:     "/api/data",
			method:       "GET",
			hasAuth:      true,
			hasRateLimit: true,
			exposesData:  false,
			minRisks:     0,
		},
		{
			name:         "user resource endpoint",
			endpoint:     "/api/users/123",
			method:       "GET",
			hasAuth:      true,
			hasRateLimit: true,
			exposesData:  false,
			minRisks:     1, // API1 (BOLA)
		},
		{
			name:         "admin endpoint",
			endpoint:     "/admin/settings",
			method:       "GET",
			hasAuth:      true,
			hasRateLimit: true,
			exposesData:  false,
			minRisks:     1, // API5 (BFLA)
		},
		{
			name:         "exposes data",
			endpoint:     "/api/data",
			method:       "GET",
			hasAuth:      true,
			hasRateLimit: true,
			exposesData:  true,
			minRisks:     1, // API3
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risks := AssessEndpointRisks(tt.endpoint, tt.method, tt.hasAuth, tt.hasRateLimit, tt.exposesData)
			if len(risks) < tt.minRisks {
				t.Errorf("Expected at least %d risks, got %d: %v", tt.minRisks, len(risks), risks)
			}
		})
	}
}

func TestContainsResourceID(t *testing.T) {
	tests := []struct {
		endpoint string
		expected bool
	}{
		{"/api/users/123", true},
		{"/api/accounts/abc-def", true},
		{"/api/health", false},
		{"/api/status", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			result := containsResourceID(tt.endpoint)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.endpoint, result)
			}
		})
	}
}

func TestIsAdminEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		expected bool
	}{
		{"/admin/users", true},
		{"/api/manage/config", true},
		{"/internal/status", true},
		{"/debug/pprof", true},
		{"/api/users", false},
		{"/api/public", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			result := isAdminEndpoint(tt.endpoint)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.endpoint, result)
			}
		})
	}
}

func TestCategoryHasSSRF(t *testing.T) {
	cat := GetCategory("API7:2023")
	if cat == nil {
		t.Fatal("Expected non-nil category")
	}

	if cat.Name != "Server Side Request Forgery" {
		t.Errorf("Expected 'Server Side Request Forgery', got '%s'", cat.Name)
	}

	hasSSRFCWE := false
	for _, cwe := range cat.CWEs {
		if cwe == "CWE-918" {
			hasSSRFCWE = true
			break
		}
	}

	if !hasSSRFCWE {
		t.Error("API7:2023 should include CWE-918 (SSRF)")
	}
}

func TestAllCategoriesHavePrevention(t *testing.T) {
	cats := GetAllCategories()

	for id, cat := range cats {
		if len(cat.Prevention) == 0 {
			t.Errorf("Category %s has no prevention guidance", id)
		}
	}
}
