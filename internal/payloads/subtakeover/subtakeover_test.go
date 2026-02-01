package subtakeover

import (
	"strings"
	"testing"
)

func TestGetServices(t *testing.T) {
	services := GetServices()
	if len(services) == 0 {
		t.Error("GetServices returned no services")
	}

	for i, s := range services {
		if s.Name == "" {
			t.Errorf("Service %d has empty Name", i)
		}
		if len(s.CNames) == 0 {
			t.Errorf("Service %d (%s) has no CNames", i, s.Name)
		}
		if s.Severity == "" {
			t.Errorf("Service %d (%s) has empty Severity", i, s.Name)
		}
		if !s.NXDomain && !s.HTTPCheck {
			// Services should have at least one detection method
			t.Errorf("Service %d (%s) has neither NXDomain nor HTTPCheck enabled", i, s.Name)
		}
	}
}

func TestGetServiceByCNAME(t *testing.T) {
	tests := []struct {
		name         string
		cname        string
		expectedName string
		shouldFind   bool
	}{
		{"GitHub Pages", "example.github.io", "GitHub Pages", true},
		{"Heroku", "myapp.herokuapp.com", "Heroku", true},
		{"AWS S3", "mybucket.s3.amazonaws.com", "AWS S3", true},
		{"Azure", "mysite.azurewebsites.net", "Azure", true},
		{"Shopify", "myshop.myshopify.com", "Shopify", true},
		{"Netlify", "mysite.netlify.app", "Netlify", true},
		{"Unknown", "example.unknown.com", "", false},
		{"Empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetServiceByCNAME(tt.cname)
			if tt.shouldFind {
				if result == nil {
					t.Errorf("GetServiceByCNAME(%s) returned nil, expected %s", tt.cname, tt.expectedName)
				} else if result.Name != tt.expectedName {
					t.Errorf("GetServiceByCNAME(%s) returned %s, expected %s", tt.cname, result.Name, tt.expectedName)
				}
			} else {
				if result != nil {
					t.Errorf("GetServiceByCNAME(%s) returned %s, expected nil", tt.cname, result.Name)
				}
			}
		})
	}
}

func TestServicesHaveValidSeverity(t *testing.T) {
	services := GetServices()
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	for _, s := range services {
		if !validSeverities[s.Severity] {
			t.Errorf("Invalid severity %q for service %s", s.Severity, s.Name)
		}
	}
}

func TestCNAMEPatternsStartWithDot(t *testing.T) {
	services := GetServices()
	for _, s := range services {
		for _, cname := range s.CNames {
			if !strings.HasPrefix(cname, ".") {
				t.Errorf("CNAME pattern %q for service %s does not start with '.'", cname, s.Name)
			}
		}
	}
}

func TestHTTPCheckServicesHaveFingerprints(t *testing.T) {
	services := GetServices()
	for _, s := range services {
		if s.HTTPCheck && len(s.Fingerprint) == 0 && !s.NXDomain {
			t.Errorf("Service %s has HTTPCheck=true but no fingerprints and NXDomain=false", s.Name)
		}
	}
}

func TestKnownServicesExist(t *testing.T) {
	services := GetServices()
	serviceNames := make(map[string]bool)
	for _, s := range services {
		serviceNames[s.Name] = true
	}

	expectedServices := []string{
		"GitHub Pages",
		"Heroku",
		"AWS S3",
		"Azure",
		"Shopify",
		"Netlify",
	}

	for _, expected := range expectedServices {
		if !serviceNames[expected] {
			t.Errorf("Expected service %s not found", expected)
		}
	}
}

func TestNoDuplicateServices(t *testing.T) {
	services := GetServices()
	seen := make(map[string]bool)
	duplicates := 0

	for _, s := range services {
		if seen[s.Name] {
			duplicates++
			t.Logf("Duplicate service: %s", s.Name)
		}
		seen[s.Name] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate services", duplicates)
	}
}

func TestNoDuplicateCNAMEPatterns(t *testing.T) {
	services := GetServices()
	seen := make(map[string]string)
	duplicates := 0

	for _, s := range services {
		for _, cname := range s.CNames {
			if prevService, exists := seen[cname]; exists {
				duplicates++
				t.Logf("Duplicate CNAME pattern %s found in %s and %s", cname, prevService, s.Name)
			}
			seen[cname] = s.Name
		}
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate CNAME patterns", duplicates)
	}
}

func TestGetServiceByCNAME_PartialMatch(t *testing.T) {
	// A short CNAME that is a suffix match pattern should not match
	result := GetServiceByCNAME(".github.io")
	if result != nil {
		t.Errorf("GetServiceByCNAME with exact pattern (no prefix) should return nil, got %s", result.Name)
	}
}

func TestFingerprintsAreNonEmpty(t *testing.T) {
	services := GetServices()
	for _, s := range services {
		for i, fp := range s.Fingerprint {
			if fp == "" {
				t.Errorf("Service %s has empty fingerprint at index %d", s.Name, i)
			}
		}
	}
}
