package secheaders

import (
	"testing"
)

func TestGetHeaderChecks(t *testing.T) {
	checks := GetHeaderChecks()
	if len(checks) == 0 {
		t.Error("GetHeaderChecks returned no checks")
	}

	for i, c := range checks {
		if c.Name == "" {
			t.Errorf("HeaderCheck %d has empty Name", i)
		}
		if c.Severity == "" {
			t.Errorf("HeaderCheck %d (%s) has empty Severity", i, c.Name)
		}
		if c.Description == "" {
			t.Errorf("HeaderCheck %d (%s) has empty Description", i, c.Name)
		}
		if c.Remediation == "" {
			t.Errorf("HeaderCheck %d (%s) has empty Remediation", i, c.Name)
		}
		if len(c.References) == 0 {
			t.Errorf("HeaderCheck %d (%s) has no References", i, c.Name)
		}
		if len(c.CWE) == 0 {
			t.Errorf("HeaderCheck %d (%s) has no CWE entries", i, c.Name)
		}
	}
}

func TestGetRequiredHeaders(t *testing.T) {
	required := GetRequiredHeaders()
	if len(required) == 0 {
		t.Error("GetRequiredHeaders returned no headers")
	}

	for _, h := range required {
		if !h.Required {
			t.Errorf("GetRequiredHeaders returned non-required header: %s", h.Name)
		}
	}
}

func TestGetInsecureHeaders(t *testing.T) {
	insecure := GetInsecureHeaders()
	if len(insecure) == 0 {
		t.Error("GetInsecureHeaders returned no headers")
	}

	for i, h := range insecure {
		if h.Name == "" {
			t.Errorf("InsecureHeader %d has empty Name", i)
		}
		if h.Severity == "" {
			t.Errorf("InsecureHeader %d (%s) has empty Severity", i, h.Name)
		}
		if h.Description == "" {
			t.Errorf("InsecureHeader %d (%s) has empty Description", i, h.Name)
		}
		if h.Remediation == "" {
			t.Errorf("InsecureHeader %d (%s) has empty Remediation", i, h.Name)
		}
		if len(h.References) == 0 {
			t.Errorf("InsecureHeader %d (%s) has no References", i, h.Name)
		}
		if len(h.CWE) == 0 {
			t.Errorf("InsecureHeader %d (%s) has no CWE entries", i, h.Name)
		}
	}
}

func TestGetHeaderCheckByName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"X-Frame-Options", true},
		{"X-Content-Type-Options", true},
		{"Content-Security-Policy", true},
		{"Strict-Transport-Security", true},
		{"Referrer-Policy", true},
		{"Permissions-Policy", true},
		{"Cache-Control", true},
		{"NonexistentHeader", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHeaderCheckByName(tt.name)
			if tt.expected && result == nil {
				t.Errorf("GetHeaderCheckByName(%s) returned nil, expected a result", tt.name)
			}
			if !tt.expected && result != nil {
				t.Errorf("GetHeaderCheckByName(%s) returned a result, expected nil", tt.name)
			}
			if result != nil && result.Name != tt.name {
				t.Errorf("GetHeaderCheckByName(%s) returned header with Name %s", tt.name, result.Name)
			}
		})
	}
}

func TestRequiredHeadersIncludeCSP(t *testing.T) {
	required := GetRequiredHeaders()
	found := false
	for _, h := range required {
		if h.Name == "Content-Security-Policy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Required headers do not include Content-Security-Policy")
	}
}

func TestRequiredHeadersIncludeHSTS(t *testing.T) {
	required := GetRequiredHeaders()
	found := false
	for _, h := range required {
		if h.Name == "Strict-Transport-Security" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Required headers do not include Strict-Transport-Security")
	}
}

func TestHeaderCheckValidSeverities(t *testing.T) {
	checks := GetHeaderChecks()
	validSeverities := map[Severity]bool{
		SeverityHigh:   true,
		SeverityMedium: true,
		SeverityLow:    true,
		SeverityInfo:   true,
	}

	for _, c := range checks {
		if !validSeverities[c.Severity] {
			t.Errorf("Invalid severity %s for header check %s", c.Severity, c.Name)
		}
	}
}

func TestInsecureHeaderValidSeverities(t *testing.T) {
	insecure := GetInsecureHeaders()
	validSeverities := map[Severity]bool{
		SeverityHigh:   true,
		SeverityMedium: true,
		SeverityLow:    true,
		SeverityInfo:   true,
	}

	for _, h := range insecure {
		if !validSeverities[h.Severity] {
			t.Errorf("Invalid severity %s for insecure header %s", h.Severity, h.Name)
		}
	}
}

func TestInsecureHeadersContainServerHeader(t *testing.T) {
	insecure := GetInsecureHeaders()
	found := false
	for _, h := range insecure {
		if h.Name == "Server" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Insecure headers do not include Server header")
	}
}

func TestInsecureHeadersContainXPoweredBy(t *testing.T) {
	insecure := GetInsecureHeaders()
	found := false
	for _, h := range insecure {
		if h.Name == "X-Powered-By" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Insecure headers do not include X-Powered-By header")
	}
}

func TestNoDuplicateHeaderChecks(t *testing.T) {
	checks := GetHeaderChecks()
	seen := make(map[string]bool)
	duplicates := 0

	for _, c := range checks {
		if seen[c.Name] {
			duplicates++
			t.Logf("Duplicate header check: %s", c.Name)
		}
		seen[c.Name] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate header checks", duplicates)
	}
}

func TestNoDuplicateInsecureHeaders(t *testing.T) {
	insecure := GetInsecureHeaders()
	seen := make(map[string]bool)
	duplicates := 0

	for _, h := range insecure {
		if seen[h.Name] {
			duplicates++
			t.Logf("Duplicate insecure header: %s", h.Name)
		}
		seen[h.Name] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate insecure headers", duplicates)
	}
}

func TestXFrameOptionsHasValidValues(t *testing.T) {
	check := GetHeaderCheckByName("X-Frame-Options")
	if check == nil {
		t.Fatal("X-Frame-Options check not found")
	}
	if len(check.ValidValues) == 0 {
		t.Error("X-Frame-Options has no ValidValues")
	}

	validSet := make(map[string]bool)
	for _, v := range check.ValidValues {
		validSet[v] = true
	}

	if !validSet["DENY"] {
		t.Error("X-Frame-Options ValidValues missing DENY")
	}
	if !validSet["SAMEORIGIN"] {
		t.Error("X-Frame-Options ValidValues missing SAMEORIGIN")
	}
}

func TestCSPHasInvalidValues(t *testing.T) {
	check := GetHeaderCheckByName("Content-Security-Policy")
	if check == nil {
		t.Fatal("Content-Security-Policy check not found")
	}
	if len(check.InvalidValues) == 0 {
		t.Error("Content-Security-Policy has no InvalidValues")
	}

	invalidSet := make(map[string]bool)
	for _, v := range check.InvalidValues {
		invalidSet[v] = true
	}

	if !invalidSet["unsafe-inline"] {
		t.Error("CSP InvalidValues missing unsafe-inline")
	}
	if !invalidSet["unsafe-eval"] {
		t.Error("CSP InvalidValues missing unsafe-eval")
	}
}
