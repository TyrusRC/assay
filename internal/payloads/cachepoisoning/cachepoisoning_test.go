package cachepoisoning

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		category Category
	}{
		{"HeaderBased", HeaderBased},
		{"PathBased", PathBased},
		{"ParameterBased", ParameterBased},
		{"Generic", Generic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.category)
			if len(payloads) == 0 {
				t.Errorf("GetPayloads(%s) returned no payloads", tt.category)
			}
		})
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()
	if len(payloads) == 0 {
		t.Error("GetAllPayloads returned no payloads")
	}

	// Verify we have payloads from multiple categories
	categories := make(map[Category]bool)
	for _, p := range payloads {
		categories[p.Category] = true
	}

	expectedCategories := []Category{HeaderBased, PathBased, ParameterBased, Generic}
	for _, expected := range expectedCategories {
		if !categories[expected] {
			t.Errorf("GetAllPayloads missing payloads for %s", expected)
		}
	}
}

func TestGetUnkeyedHeaders(t *testing.T) {
	headers := GetUnkeyedHeaders()
	if len(headers) == 0 {
		t.Error("GetUnkeyedHeaders returned no headers")
	}

	// Check that key unkeyed headers are included
	expectedHeaders := []string{"X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Forwarded-Port"}
	for _, expected := range expectedHeaders {
		found := false
		for _, h := range headers {
			if h.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected unkeyed header %q not found", expected)
		}
	}
}

func TestPayloadFields(t *testing.T) {
	payloads := GetAllPayloads()
	for i, p := range payloads {
		if p.HeaderName == "" && p.Value == "" {
			t.Errorf("Payload %d has both empty HeaderName and Value", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty Description", i)
		}
	}
}

func TestUnkeyedHeaderFields(t *testing.T) {
	headers := GetUnkeyedHeaders()
	for i, h := range headers {
		if h.Name == "" {
			t.Errorf("UnkeyedHeader %d has empty Name", i)
		}
		if h.TestValue == "" {
			t.Errorf("UnkeyedHeader %d (%s) has empty TestValue", i, h.Name)
		}
	}
}

func TestCategory_String(t *testing.T) {
	tests := []struct {
		category Category
		want     string
	}{
		{HeaderBased, "header"},
		{PathBased, "path"},
		{ParameterBased, "parameter"},
		{Generic, "generic"},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			if string(tt.category) != tt.want {
				t.Errorf("Category = %q, want %q", string(tt.category), tt.want)
			}
		})
	}
}

func TestHeaderBasedPayloads(t *testing.T) {
	payloads := GetPayloads(HeaderBased)

	// Check for header injection payloads
	hasForwardedHost := false
	hasForwardedScheme := false
	for _, p := range payloads {
		if p.HeaderName == "X-Forwarded-Host" {
			hasForwardedHost = true
		}
		if p.HeaderName == "X-Forwarded-Scheme" {
			hasForwardedScheme = true
		}
	}

	if !hasForwardedHost {
		t.Error("Expected X-Forwarded-Host header payload")
	}
	if !hasForwardedScheme {
		t.Error("Expected X-Forwarded-Scheme header payload")
	}
}

func TestPathBasedPayloads(t *testing.T) {
	payloads := GetPayloads(PathBased)
	if len(payloads) == 0 {
		t.Error("Expected path-based payloads")
	}
}

func TestDeduplicatePayloads(t *testing.T) {
	payloads := []Payload{
		{HeaderName: "X-Forwarded-Host", Value: "evil.com", Category: HeaderBased},
		{HeaderName: "X-Forwarded-Port", Value: "443", Category: HeaderBased},
		{HeaderName: "X-Forwarded-Host", Value: "evil.com", Category: HeaderBased}, // duplicate
		{HeaderName: "X-Forwarded-Host", Value: "evil.com", Category: PathBased},   // different category
	}

	deduped := DeduplicatePayloads(payloads)

	if len(deduped) != 3 {
		t.Errorf("DeduplicatePayloads() returned %d payloads, want 3", len(deduped))
	}
}

func TestGetPayloads_UnknownCategory(t *testing.T) {
	payloads := GetPayloads(Category("unknown"))
	genericPayloads := GetPayloads(Generic)

	if len(payloads) != len(genericPayloads) {
		t.Errorf("Unknown category should return generic payloads, got %d, want %d", len(payloads), len(genericPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		key := p.HeaderName + "|" + p.Value + "|" + string(p.Category)
		if seen[key] {
			duplicates++
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s %s", p.HeaderName, p.Value)
		}
	}
}
