package loginj

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		category Category
	}{
		{"CRLF", CRLF},
		{"FormatString", FormatString},
		{"FakeEntry", FakeEntry},
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

	expectedCategories := []Category{CRLF, FormatString, FakeEntry, Generic}
	for _, expected := range expectedCategories {
		if !categories[expected] {
			t.Errorf("GetAllPayloads missing payloads for %s", expected)
		}
	}
}

func TestGetInjectionHeaders(t *testing.T) {
	headers := GetInjectionHeaders()
	if len(headers) == 0 {
		t.Error("GetInjectionHeaders returned no headers")
	}

	// Check that key logged headers are included
	expectedHeaders := []string{"User-Agent", "Referer", "X-Forwarded-For"}
	for _, expected := range expectedHeaders {
		found := false
		for _, h := range headers {
			if h == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected injection header %q not found", expected)
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
			if len(truncated) > 30 {
				truncated = truncated[:30]
			}
			t.Errorf("Payload %q has empty Description", truncated)
		}
	}
}

func TestCategory_String(t *testing.T) {
	tests := []struct {
		category Category
		want     string
	}{
		{CRLF, "crlf"},
		{FormatString, "format_string"},
		{FakeEntry, "fake_entry"},
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

func TestCRLFPayloads(t *testing.T) {
	payloads := GetPayloads(CRLF)

	// Check for CRLF sequences
	hasCRLF := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "\r\n") || containsSubstring(p.Value, "%0d%0a") || containsSubstring(p.Value, "\\r\\n") {
			hasCRLF = true
			break
		}
	}
	if !hasCRLF {
		t.Error("Expected CRLF sequence payloads")
	}
}

func TestFormatStringPayloads(t *testing.T) {
	payloads := GetPayloads(FormatString)
	if len(payloads) == 0 {
		t.Error("Expected format string payloads")
	}

	// Check for format specifiers
	hasFormat := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "%s") || containsSubstring(p.Value, "%n") || containsSubstring(p.Value, "%x") {
			hasFormat = true
			break
		}
	}
	if !hasFormat {
		t.Error("Expected format string specifier payloads (percent-s, percent-n, percent-x)")
	}
}

func TestFakeEntryPayloads(t *testing.T) {
	payloads := GetPayloads(FakeEntry)
	if len(payloads) == 0 {
		t.Error("Expected fake log entry payloads")
	}

	// Check for fake log-like entries
	hasFakeEntry := false
	for _, p := range payloads {
		if containsSubstring(p.Value, "INFO") || containsSubstring(p.Value, "admin") || containsSubstring(p.Value, "login") {
			hasFakeEntry = true
			break
		}
	}
	if !hasFakeEntry {
		t.Error("Expected fake log entry patterns")
	}
}

func TestDeduplicatePayloads(t *testing.T) {
	payloads := []Payload{
		{Value: "test\r\nfake", Category: CRLF},
		{Value: "%s%s%s%n", Category: FormatString},
		{Value: "test\r\nfake", Category: CRLF},      // duplicate
		{Value: "test\r\nfake", Category: FormatString}, // different category
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
		key := p.Value + "|" + string(p.Category)
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
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", p.Value)
		}
	}
}

func TestAllCategoriesRepresented(t *testing.T) {
	all := GetAllPayloads()
	categories := make(map[Category]bool)

	for _, p := range all {
		categories[p.Category] = true
	}

	expectedCategories := []Category{CRLF, FormatString, FakeEntry}
	for _, expected := range expectedCategories {
		if !categories[expected] {
			t.Errorf("No payloads found for category %s", expected)
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
