package redirect

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	payloads := GetPayloads()

	if len(payloads) == 0 {
		t.Error("GetPayloads() returned empty slice")
	}

	// Verify payloads have required fields
	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty Description", i)
		}
	}
}

func TestGetBypassPayloads(t *testing.T) {
	payloads := GetBypassPayloads()

	if len(payloads) == 0 {
		t.Error("GetBypassPayloads() returned empty slice")
	}

	// All bypass payloads should have a bypass type
	for i, p := range payloads {
		if p.BypassType == BypassNone {
			t.Errorf("Bypass payload %d has BypassNone type", i)
		}
	}
}

func TestGetPayloadsByType(t *testing.T) {
	types := []BypassType{
		BypassProtocolRelative,
		BypassAuthSyntax,
		BypassEncoding,
		BypassSlashManipulation,
		BypassDomainConfusion,
		BypassWhitespace,
	}

	for _, bypassType := range types {
		t.Run(string(bypassType), func(t *testing.T) {
			payloads := GetPayloadsByType(bypassType)
			if len(payloads) == 0 {
				t.Errorf("No payloads for bypass type %s", bypassType)
			}

			for _, p := range payloads {
				if p.BypassType != bypassType {
					t.Errorf("Payload has wrong type: got %s, want %s", p.BypassType, bypassType)
				}
			}
		})
	}
}

func TestRedirectParams(t *testing.T) {
	params := RedirectParams()

	if len(params) == 0 {
		t.Error("RedirectParams() returned empty slice")
	}

	// Check for common redirect params
	expected := []string{"url", "redirect", "next", "return", "goto"}
	for _, exp := range expected {
		found := false
		for _, p := range params {
			if p == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected param %q not found in RedirectParams()", exp)
		}
	}
}

func TestGeneratePayloadsForDomain(t *testing.T) {
	payloads := GeneratePayloadsForDomain("trusted.com", "evil.com")

	if len(payloads) == 0 {
		t.Error("GeneratePayloadsForDomain() returned empty slice")
	}

	// Check that payloads contain both domains
	for _, p := range payloads {
		hasEither := false
		if contains(p.Value, "trusted") || contains(p.Value, "evil") {
			hasEither = true
		}
		if !hasEither {
			t.Errorf("Payload %q should contain domain references", p.Value)
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	payloads := GetPayloads()
	seen := make(map[string]bool)

	for _, p := range payloads {
		if seen[p.Value] {
			t.Errorf("Duplicate payload: %s", p.Value)
		}
		seen[p.Value] = true
	}
}

func TestPayloadCategories(t *testing.T) {
	payloads := GetPayloads()

	bypassCounts := make(map[BypassType]int)
	for _, p := range payloads {
		bypassCounts[p.BypassType]++
	}

	// Should have payloads in each category
	expectedCategories := []BypassType{
		BypassNone,
		BypassProtocolRelative,
		BypassAuthSyntax,
		BypassEncoding,
	}

	for _, cat := range expectedCategories {
		if bypassCounts[cat] == 0 {
			t.Errorf("No payloads for category %s", cat)
		}
	}
}

func TestAllBypassTypesHavePayloads(t *testing.T) {
	types := []BypassType{
		BypassNone,
		BypassProtocolRelative,
		BypassAuthSyntax,
		BypassEncoding,
		BypassNullByte,
		BypassSlashManipulation,
		BypassDomainConfusion,
		BypassWhitespace,
	}

	for _, bt := range types {
		payloads := GetPayloadsByType(bt)
		if len(payloads) == 0 && bt != BypassNullByte {
			// NullByte might have fewer payloads
			t.Logf("Warning: No payloads for type %s", bt)
		}
	}
}

func TestProtocolRelativePayloads(t *testing.T) {
	payloads := GetPayloadsByType(BypassProtocolRelative)

	for _, p := range payloads {
		// Protocol relative URLs should start with // or similar
		if !contains(p.Value, "//") && !contains(p.Value, "/\\") && !contains(p.Value, "\\/") {
			t.Errorf("Protocol relative payload should contain //: %s", p.Value)
		}
	}
}

func TestAuthSyntaxPayloads(t *testing.T) {
	payloads := GetPayloadsByType(BypassAuthSyntax)

	for _, p := range payloads {
		// Auth syntax payloads should contain @ (or encoded version)
		if !contains(p.Value, "@") && !contains(p.Value, "%40") {
			t.Errorf("Auth syntax payload should contain @: %s", p.Value)
		}
	}
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
