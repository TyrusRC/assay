package crlf

import (
	"strings"
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

func TestGetHeaderInjectionPayloads(t *testing.T) {
	payloads := GetHeaderInjectionPayloads()

	if len(payloads) == 0 {
		t.Error("GetHeaderInjectionPayloads() returned empty slice")
	}

	// All header injection payloads should have header injection type
	for i, p := range payloads {
		if p.InjectionType != InjectionHeader && p.InjectionType != InjectionLogForging {
			t.Errorf("Payload %d has wrong injection type: %s", i, p.InjectionType)
		}
	}
}

func TestGetResponseSplitPayloads(t *testing.T) {
	payloads := GetResponseSplitPayloads()

	if len(payloads) == 0 {
		t.Error("GetResponseSplitPayloads() returned empty slice")
	}

	// All response split payloads should have response split type
	for i, p := range payloads {
		if p.InjectionType != InjectionResponseSplit {
			t.Errorf("Payload %d has wrong injection type: %s", i, p.InjectionType)
		}
	}
}

func TestGetPayloadsByEncoding(t *testing.T) {
	encodings := []EncodingType{
		EncodingURL,
		EncodingDouble,
		EncodingUnicode,
		EncodingMixed,
	}

	for _, encoding := range encodings {
		t.Run(string(encoding), func(t *testing.T) {
			payloads := GetPayloadsByEncoding(encoding)
			if len(payloads) == 0 {
				t.Errorf("No payloads for encoding type %s", encoding)
			}

			for _, p := range payloads {
				if p.EncodingType != encoding {
					t.Errorf("Payload has wrong encoding: got %s, want %s", p.EncodingType, encoding)
				}
			}
		})
	}
}

func TestCRLFSequences(t *testing.T) {
	sequences := CRLFSequences()

	if len(sequences) == 0 {
		t.Error("CRLFSequences() returned empty slice")
	}

	// Should contain common CRLF patterns
	expected := []string{"\r\n", "%0d%0a", "%0D%0A"}
	for _, exp := range expected {
		found := false
		for _, seq := range sequences {
			if seq == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected sequence %q not found", exp)
		}
	}
}

func TestInjectionMarker(t *testing.T) {
	marker := InjectionMarker()

	if marker == "" {
		t.Error("InjectionMarker() returned empty string")
	}

	// Marker should be a valid header name
	if strings.ContainsAny(marker, "\r\n:") {
		t.Error("InjectionMarker() contains invalid characters")
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

func TestPayloadContainsCRLF(t *testing.T) {
	payloads := GetPayloads()

	// Patterns that indicate CRLF injection (including various encodings)
	crlfPatterns := []string{
		"%0d", "%0D", "%0a", "%0A", // Single URL encoded
		"%250d", "%250D", "%250a", "%250A", // Double URL encoded
		"%25250",          // Triple URL encoded prefix
		"%E5%98", "%c0%8", // UTF-8/Overlong encoded
		"\\r", "\\n",
		"\u560d", "\u560a",
		"%%0", // Malformed percent encoding
	}

	for _, p := range payloads {
		hasCRLF := false
		for _, pattern := range crlfPatterns {
			if strings.Contains(p.Value, pattern) {
				hasCRLF = true
				break
			}
		}
		if !hasCRLF {
			t.Errorf("Payload should contain CRLF pattern: %s", p.Value)
		}
	}
}

func TestInjectedHeaderField(t *testing.T) {
	payloads := GetHeaderInjectionPayloads()

	// Most header injection payloads should have InjectedHeader set
	withHeader := 0
	for _, p := range payloads {
		if p.InjectedHeader != "" {
			withHeader++
		}
	}

	if withHeader == 0 {
		t.Error("Expected some header injection payloads to have InjectedHeader set")
	}
}

func TestEncodingTypeDistribution(t *testing.T) {
	payloads := GetPayloads()

	counts := make(map[EncodingType]int)
	for _, p := range payloads {
		counts[p.EncodingType]++
	}

	// Should have variety of encoding types
	if len(counts) < 3 {
		t.Error("Expected payloads with at least 3 different encoding types")
	}

	// URL encoding should have the most payloads
	if counts[EncodingURL] == 0 {
		t.Error("Expected URL-encoded payloads")
	}
}

func TestInjectionTypeDistribution(t *testing.T) {
	payloads := GetPayloads()

	counts := make(map[InjectionType]int)
	for _, p := range payloads {
		counts[p.InjectionType]++
	}

	// Should have both header injection and response split
	if counts[InjectionHeader] == 0 {
		t.Error("Expected header injection payloads")
	}
	if counts[InjectionResponseSplit] == 0 {
		t.Error("Expected response split payloads")
	}
}

func TestSetCookiePayloads(t *testing.T) {
	payloads := GetPayloads()

	setCookieCount := 0
	for _, p := range payloads {
		if p.InjectedHeader == "Set-Cookie" {
			setCookieCount++
		}
	}

	if setCookieCount == 0 {
		t.Error("Expected Set-Cookie injection payloads")
	}
}

func TestLocationPayloads(t *testing.T) {
	payloads := GetPayloads()

	locationCount := 0
	for _, p := range payloads {
		if p.InjectedHeader == "Location" {
			locationCount++
		}
	}

	if locationCount == 0 {
		t.Error("Expected Location header injection payloads")
	}
}

func TestEncodingVariations(t *testing.T) {
	// Test that we have variations for common patterns
	urlEncoded := GetPayloadsByEncoding(EncodingURL)
	doubleEncoded := GetPayloadsByEncoding(EncodingDouble)
	unicodeEncoded := GetPayloadsByEncoding(EncodingUnicode)

	if len(urlEncoded) == 0 {
		t.Error("Should have URL-encoded payloads")
	}
	if len(doubleEncoded) == 0 {
		t.Error("Should have double-encoded payloads")
	}
	if len(unicodeEncoded) == 0 {
		t.Error("Should have Unicode-encoded payloads")
	}
}
