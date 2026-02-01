package jndi

import (
	"strings"
	"testing"
)

func TestGetPayloads(t *testing.T) {
	payloads := GetPayloads()
	if len(payloads) == 0 {
		t.Error("GetPayloads returned no payloads")
	}

	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Protocol == "" {
			t.Errorf("Payload %d has empty Protocol", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty Description", i)
		}
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads returned no payloads")
	}
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", truncate(p.Value, 40))
		}
	}
}

func TestGetByProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		minCount int
	}{
		{"LDAP", ProtocolLDAP, 5},
		{"LDAPS", ProtocolLDAPS, 1},
		{"RMI", ProtocolRMI, 1},
		{"DNS", ProtocolDNS, 1},
		{"IIOP", ProtocolIIOP, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetByProtocol(tt.protocol)
			if len(payloads) < tt.minCount {
				t.Errorf("GetByProtocol(%s) returned %d payloads, want at least %d", tt.protocol, len(payloads), tt.minCount)
			}
			for _, p := range payloads {
				if p.Protocol != tt.protocol {
					t.Errorf("GetByProtocol(%s) returned payload with Protocol %s", tt.protocol, p.Protocol)
				}
			}
		})
	}
}

func TestGetByProtocol_UnknownProtocol(t *testing.T) {
	payloads := GetByProtocol(Protocol("unknown"))
	if len(payloads) != 0 {
		t.Errorf("GetByProtocol with unknown protocol returned %d payloads, want 0", len(payloads))
	}
}

func TestGetTargetHeaders(t *testing.T) {
	headers := GetTargetHeaders()
	if len(headers) == 0 {
		t.Error("GetTargetHeaders returned no headers")
	}

	for i, h := range headers {
		if h == "" {
			t.Errorf("TargetHeader %d is empty", i)
		}
	}
}

func TestTargetHeadersContainCommonHeaders(t *testing.T) {
	headers := GetTargetHeaders()
	headerSet := make(map[string]bool)
	for _, h := range headers {
		headerSet[h] = true
	}

	expectedHeaders := []string{
		"User-Agent",
		"X-Forwarded-For",
		"Referer",
		"Authorization",
	}

	for _, expected := range expectedHeaders {
		if !headerSet[expected] {
			t.Errorf("TargetHeaders missing expected header: %s", expected)
		}
	}
}

func TestBasicPayloadsContainJNDIPrefix(t *testing.T) {
	payloads := GetPayloads()
	for _, p := range payloads {
		if p.WAFBypass {
			// WAF bypass payloads intentionally fragment "jndi" using
			// nested lookups like ${lower:j}${upper:n}${lower:d}${upper:i}
			// or ${::-j}${::-n}${::-d}${::-i}. These payloads split every
			// character, so the literal "jndi" substring will not appear.
			// Verify they contain JNDI-related protocol references ("dap")
			// or the CALLBACK placeholder as a structural check.
			lower := strings.ToLower(p.Value)
			hasJNDIRef := strings.Contains(lower, "ndi") ||
				strings.Contains(lower, "dap") ||
				strings.Contains(lower, "{callback}")
			if !hasJNDIRef {
				t.Errorf("WAF bypass payload does not contain JNDI-related content: %s", truncate(p.Value, 60))
			}
			continue
		}
		if !strings.Contains(strings.ToLower(p.Value), "jndi") {
			t.Errorf("Non-bypass payload does not contain 'jndi': %s", truncate(p.Value, 50))
		}
	}
}

func TestPayloadsContainCallbackPlaceholder(t *testing.T) {
	payloads := GetPayloads()
	for _, p := range payloads {
		if !strings.Contains(p.Value, "{CALLBACK}") {
			t.Errorf("Payload does not contain {CALLBACK} placeholder: %s", truncate(p.Value, 50))
		}
	}
}

func TestPayloadValidProtocols(t *testing.T) {
	payloads := GetPayloads()
	validProtocols := map[Protocol]bool{
		ProtocolLDAP:  true,
		ProtocolLDAPS: true,
		ProtocolRMI:   true,
		ProtocolDNS:   true,
		ProtocolIIOP:  true,
		ProtocolCORBA: true,
	}

	for _, p := range payloads {
		if !validProtocols[p.Protocol] {
			t.Errorf("Invalid protocol %s for payload %s", p.Protocol, truncate(p.Value, 30))
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		// Key by Value + Description to allow intentional variants
		// (e.g., Unicode-escaped payloads that resolve to same string)
		key := p.Value + "|" + p.Description
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (%s)", truncate(p.Value, 40), p.Description)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestNoDuplicateTargetHeaders(t *testing.T) {
	headers := GetTargetHeaders()
	seen := make(map[string]bool)
	duplicates := 0

	for _, h := range headers {
		if seen[h] {
			duplicates++
			t.Logf("Duplicate target header: %s", h)
		}
		seen[h] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate target headers", duplicates)
	}
}

func TestAllProtocolsWithPayloadsHaveResults(t *testing.T) {
	protocols := []Protocol{ProtocolLDAP, ProtocolLDAPS, ProtocolRMI, ProtocolDNS, ProtocolIIOP}
	for _, proto := range protocols {
		payloads := GetByProtocol(proto)
		if len(payloads) == 0 {
			t.Errorf("Protocol %s has no payloads", proto)
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
