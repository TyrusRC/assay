package rfi

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
		{"HTTP", ProtocolHTTP, 5},
		{"HTTPS", ProtocolHTTPS, 1},
		{"Data", ProtocolData, 3},
		{"FTP", ProtocolFTP, 1},
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

func TestGetOOBPayloads(t *testing.T) {
	payloads := GetOOBPayloads()
	if len(payloads) == 0 {
		t.Error("GetOOBPayloads returned no payloads")
	}

	for i, p := range payloads {
		if p.Template == "" {
			t.Errorf("OOBPayload %d has empty Template", i)
		}
		if p.Protocol == "" {
			t.Errorf("OOBPayload %d has empty Protocol", i)
		}
		if p.Description == "" {
			t.Errorf("OOBPayload %d has empty Description", i)
		}
	}
}

func TestOOBPayloadsContainCallbackPlaceholder(t *testing.T) {
	payloads := GetOOBPayloads()
	for _, p := range payloads {
		if !strings.Contains(p.Template, "{CALLBACK}") {
			t.Errorf("OOBPayload does not contain {CALLBACK} placeholder: %s", p.Template)
		}
	}
}

func TestHTTPPayloadsContainURL(t *testing.T) {
	payloads := GetByProtocol(ProtocolHTTP)
	for _, p := range payloads {
		lower := strings.ToLower(p.Value)
		hasHTTP := strings.Contains(lower, "http") || strings.Contains(lower, "//")
		if !hasHTTP {
			t.Errorf("HTTP payload does not contain URL: %s", truncate(p.Value, 50))
		}
	}
}

func TestDataPayloadsContainDataScheme(t *testing.T) {
	payloads := GetByProtocol(ProtocolData)
	for _, p := range payloads {
		lower := strings.ToLower(p.Value)
		if !strings.Contains(lower, "data:") && !strings.Contains(lower, "expect:") && !strings.Contains(lower, "php:") {
			t.Errorf("Data protocol payload does not contain data/expect/php scheme: %s", truncate(p.Value, 50))
		}
	}
}

func TestPayloadValidProtocols(t *testing.T) {
	payloads := GetPayloads()
	validProtocols := map[Protocol]bool{
		ProtocolHTTP:  true,
		ProtocolHTTPS: true,
		ProtocolFTP:   true,
		ProtocolData:  true,
	}

	for _, p := range payloads {
		if !validProtocols[p.Protocol] {
			t.Errorf("Invalid protocol %s for payload %s", p.Protocol, truncate(p.Value, 30))
		}
	}
}

func TestAllProtocolsHavePayloads(t *testing.T) {
	protocols := []Protocol{ProtocolHTTP, ProtocolHTTPS, ProtocolData, ProtocolFTP}
	for _, proto := range protocols {
		payloads := GetByProtocol(proto)
		if len(payloads) == 0 {
			t.Errorf("Protocol %s has no payloads", proto)
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		if seen[p.Value] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s", truncate(p.Value, 40))
			}
		}
		seen[p.Value] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestNoDuplicateOOBPayloads(t *testing.T) {
	all := GetOOBPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		if seen[p.Template] {
			duplicates++
			t.Logf("Duplicate OOB payload found: %s", p.Template)
		}
		seen[p.Template] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate OOB payloads", duplicates)
	}
}

func TestOOBPayloadValidProtocols(t *testing.T) {
	payloads := GetOOBPayloads()
	validProtocols := map[Protocol]bool{
		ProtocolHTTP:  true,
		ProtocolHTTPS: true,
		ProtocolFTP:   true,
		ProtocolData:  true,
	}

	for _, p := range payloads {
		if !validProtocols[p.Protocol] {
			t.Errorf("Invalid protocol %s for OOB payload %s", p.Protocol, p.Template)
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
