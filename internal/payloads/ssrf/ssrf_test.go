package ssrf

import (
	"strings"
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		target   TargetType
		minCount int
	}{
		{"Internal", TargetInternal, 10},
		{"Cloud", TargetCloud, 10},
		{"LocalFile", TargetLocalFile, 10},
		{"Protocol", TargetProtocol, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.target)
			if len(payloads) < tt.minCount {
				t.Errorf("GetPayloads(%s) returned %d payloads, want at least %d",
					tt.target, len(payloads), tt.minCount)
			}

			for _, p := range payloads {
				if p.Value == "" {
					t.Error("Payload has empty value")
				}
				if p.Description == "" {
					t.Error("Payload has empty description")
				}
			}
		})
	}
}

func TestGetCloudPayloads(t *testing.T) {
	tests := []struct {
		name      string
		cloudType string
		minCount  int
	}{
		{"AWS", "aws", 5},
		{"GCP", "gcp", 4},
		{"Azure", "azure", 1},
		{"DigitalOcean", "digitalocean", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetCloudPayloads(tt.cloudType)
			if len(payloads) < tt.minCount {
				t.Errorf("GetCloudPayloads(%s) returned %d payloads, want at least %d",
					tt.cloudType, len(payloads), tt.minCount)
			}

			for _, p := range payloads {
				if p.CloudType != tt.cloudType {
					t.Errorf("Payload cloud type = %s, want %s", p.CloudType, tt.cloudType)
				}
			}
		})
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads() returned empty slice")
	}

	for _, p := range payloads {
		if !p.WAFBypass {
			t.Error("GetWAFBypassPayloads() returned non-bypass payload")
		}
	}
}

func TestGetAllPayloads(t *testing.T) {
	all := GetAllPayloads()
	if len(all) == 0 {
		t.Error("GetAllPayloads() returned empty slice")
	}

	// Verify we have different target types
	hasInternal := false
	hasCloud := false
	hasFile := false
	for _, p := range all {
		switch p.Target {
		case TargetInternal:
			hasInternal = true
		case TargetCloud:
			hasCloud = true
		case TargetLocalFile:
			hasFile = true
		}
	}

	if !hasInternal {
		t.Error("No internal payloads found")
	}
	if !hasCloud {
		t.Error("No cloud payloads found")
	}
	if !hasFile {
		t.Error("No file payloads found")
	}
}

func TestPayloadCategories(t *testing.T) {
	all := GetAllPayloads()

	for _, p := range all {
		switch p.Target {
		case TargetInternal, TargetCloud, TargetLocalFile, TargetProtocol:
			// Valid
		default:
			t.Errorf("Invalid target type: %s", p.Target)
		}

		switch p.Protocol {
		case ProtocolHTTP, ProtocolHTTPS, ProtocolFile, ProtocolGopher, ProtocolDict, ProtocolFTP:
			// Valid
		default:
			t.Errorf("Invalid protocol: %s", p.Protocol)
		}
	}
}

func TestLocalhostPayloadsExist(t *testing.T) {
	payloads := GetPayloads(TargetInternal)

	hasLocalhost := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "127.0.0.1") || strings.Contains(p.Value, "localhost") {
			hasLocalhost = true
			break
		}
	}

	if !hasLocalhost {
		t.Error("Internal payloads should include localhost")
	}
}

func TestAWSMetadataPayloadsExist(t *testing.T) {
	payloads := GetCloudPayloads("aws")

	hasMetadata := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "169.254.169.254") {
			hasMetadata = true
			break
		}
	}

	if !hasMetadata {
		t.Error("AWS payloads should include 169.254.169.254 metadata endpoint")
	}
}

func TestFileProtocolPayloadsExist(t *testing.T) {
	payloads := GetPayloads(TargetLocalFile)

	hasFileProtocol := false
	for _, p := range payloads {
		if strings.HasPrefix(p.Value, "file://") {
			hasFileProtocol = true
			break
		}
	}

	if !hasFileProtocol {
		t.Error("File payloads should use file:// protocol")
	}
}

func TestGetPayloads_UnknownTarget(t *testing.T) {
	// Unknown target should return internal payloads (default)
	payloads := GetPayloads(TargetType("unknown"))
	internalPayloads := GetPayloads(TargetInternal)

	if len(payloads) != len(internalPayloads) {
		t.Errorf("Unknown target should return internal payloads, got %d, want %d", len(payloads), len(internalPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		// Key is value + target to allow same payload for different targets
		key := p.Value + "|" + string(p.Target)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (Target: %s)", truncate(p.Value, 40), p.Target)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestPayloadFieldsComplete(t *testing.T) {
	all := GetAllPayloads()

	for i, p := range all {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty Description", i)
		}
		if p.Protocol == "" {
			t.Errorf("Payload %d has empty Protocol", i)
		}
	}
}

func TestAllTargetTypesHavePayloads(t *testing.T) {
	targets := []TargetType{TargetInternal, TargetCloud, TargetLocalFile, TargetProtocol}

	for _, target := range targets {
		payloads := GetPayloads(target)
		if len(payloads) == 0 {
			t.Errorf("Target type %s has no payloads", target)
		}
	}
}

func TestAllProtocolsRepresented(t *testing.T) {
	all := GetAllPayloads()
	protocols := make(map[Protocol]bool)

	for _, p := range all {
		protocols[p.Protocol] = true
	}

	expectedProtocols := []Protocol{ProtocolHTTP, ProtocolFile}
	for _, expected := range expectedProtocols {
		if !protocols[expected] {
			t.Errorf("No payloads found for protocol %s", expected)
		}
	}
}

func TestCloudPayloadsHaveCloudType(t *testing.T) {
	payloads := GetPayloads(TargetCloud)

	for _, p := range payloads {
		if p.CloudType == "" {
			t.Errorf("Cloud payload missing CloudType: %s", truncate(p.Value, 40))
		}
	}
}

func TestGetCloudPayloads_UnknownProvider(t *testing.T) {
	payloads := GetCloudPayloads("unknown_provider")
	if len(payloads) != 0 {
		t.Errorf("Unknown cloud provider should return empty list, got %d", len(payloads))
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
