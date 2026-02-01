package xxe

import (
	"strings"
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		xxeType  XXEType
		minCount int
	}{
		{"Classic", TypeClassic, 5},
		{"Blind", TypeBlind, 3},
		{"ErrorBased", TypeErrorBased, 2},
		{"DoS", TypeDoS, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.xxeType)
			if len(payloads) < tt.minCount {
				t.Errorf("GetPayloads(%s) returned %d payloads, want at least %d",
					tt.xxeType, len(payloads), tt.minCount)
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

func TestGetByParser(t *testing.T) {
	tests := []struct {
		name     string
		parser   Parser
		minCount int
	}{
		{"Generic", ParserGeneric, 10},
		{"PHP", ParserPHP, 2},
		{"Java", ParserJava, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetByParser(tt.parser)
			if len(payloads) < tt.minCount {
				t.Errorf("GetByParser(%s) returned %d payloads, want at least %d",
					tt.parser, len(payloads), tt.minCount)
			}

			for _, p := range payloads {
				if p.Parser != tt.parser && p.Parser != ParserGeneric {
					t.Errorf("Payload parser = %s, want %s or generic", p.Parser, tt.parser)
				}
			}
		})
	}
}

func TestGetAllPayloads(t *testing.T) {
	all := GetAllPayloads()
	if len(all) == 0 {
		t.Error("GetAllPayloads() returned empty slice")
	}

	// Verify we have different types
	hasClassic := false
	hasBlind := false
	hasDoS := false
	for _, p := range all {
		switch p.Type {
		case TypeClassic:
			hasClassic = true
		case TypeBlind:
			hasBlind = true
		case TypeDoS:
			hasDoS = true
		}
	}

	if !hasClassic {
		t.Error("No classic payloads found")
	}
	if !hasBlind {
		t.Error("No blind payloads found")
	}
	if !hasDoS {
		t.Error("No DoS payloads found")
	}
}

func TestPayloadCategories(t *testing.T) {
	all := GetAllPayloads()

	for _, p := range all {
		switch p.Type {
		case TypeClassic, TypeBlind, TypeErrorBased, TypeDoS:
			// Valid
		default:
			t.Errorf("Invalid XXE type: %s", p.Type)
		}

		switch p.Target {
		case TargetFileRead, TargetSSRF, TargetDoS, TargetRCE:
			// Valid
		default:
			t.Errorf("Invalid target type: %s", p.Target)
		}

		switch p.Parser {
		case ParserGeneric, ParserPHP, ParserJava, ParserDotNet, ParserPython:
			// Valid
		default:
			t.Errorf("Invalid parser: %s", p.Parser)
		}
	}
}

func TestPayloadsContainDOCTYPE(t *testing.T) {
	all := GetAllPayloads()

	for _, p := range all {
		if !strings.Contains(p.Value, "DOCTYPE") && !strings.Contains(p.Value, "doctype") {
			t.Errorf("XXE payload should contain DOCTYPE: %s", p.Description)
		}
	}
}

func TestPayloadsContainEntity(t *testing.T) {
	all := GetAllPayloads()

	for _, p := range all {
		if !strings.Contains(p.Value, "ENTITY") && !strings.Contains(p.Value, "entity") {
			t.Errorf("XXE payload should contain ENTITY: %s", p.Description)
		}
	}
}

func TestClassicPayloadsHaveFileRead(t *testing.T) {
	payloads := GetPayloads(TypeClassic)

	hasFileRead := false
	for _, p := range payloads {
		if p.Target == TargetFileRead {
			hasFileRead = true
			break
		}
	}

	if !hasFileRead {
		t.Error("Classic payloads should include file read targets")
	}
}

func TestDoSPayloadsHaveBillionLaughs(t *testing.T) {
	payloads := GetPayloads(TypeDoS)

	hasBillionLaughs := false
	for _, p := range payloads {
		if strings.Contains(p.Description, "Billion") || strings.Contains(p.Description, "expansion") {
			hasBillionLaughs = true
			break
		}
	}

	if !hasBillionLaughs {
		t.Error("DoS payloads should include billion laughs attack")
	}
}

func TestGetDTDForBlindXXE(t *testing.T) {
	dtd := GetDTDForBlindXXE("attacker.com", "/etc/passwd")

	if !strings.Contains(dtd, "attacker.com") {
		t.Error("DTD should contain attacker server")
	}
	if !strings.Contains(dtd, "/etc/passwd") {
		t.Error("DTD should contain target file")
	}
	if !strings.Contains(dtd, "ENTITY") {
		t.Error("DTD should define entities")
	}
}

func TestGetDTDForFTPExfil(t *testing.T) {
	dtd := GetDTDForFTPExfil("attacker.com", "/etc/passwd")

	if !strings.Contains(dtd, "ftp://") {
		t.Error("FTP DTD should use ftp:// protocol")
	}
	if !strings.Contains(dtd, "attacker.com") {
		t.Error("FTP DTD should contain attacker server")
	}
}

func TestGetPayloads_UnknownType(t *testing.T) {
	// Unknown type should return classic payloads (default)
	payloads := GetPayloads(XXEType("unknown"))
	classicPayloads := GetPayloads(TypeClassic)

	if len(payloads) != len(classicPayloads) {
		t.Errorf("Unknown type should return classic payloads, got %d, want %d", len(payloads), len(classicPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		// Key is value + type to allow same payload for different types
		key := p.Value + "|" + string(p.Type)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (Type: %s)", truncate(p.Value, 40), p.Type)
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
		if p.Type == "" {
			t.Errorf("Payload %d has empty Type", i)
		}
		if p.Parser == "" {
			t.Errorf("Payload %d has empty Parser", i)
		}
	}
}

func TestAllXXETypesHavePayloads(t *testing.T) {
	types := []XXEType{TypeClassic, TypeBlind, TypeErrorBased, TypeDoS}

	for _, xxeType := range types {
		payloads := GetPayloads(xxeType)
		if len(payloads) == 0 {
			t.Errorf("XXE type %s has no payloads", xxeType)
		}
	}
}

func TestAllTargetTypesRepresented(t *testing.T) {
	all := GetAllPayloads()
	targets := make(map[TargetType]bool)

	for _, p := range all {
		targets[p.Target] = true
	}

	expectedTargets := []TargetType{TargetFileRead, TargetSSRF, TargetDoS}
	for _, expected := range expectedTargets {
		if !targets[expected] {
			t.Errorf("No payloads found for target type %s", expected)
		}
	}
}

func TestBlindPayloadsHaveCallbackURLs(t *testing.T) {
	payloads := GetPayloads(TypeBlind)

	hasCallback := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "ATTACKER") || strings.Contains(p.Value, "http://") {
			hasCallback = true
			break
		}
	}

	if !hasCallback {
		t.Error("Blind XXE payloads should include callback URLs")
	}
}

func TestGetByParser_DotNet(t *testing.T) {
	// DotNet parser should return generic payloads (since no specific DotNet payloads exist)
	payloads := GetByParser(ParserDotNet)

	// Should at least return generic payloads
	if len(payloads) == 0 {
		t.Error("GetByParser(ParserDotNet) should return at least generic payloads")
	}
}

func TestGetByParser_Python(t *testing.T) {
	// Python parser should return generic payloads (since no specific Python payloads exist)
	payloads := GetByParser(ParserPython)

	// Should at least return generic payloads
	if len(payloads) == 0 {
		t.Error("GetByParser(ParserPython) should return at least generic payloads")
	}
}

func TestGetDTDForBlindXXE_EmptyParams(t *testing.T) {
	dtd := GetDTDForBlindXXE("", "")

	// Should still generate a valid DTD structure
	if !strings.Contains(dtd, "ENTITY") {
		t.Error("DTD should contain ENTITY even with empty params")
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
