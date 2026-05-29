package arginject

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 20 {
		t.Errorf("expected at least 20 argument-injection payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	got := GetPayloads()
	if len(got) == 0 {
		t.Fatal("no payloads to assert")
	}
	for _, p := range got {
		if p.Value == "" {
			t.Errorf("payload has empty Value")
		}
		if p.Binary == "" {
			t.Errorf("payload %q has empty Binary", p.Value)
		}
		if p.Description == "" {
			t.Errorf("payload %q has empty Description", p.Value)
		}
		// Every payload value must start with `-` (a flag) — distinct
		// from generic command injection where the payload is its own command.
		if !strings.HasPrefix(p.Value, "-") {
			t.Errorf("payload %q does not start with `-` (argument injection sinks expect flag-shaped values)", p.Value)
		}
	}
}

func TestGetByBinary_CoverHighValueTargets(t *testing.T) {
	binaries := []string{"curl", "ssh", "git", "tar", "find", "convert"}
	for _, b := range binaries {
		t.Run(b, func(t *testing.T) {
			got := GetByBinary(b)
			if len(got) == 0 {
				t.Errorf("no payloads for binary %q", b)
			}
			for _, p := range got {
				if p.Binary != b {
					t.Errorf("GetByBinary(%q) returned payload with Binary=%q", b, p.Binary)
				}
			}
		})
	}
}

func TestGetByBinary_Unknown(t *testing.T) {
	if got := GetByBinary("nonexistent"); len(got) != 0 {
		t.Errorf("expected 0 payloads for unknown binary, got %d", len(got))
	}
}

func TestSupportedBinaries_NonEmpty(t *testing.T) {
	got := SupportedBinaries()
	if len(got) < 6 {
		t.Errorf("expected at least 6 supported binaries, got %d", len(got))
	}
	// Each entry in SupportedBinaries() must actually have payloads.
	for _, b := range got {
		if len(GetByBinary(b)) == 0 {
			t.Errorf("SupportedBinaries lists %q but no payloads exist", b)
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range GetPayloads() {
		key := p.Binary + "|" + p.Value
		if seen[key] {
			t.Errorf("duplicate payload: %s | %s", p.Binary, p.Value)
		}
		seen[key] = true
	}
}
