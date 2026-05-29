package cmdi

import (
	"strings"
	"testing"
)

func TestGetShellshockPayloads_MinCount(t *testing.T) {
	got := GetShellshockPayloads()
	if len(got) < 6 {
		t.Errorf("expected at least 6 Shellshock payloads, got %d", len(got))
	}
}

func TestGetShellshockPayloads_HaveFunctionDef(t *testing.T) {
	got := GetShellshockPayloads()
	if len(got) == 0 {
		t.Fatal("no shellshock payloads to assert on")
	}
	// All shellshock payloads must contain the empty-function-body trigger
	// `() { :;};` that drives CVE-2014-6271 parsing.
	for _, p := range got {
		if !strings.Contains(p.Value, "() {") {
			t.Errorf("payload missing () { ... } function-def trigger: %q", p.Value)
		}
		if p.Platform != PlatformLinux {
			t.Errorf("Shellshock targets bash → PlatformLinux, got %q for %q", p.Platform, p.Value)
		}
	}
}

func TestGetShellshockPayloads_CoverVulnVariants(t *testing.T) {
	got := GetShellshockPayloads()
	joined := ""
	for _, p := range got {
		joined += p.Value + "\n"
	}
	required := []string{
		":;};",      // original CVE-2014-6271
		"$(",        // command substitution variant
		"echo",      // value-marker probe (verification leg)
		"/bin/",     // explicit binary path (some hardened images)
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("Shellshock bank missing required variant marker: %q", r)
		}
	}
}

func TestShellshockPayloads_InAggregate(t *testing.T) {
	all := GetAllPayloads()
	hits := 0
	for _, p := range all {
		if strings.Contains(p.Value, "() {") {
			hits++
		}
	}
	if hits == 0 {
		t.Error("GetAllPayloads must include Shellshock payloads")
	}
}
