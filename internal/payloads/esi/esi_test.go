package esi

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 10 {
		t.Errorf("expected at least 10 ESI payloads, got %d", len(got))
	}
}

func TestGetPayloads_ShapeAndMarkers(t *testing.T) {
	got := GetPayloads()
	if len(got) == 0 {
		t.Fatal("no payloads to assert on")
	}
	for _, p := range got {
		if p.Value == "" {
			t.Errorf("payload has empty Value")
		}
		if p.Description == "" {
			t.Errorf("payload %q has empty Description", p.Value)
		}
		// Every ESI payload must contain an <esi:* tag — that's what
		// distinguishes ESI from HTML/SSI/Mustache injection.
		if !strings.Contains(p.Value, "<esi:") {
			t.Errorf("payload missing <esi:*> tag: %q", p.Value)
		}
	}
}

func TestGetPayloads_CoverPrimitives(t *testing.T) {
	got := GetPayloads()
	joined := ""
	for _, p := range got {
		joined += p.Value + "\n"
	}
	required := []string{
		"<esi:include",   // remote-include primitive (SSRF surface)
		"<esi:vars",      // variable interpolation (HTTP_HOST etc.)
		"<esi:assign",    // variable assignment
		"<esi:eval",      // sub-template evaluation
		"<esi:debug",     // debug dump (engine fingerprint)
		"<esi:try",       // exception-class chain
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("ESI payload bank missing required primitive: %q", r)
		}
	}
}

func TestGetEngineFingerprints(t *testing.T) {
	got := GetEngineFingerprints()
	if len(got) < 3 {
		t.Errorf("expected at least 3 ESI engine fingerprints, got %d", len(got))
	}
	wantEngines := []string{"akamai", "varnish", "fastly"}
	seen := make(map[string]bool, len(got))
	for _, f := range got {
		if f.Engine == "" {
			t.Errorf("fingerprint missing Engine: %+v", f)
		}
		if len(f.Headers) == 0 && f.ProbeValue == "" {
			t.Errorf("fingerprint %s has neither response Headers nor a ProbeValue", f.Engine)
		}
		seen[strings.ToLower(f.Engine)] = true
	}
	for _, e := range wantEngines {
		if !seen[e] {
			t.Errorf("missing engine fingerprint: %s", e)
		}
	}
}

func TestGetWAFBypassPayloads_Flagged(t *testing.T) {
	got := GetWAFBypassPayloads()
	for _, p := range got {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %q", p.Value)
		}
	}
}

func TestGetAllPayloads_Aggregate(t *testing.T) {
	got := GetAllPayloads()
	expected := len(GetPayloads()) + len(GetWAFBypassPayloads())
	if len(got) != expected {
		t.Errorf("GetAllPayloads returned %d, want %d", len(got), expected)
	}
}
