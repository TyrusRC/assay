package csti

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
		if p.Framework == "" {
			t.Errorf("Payload %d has empty Framework", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty Description", i)
		}
	}
}

func TestGetByFramework(t *testing.T) {
	tests := []struct {
		name      string
		framework Framework
		minCount  int
	}{
		{"Angular", FrameworkAngular, 3},
		{"Vue", FrameworkVue, 2},
		{"Generic", FrameworkGeneric, 5},
		{"Handlebars", FrameworkHandlebars, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetByFramework(tt.framework)
			if len(payloads) < tt.minCount {
				t.Errorf("GetByFramework(%s) returned %d payloads, want at least %d", tt.framework, len(payloads), tt.minCount)
			}
			for _, p := range payloads {
				if p.Framework != tt.framework {
					t.Errorf("GetByFramework(%s) returned payload with Framework %s", tt.framework, p.Framework)
				}
			}
		})
	}
}

func TestGetByFramework_UnknownFramework(t *testing.T) {
	payloads := GetByFramework(Framework("unknown"))
	if len(payloads) != 0 {
		t.Errorf("GetByFramework with unknown framework returned %d payloads, want 0", len(payloads))
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

func TestGetProbePayloads(t *testing.T) {
	payloads := GetProbePayloads()
	if len(payloads) == 0 {
		t.Error("GetProbePayloads returned no payloads")
	}
	for _, p := range payloads {
		if p.Expected == "" {
			t.Errorf("GetProbePayloads returned payload with empty Expected: %s", truncate(p.Value, 40))
		}
		if p.WAFBypass {
			t.Errorf("GetProbePayloads returned WAFBypass payload: %s", truncate(p.Value, 40))
		}
	}
}

func TestPayloadsContainTemplateExpressions(t *testing.T) {
	payloads := GetPayloads()
	templateMarkers := []string{"{{", "${", "#{", "<%"}
	for _, p := range payloads {
		found := false
		for _, marker := range templateMarkers {
			if strings.Contains(p.Value, marker) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Payload %q does not contain any template expression marker", truncate(p.Value, 40))
		}
	}
}

func TestPayloadValidFrameworks(t *testing.T) {
	payloads := GetPayloads()
	validFrameworks := map[Framework]bool{
		FrameworkAngular:    true,
		FrameworkVue:        true,
		FrameworkReact:      true,
		FrameworkEmber:      true,
		FrameworkHandlebars: true,
		FrameworkGeneric:    true,
	}

	for _, p := range payloads {
		if !validFrameworks[p.Framework] {
			t.Errorf("Invalid framework %s for payload %s", p.Framework, truncate(p.Value, 30))
		}
	}
}

func TestAllFrameworksWithPayloadsHaveResults(t *testing.T) {
	frameworks := []Framework{FrameworkAngular, FrameworkVue, FrameworkGeneric, FrameworkHandlebars}
	for _, fw := range frameworks {
		payloads := GetByFramework(fw)
		if len(payloads) == 0 {
			t.Errorf("Framework %s has no payloads", fw)
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		key := p.Value + "|" + string(p.Framework)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (Framework: %s)", truncate(p.Value, 40), p.Framework)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
