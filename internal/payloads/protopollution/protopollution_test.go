package protopollution

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	payloads := GetPayloads()
	if len(payloads) == 0 {
		t.Error("GetPayloads() returned no payloads")
	}

	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Description == "" {
			truncated := p.Value
			if len(truncated) > 30 {
				truncated = truncated[:30]
			}
			t.Errorf("Payload %q has empty Description", truncated)
		}
		if p.Technique == "" {
			t.Errorf("Payload %d (%q) has empty Technique", i, p.Value)
		}
	}
}

func TestGetPayloadsByTechnique(t *testing.T) {
	techniques := []Technique{TechQueryParam, TechJSONBody, TechDotNotation}

	for _, tech := range techniques {
		t.Run(string(tech), func(t *testing.T) {
			payloads := GetPayloadsByTechnique(tech)
			if len(payloads) == 0 {
				t.Errorf("GetPayloadsByTechnique(%s) returned no payloads", tech)
			}
			for _, p := range payloads {
				if p.Technique != tech {
					t.Errorf("GetPayloadsByTechnique(%s) returned payload with technique %s", tech, p.Technique)
				}
			}
		})
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", p.Value)
		}
	}
}

func TestRequiredPayloadsPresent(t *testing.T) {
	payloads := GetPayloads()

	required := []string{
		"__proto__[skws]=1",
		"constructor.prototype.skws=1",
		"__proto__.skws=1",
	}

	for _, req := range required {
		found := false
		for _, p := range payloads {
			if p.Value == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Required payload %q not found", req)
		}
	}
}

func TestTechniqueConstants(t *testing.T) {
	tests := []struct {
		tech Technique
		want string
	}{
		{TechQueryParam, "query_param"},
		{TechJSONBody, "json_body"},
		{TechDotNotation, "dot_notation"},
	}

	for _, tt := range tests {
		t.Run(string(tt.tech), func(t *testing.T) {
			if string(tt.tech) != tt.want {
				t.Errorf("Technique = %q, want %q", string(tt.tech), tt.want)
			}
		})
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetPayloads()
	seen := make(map[string]bool)

	for _, p := range all {
		if seen[p.Value] {
			t.Errorf("Duplicate payload found: %s", p.Value)
		}
		seen[p.Value] = true
	}
}

func TestGetPayloadsByTechnique_EmptyResult(t *testing.T) {
	payloads := GetPayloadsByTechnique(Technique("nonexistent"))
	if len(payloads) != 0 {
		t.Errorf("Expected no payloads for nonexistent technique, got %d", len(payloads))
	}
}

func TestAllPayloadsHaveValidTechnique(t *testing.T) {
	validTechniques := map[Technique]bool{
		TechQueryParam:  true,
		TechJSONBody:    true,
		TechDotNotation: true,
	}

	for _, p := range GetPayloads() {
		if !validTechniques[p.Technique] {
			t.Errorf("Payload %q has invalid technique %q", p.Value, p.Technique)
		}
	}
}
