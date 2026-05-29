package nodejsinject

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 15 {
		t.Errorf("expected at least 15 NodeJS SSJI payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	got := GetPayloads()
	if len(got) == 0 {
		t.Fatal("no payloads")
	}
	validImpact := map[Impact]bool{
		ImpactRCE:        true,
		ImpactSandboxEsc: true,
		ImpactInfoLeak:   true,
		ImpactBlind:      true,
	}
	for _, p := range got {
		if p.Value == "" {
			t.Errorf("payload has empty Value")
		}
		if p.Technique == "" {
			t.Errorf("payload %q has empty Technique", p.Value)
		}
		if !validImpact[p.Impact] {
			t.Errorf("payload %q has invalid Impact %q", p.Value, p.Impact)
		}
	}
}

func TestGetPayloads_CoverSinks(t *testing.T) {
	got := GetPayloads()
	joined := ""
	for _, p := range got {
		joined += p.Value + "\n"
	}
	required := []string{
		"require('child_process')",   // primary RCE sink
		"global.process",             // vm sandbox escape
		"Function(",                  // Function constructor RCE
		"setTimeout",                 // eval-via-setTimeout
		"constructor.constructor",    // vm escape via constructor chain
		"this.constructor",           // vm escape via this
		"process.mainModule",         // require() resolution
		"_$$ND_FUNC$$_",              // node-serialize marker (deser-class)
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("NodeJS SSJI bank missing required sink: %q", r)
		}
	}
}

func TestGetByImpact(t *testing.T) {
	for _, imp := range []Impact{ImpactRCE, ImpactSandboxEsc, ImpactBlind} {
		got := GetByImpact(imp)
		if len(got) == 0 {
			t.Errorf("no payloads for impact %q", imp)
		}
		for _, p := range got {
			if p.Impact != imp {
				t.Errorf("GetByImpact(%q) returned %q", imp, p.Impact)
			}
		}
	}
}

func TestGetErrorPatterns_NonEmpty(t *testing.T) {
	got := GetErrorPatterns()
	if len(got) < 4 {
		t.Errorf("expected at least 4 NodeJS error patterns, got %d", len(got))
	}
	// Every pattern must reference a NodeJS-class term.
	for _, p := range got {
		lp := strings.ToLower(p)
		if !strings.Contains(lp, "node") &&
			!strings.Contains(lp, "syntaxerror") &&
			!strings.Contains(lp, "referenceerror") &&
			!strings.Contains(lp, "typeerror") &&
			!strings.Contains(lp, "v8") {
			t.Errorf("error pattern %q is not Node/V8-class", p)
		}
	}
}
