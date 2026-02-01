package ssti

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	engines := []TemplateEngine{
		EngineJinja2,
		EngineTwig,
		EngineFreemarker,
		EngineVelocity,
		EngineERB,
		EngineThymeleaf,
		EngineMako,
		EngineSmarty,
		EnginePebble,
		EngineHandlebars,
		EngineMustache,
	}

	for _, engine := range engines {
		t.Run(string(engine), func(t *testing.T) {
			payloads := GetPayloads(engine)
			if len(payloads) == 0 {
				t.Errorf("GetPayloads(%s) returned no payloads", engine)
			}

			// Verify all payloads have the expected engine
			for _, p := range payloads {
				if p.Engine != engine {
					t.Errorf("GetPayloads(%s) returned payload with engine %s", engine, p.Engine)
				}
			}
		})
	}
}

func TestGetPayloads_UnknownEngine(t *testing.T) {
	payloads := GetPayloads(EngineUnknown)
	all := GetAllPayloads()

	if len(payloads) != len(all) {
		t.Errorf("GetPayloads(EngineUnknown) returned %d payloads, want %d", len(payloads), len(all))
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()

	if len(payloads) == 0 {
		t.Error("GetAllPayloads returned no payloads")
	}

	// Verify all payloads have required fields
	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Engine == "" {
			t.Errorf("Payload %d has empty Engine", i)
		}
		if p.Type == "" {
			t.Errorf("Payload %d has empty Type", i)
		}
	}
}

func TestGetDetectionPayloads(t *testing.T) {
	payloads := GetDetectionPayloads()

	if len(payloads) == 0 {
		t.Error("GetDetectionPayloads returned no payloads")
	}

	// Verify all returned payloads are detection or fingerprint type
	for _, p := range payloads {
		if p.Type != TypeDetection && p.Type != TypeFingerprint {
			t.Errorf("GetDetectionPayloads returned payload with type %s", p.Type)
		}
	}
}

func TestGetRCEPayloads(t *testing.T) {
	payloads := GetRCEPayloads()

	if len(payloads) == 0 {
		t.Error("GetRCEPayloads returned no payloads")
	}

	// Verify all returned payloads are RCE type
	for _, p := range payloads {
		if p.Type != TypeRCE {
			t.Errorf("GetRCEPayloads returned payload with type %s", p.Type)
		}
	}
}

func TestGetMathPayloads(t *testing.T) {
	payloads := GetMathPayloads()

	if len(payloads) == 0 {
		t.Error("GetMathPayloads returned no payloads")
	}

	// Verify all returned payloads use math detection
	for _, p := range payloads {
		if p.DetectionMethod != MethodMath {
			t.Errorf("GetMathPayloads returned payload with detection method %s", p.DetectionMethod)
		}
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()

	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads returned no payloads")
	}

	// Verify all returned payloads have WAFBypass flag
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", p.Value[:min(30, len(p.Value))])
		}
	}
}

func TestGetFingerprintPayloads(t *testing.T) {
	payloads := GetFingerprintPayloads()

	if len(payloads) == 0 {
		t.Error("GetFingerprintPayloads returned no payloads")
	}

	// Verify all returned payloads are fingerprint type
	for _, p := range payloads {
		if p.Type != TypeFingerprint {
			t.Errorf("GetFingerprintPayloads returned payload with type %s", p.Type)
		}
	}
}

func TestGetPolyglotPayloads(t *testing.T) {
	payloads := GetPolyglotPayloads()

	if len(payloads) == 0 {
		t.Error("GetPolyglotPayloads returned no payloads")
	}

	// Verify polyglot payloads have Unknown engine
	for _, p := range payloads {
		if p.Engine != EngineUnknown {
			t.Errorf("GetPolyglotPayloads returned payload with engine %s, want %s", p.Engine, EngineUnknown)
		}
	}
}

func TestPayloadTypes(t *testing.T) {
	tests := []struct {
		payloadType PayloadType
		count       int // minimum expected count
	}{
		{TypeDetection, 5},
		{TypeFingerprint, 5},
		{TypeRCE, 10},
		{TypeConfigLeak, 2},
		{TypeFileRead, 3},
	}

	allPayloads := GetAllPayloads()

	for _, tt := range tests {
		t.Run(string(tt.payloadType), func(t *testing.T) {
			count := 0
			for _, p := range allPayloads {
				if p.Type == tt.payloadType {
					count++
				}
			}
			if count < tt.count {
				t.Errorf("Expected at least %d payloads of type %s, got %d", tt.count, tt.payloadType, count)
			}
		})
	}
}

func TestDetectionMethods(t *testing.T) {
	tests := []struct {
		method DetectionMethod
		count  int // minimum expected count
	}{
		{MethodMath, 10},
		{MethodReflection, 5},
		{MethodOutput, 10},
	}

	allPayloads := GetAllPayloads()

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			count := 0
			for _, p := range allPayloads {
				if p.DetectionMethod == tt.method {
					count++
				}
			}
			if count < tt.count {
				t.Errorf("Expected at least %d payloads with method %s, got %d", tt.count, tt.method, count)
			}
		})
	}
}

func TestMathPayloads_HaveExpectedOutput(t *testing.T) {
	payloads := GetMathPayloads()

	for _, p := range payloads {
		if p.ExpectedOutput == "" {
			t.Errorf("Math payload %q should have ExpectedOutput set", p.Value[:min(30, len(p.Value))])
		}
	}
}

func TestTemplateEnginePayloads_Coverage(t *testing.T) {
	// Verify each engine has detection and RCE payloads (where applicable)
	engines := []struct {
		engine       TemplateEngine
		hasDetection bool
		hasRCE       bool
	}{
		{EngineJinja2, true, true},
		{EngineTwig, true, true},
		{EngineFreemarker, true, true},
		{EngineVelocity, true, true},
		{EngineERB, true, true},
		{EngineThymeleaf, true, true},
		{EngineMako, true, true},
		{EngineSmarty, true, true},
		{EnginePebble, true, true},
		{EngineHandlebars, true, true},
		{EngineMustache, true, false}, // Mustache is logic-less
	}

	for _, tt := range engines {
		t.Run(string(tt.engine), func(t *testing.T) {
			payloads := GetPayloads(tt.engine)

			hasDetection := false
			hasRCE := false

			for _, p := range payloads {
				if p.Type == TypeDetection {
					hasDetection = true
				}
				if p.Type == TypeRCE {
					hasRCE = true
				}
			}

			if tt.hasDetection && !hasDetection {
				t.Errorf("Engine %s should have detection payloads", tt.engine)
			}
			if tt.hasRCE && !hasRCE {
				t.Errorf("Engine %s should have RCE payloads", tt.engine)
			}
		})
	}
}

func TestJinja2Fingerprint_SevenTimesSeven(t *testing.T) {
	// Jinja2 specific: {{7*'7'}} should produce "7777777"
	payloads := GetPayloads(EngineJinja2)

	found := false
	for _, p := range payloads {
		if p.Value == "{{7*'7'}}" {
			found = true
			if p.ExpectedOutput != "7777777" {
				t.Errorf("Jinja2 fingerprint payload expected output should be '7777777', got %q", p.ExpectedOutput)
			}
			break
		}
	}

	if !found {
		t.Error("Jinja2 fingerprint payload {{7*'7'}} not found")
	}
}

func TestTwigFingerprint_SevenTimesSeven(t *testing.T) {
	// Twig specific: {{7*'7'}} should produce "49"
	payloads := GetPayloads(EngineTwig)

	found := false
	for _, p := range payloads {
		if p.Value == "{{7*'7'}}" {
			found = true
			if p.ExpectedOutput != "49" {
				t.Errorf("Twig fingerprint payload expected output should be '49', got %q", p.ExpectedOutput)
			}
			break
		}
	}

	if !found {
		t.Error("Twig fingerprint payload {{7*'7'}} not found")
	}
}

func TestTemplateEngineString(t *testing.T) {
	tests := []struct {
		engine   TemplateEngine
		expected string
	}{
		{EngineJinja2, "jinja2"},
		{EngineTwig, "twig"},
		{EngineFreemarker, "freemarker"},
		{EngineVelocity, "velocity"},
		{EngineERB, "erb"},
		{EngineThymeleaf, "thymeleaf"},
		{EngineMako, "mako"},
		{EngineSmarty, "smarty"},
		{EnginePebble, "pebble"},
		{EngineHandlebars, "handlebars"},
		{EngineMustache, "mustache"},
		{EngineUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.engine), func(t *testing.T) {
			if string(tt.engine) != tt.expected {
				t.Errorf("TemplateEngine string = %q, want %q", string(tt.engine), tt.expected)
			}
		})
	}
}

func TestPayloadTypeString(t *testing.T) {
	tests := []struct {
		payloadType PayloadType
		expected    string
	}{
		{TypeDetection, "detection"},
		{TypeFingerprint, "fingerprint"},
		{TypeRCE, "rce"},
		{TypeConfigLeak, "config_leak"},
		{TypeFileRead, "file_read"},
	}

	for _, tt := range tests {
		t.Run(string(tt.payloadType), func(t *testing.T) {
			if string(tt.payloadType) != tt.expected {
				t.Errorf("PayloadType string = %q, want %q", string(tt.payloadType), tt.expected)
			}
		})
	}
}

func TestDetectionMethodString(t *testing.T) {
	tests := []struct {
		method   DetectionMethod
		expected string
	}{
		{MethodMath, "math"},
		{MethodError, "error"},
		{MethodReflection, "reflection"},
		{MethodOutput, "output"},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			if string(tt.method) != tt.expected {
				t.Errorf("DetectionMethod string = %q, want %q", string(tt.method), tt.expected)
			}
		})
	}
}

func TestPayloadFields_NonEmpty(t *testing.T) {
	payloads := GetAllPayloads()

	for i, p := range payloads {
		if p.Value == "" {
			t.Errorf("Payload %d has empty Value", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d (%s) has empty Description", i, p.Value[:min(20, len(p.Value))])
		}
		if p.DetectionMethod == "" {
			t.Errorf("Payload %d (%s) has empty DetectionMethod", i, p.Value[:min(20, len(p.Value))])
		}
	}
}

func TestEachEngineHasBasicMathPayload(t *testing.T) {
	// Every engine should have at least one basic math payload (7*7=49)
	engines := []TemplateEngine{
		EngineJinja2,
		EngineTwig,
		EngineFreemarker,
		EngineVelocity,
		EngineERB,
		EngineThymeleaf,
		EngineMako,
		EngineSmarty,
		EnginePebble,
	}

	for _, engine := range engines {
		t.Run(string(engine), func(t *testing.T) {
			payloads := GetPayloads(engine)

			hasMath := false
			for _, p := range payloads {
				if p.DetectionMethod == MethodMath && p.ExpectedOutput == "49" {
					hasMath = true
					break
				}
			}

			if !hasMath {
				t.Errorf("Engine %s should have a basic math payload with expected output 49", engine)
			}
		})
	}
}

func TestNoDuplicatePayloadsWithinEngine(t *testing.T) {
	engines := []TemplateEngine{
		EngineJinja2,
		EngineTwig,
		EngineFreemarker,
		EngineVelocity,
		EngineERB,
		EngineThymeleaf,
		EngineMako,
		EngineSmarty,
	}

	for _, engine := range engines {
		t.Run(string(engine), func(t *testing.T) {
			payloads := GetPayloads(engine)
			seen := make(map[string]bool)

			for _, p := range payloads {
				if seen[p.Value] {
					t.Errorf("Duplicate payload found for engine %s: %s", engine, p.Value[:min(40, len(p.Value))])
				}
				seen[p.Value] = true
			}
		})
	}
}
