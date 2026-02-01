package xss

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	contexts := []Context{HTMLContext, AttributeContext, JavaScriptContext, URLContext, CSSContext, TemplateContext}

	for _, ctx := range contexts {
		t.Run(string(ctx), func(t *testing.T) {
			payloads := GetPayloads(ctx)
			if len(payloads) == 0 {
				t.Errorf("GetPayloads(%s) returned no payloads", ctx)
			}
		})
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	if len(payloads) == 0 {
		t.Error("GetWAFBypassPayloads returned no payloads")
	}
	for _, p := range payloads {
		if !p.WAFBypass {
			t.Errorf("GetWAFBypassPayloads returned payload without WAFBypass flag: %s", p.Value[:min(30, len(p.Value))])
		}
	}
}

func TestGetPolyglotPayloads(t *testing.T) {
	payloads := GetPolyglotPayloads()
	if len(payloads) == 0 {
		t.Error("GetPolyglotPayloads returned no payloads")
	}
	for _, p := range payloads {
		if !p.Polyglot {
			t.Errorf("GetPolyglotPayloads returned non-polyglot payload")
		}
	}
}

func TestGetDOMPayloads(t *testing.T) {
	payloads := GetDOMPayloads()
	if len(payloads) == 0 {
		t.Error("GetDOMPayloads returned no payloads")
	}
	for _, p := range payloads {
		if p.Type != TypeDOM {
			t.Errorf("GetDOMPayloads returned payload with type %s", p.Type)
		}
	}
}

func TestPayloadFields(t *testing.T) {
	payloads := GetAllPayloads()
	if len(payloads) == 0 {
		t.Error("GetAllPayloads returned no payloads")
	}
	for _, p := range payloads {
		if p.Value == "" {
			t.Error("Payload has empty Value")
		}
	}
}

func TestGetPayloads_UnknownContext(t *testing.T) {
	// Unknown context should return HTML payloads (default)
	payloads := GetPayloads(Context("unknown"))
	htmlPayloads := GetPayloads(HTMLContext)

	if len(payloads) != len(htmlPayloads) {
		t.Errorf("Unknown context should return HTML payloads, got %d, want %d", len(payloads), len(htmlPayloads))
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetAllPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		// Key is value + context to allow same payload for different contexts
		key := p.Value + "|" + string(p.Context)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate payload found: %s (Context: %s)", truncateStr(p.Value, 40), p.Context)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate payloads", duplicates)
	}
}

func TestPayloadValidContexts(t *testing.T) {
	all := GetAllPayloads()
	validContexts := map[Context]bool{
		HTMLContext:       true,
		AttributeContext:  true,
		JavaScriptContext: true,
		URLContext:        true,
		CSSContext:        true,
		TemplateContext:   true,
		"":                true, // Polyglot payloads may have empty context
	}

	for _, p := range all {
		if !validContexts[p.Context] {
			t.Errorf("Invalid context %s for payload %s", p.Context, truncateStr(p.Value, 30))
		}
	}
}

func TestPayloadValidTypes(t *testing.T) {
	all := GetAllPayloads()
	validTypes := map[PayloadType]bool{
		TypeReflected: true,
		TypeStored:    true,
		TypeDOM:       true,
		"":            true, // Some payloads may have empty type
	}

	for _, p := range all {
		if !validTypes[p.Type] {
			t.Errorf("Invalid type %s for payload %s", p.Type, truncateStr(p.Value, 30))
		}
	}
}

func TestAllCategoriesHavePayloads(t *testing.T) {
	contexts := []Context{HTMLContext, AttributeContext, JavaScriptContext, URLContext, CSSContext, TemplateContext}

	for _, ctx := range contexts {
		payloads := GetPayloads(ctx)
		if len(payloads) == 0 {
			t.Errorf("Context %s has no payloads", ctx)
		}
	}
}

func TestPolyglotPayloadsHaveCorrectFlag(t *testing.T) {
	payloads := GetPolyglotPayloads()
	for _, p := range payloads {
		if !p.Polyglot {
			t.Errorf("GetPolyglotPayloads returned non-polyglot: %s", truncateStr(p.Value, 40))
		}
	}
}

func TestDOMPayloadsHaveCorrectType(t *testing.T) {
	payloads := GetDOMPayloads()
	for _, p := range payloads {
		if p.Type != TypeDOM {
			t.Errorf("GetDOMPayloads returned non-DOM type: %s", truncateStr(p.Value, 40))
		}
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
