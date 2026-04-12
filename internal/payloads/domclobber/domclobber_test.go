package domclobber

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
		if p.Element == "" {
			t.Errorf("Payload %d (%q) has empty Element", i, p.Value)
		}
	}
}

func TestGetPayloadsByElement(t *testing.T) {
	elements := []Element{ElemForm, ElemImg, ElemAnchor, ElemObject, ElemEmbed}

	for _, elem := range elements {
		t.Run(string(elem), func(t *testing.T) {
			payloads := GetPayloadsByElement(elem)
			if len(payloads) == 0 {
				t.Errorf("GetPayloadsByElement(%s) returned no payloads", elem)
			}
			for _, p := range payloads {
				if p.Element != elem {
					t.Errorf("GetPayloadsByElement(%s) returned payload with element %s", elem, p.Element)
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
		`<form id=x>`,
		`<img name=x>`,
		`<a id=x name=x>`,
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

func TestElementConstants(t *testing.T) {
	tests := []struct {
		elem Element
		want string
	}{
		{ElemForm, "form"},
		{ElemImg, "img"},
		{ElemAnchor, "anchor"},
		{ElemObject, "object"},
		{ElemEmbed, "embed"},
	}

	for _, tt := range tests {
		t.Run(string(tt.elem), func(t *testing.T) {
			if string(tt.elem) != tt.want {
				t.Errorf("Element = %q, want %q", string(tt.elem), tt.want)
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

func TestGetPayloadsByElement_EmptyResult(t *testing.T) {
	payloads := GetPayloadsByElement(Element("nonexistent"))
	if len(payloads) != 0 {
		t.Errorf("Expected no payloads for nonexistent element, got %d", len(payloads))
	}
}

func TestDOMPropertyPayloads(t *testing.T) {
	payloads := GetPayloads()

	hasDOMProperty := false
	for _, p := range payloads {
		if p.TargetProperty != "" {
			hasDOMProperty = true
			break
		}
	}

	if !hasDOMProperty {
		t.Error("Expected at least one payload targeting a DOM property")
	}
}

func TestAllPayloadsHaveValidElement(t *testing.T) {
	validElements := map[Element]bool{
		ElemForm:   true,
		ElemImg:    true,
		ElemAnchor: true,
		ElemObject: true,
		ElemEmbed:  true,
	}

	for _, p := range GetPayloads() {
		if !validElements[p.Element] {
			t.Errorf("Payload %q has invalid element %q", p.Value, p.Element)
		}
	}
}
