package executor

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/detection/oob"
)

func TestNewInteractshHelper_NilClient(t *testing.T) {
	h := NewInteractshHelper(nil)
	if h == nil {
		t.Fatal("NewInteractshHelper(nil) returned nil")
	}
	if h.client != nil {
		t.Error("expected nil client")
	}
	if h.payload != nil {
		t.Error("expected nil payload when client is nil")
	}
}

func TestInteractshHelper_GetURL_NilClient(t *testing.T) {
	h := NewInteractshHelper(nil)
	got := h.GetURL()
	if got != interactshPlaceholder {
		t.Errorf("GetURL() = %q, want %q", got, interactshPlaceholder)
	}
}

func TestInteractshHelper_GetDNSURL_NilClient(t *testing.T) {
	h := NewInteractshHelper(nil)
	got := h.GetDNSURL()
	if got != interactshPlaceholder {
		t.Errorf("GetDNSURL() = %q, want %q", got, interactshPlaceholder)
	}
}

func TestInteractshHelper_InjectVariables_NilClient(t *testing.T) {
	h := NewInteractshHelper(nil)
	vars := make(map[string]interface{})
	h.InjectVariables(vars)

	keys := []string{"interactsh-url", "interactsh_url", "interactsh-dns-url"}
	for _, k := range keys {
		v, ok := vars[k]
		if !ok {
			t.Errorf("InjectVariables did not set %q", k)
			continue
		}
		if v != interactshPlaceholder {
			t.Errorf("vars[%q] = %q, want %q", k, v, interactshPlaceholder)
		}
	}
}

func TestInteractshHelper_InjectVariables_PreservesExisting(t *testing.T) {
	h := NewInteractshHelper(nil)
	vars := map[string]interface{}{
		"existing-key": "existing-value",
	}
	h.InjectVariables(vars)

	if vars["existing-key"] != "existing-value" {
		t.Error("InjectVariables should not remove existing variables")
	}
}

func TestInteractshHelper_Poll_NilClient(t *testing.T) {
	h := NewInteractshHelper(nil)
	got := h.Poll(context.Background())
	if got {
		t.Error("Poll() with nil client should return false")
	}
}

func TestInteractshHelper_HasInteraction_NilClient(t *testing.T) {
	h := NewInteractshHelper(nil)
	got := h.HasInteraction()
	if got {
		t.Error("HasInteraction() with nil client should return false")
	}
}

func TestInteractshHelper_InjectVariables_AllKeysSet(t *testing.T) {
	h := NewInteractshHelper(nil)
	vars := make(map[string]interface{})
	h.InjectVariables(vars)

	if len(vars) != 3 {
		t.Errorf("expected 3 variables injected, got %d", len(vars))
	}
}

func TestInteractshHelper_WithNilClientFields(t *testing.T) {
	// Verify all methods work correctly without panic when client is nil
	h := NewInteractshHelper(nil)

	_ = h.GetURL()
	_ = h.GetDNSURL()
	_ = h.Poll(context.Background())
	_ = h.HasInteraction()

	vars := make(map[string]interface{})
	h.InjectVariables(vars)
}

// TestInteractshHelper_TypeAssertions verifies that the oob package types are accessible.
func TestInteractshHelper_TypeAssertions(t *testing.T) {
	// Verify the oob package constants are accessible
	types := []string{
		oob.PayloadTypeSQLi,
		oob.PayloadTypeXXE,
		oob.PayloadTypeSSRF,
	}
	for _, typ := range types {
		if typ == "" {
			t.Error("expected non-empty payload type constant")
		}
	}
}
