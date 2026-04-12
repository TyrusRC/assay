package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

func TestHeaderDiscoverer_Name(t *testing.T) {
	d := NewHeaderDiscoverer()
	if d.Name() != "header" {
		t.Errorf("Name() = %q, want %q", d.Name(), "header")
	}
}

func TestHeaderDiscoverer_Discover(t *testing.T) {
	d := NewHeaderDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(params) == 0 {
		t.Fatal("Discover() returned empty params")
	}

	// All params should be header location
	for _, p := range params {
		if p.Location != core.ParamLocationHeader {
			t.Errorf("param %q location = %q, want %q", p.Name, p.Location, core.ParamLocationHeader)
		}
	}

	// Check known headers are present
	expectedHeaders := []string{
		"Referer", "X-Forwarded-For", "X-Forwarded-Host",
		"User-Agent", "Host", "Origin",
	}
	for _, expected := range expectedHeaders {
		found := false
		for _, p := range params {
			if p.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected header: %q", expected)
		}
	}
}

func TestInjectableHeaders(t *testing.T) {
	headers := InjectableHeaders()
	if len(headers) == 0 {
		t.Fatal("InjectableHeaders() returned empty")
	}

	// Verify it's a copy
	headers[0] = "modified"
	original := InjectableHeaders()
	if original[0] == "modified" {
		t.Error("InjectableHeaders() should return a copy")
	}
}
