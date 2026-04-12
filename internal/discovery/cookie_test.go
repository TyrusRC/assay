package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestCookieDiscoverer_Name(t *testing.T) {
	d := NewCookieDiscoverer()
	if d.Name() != "cookie" {
		t.Errorf("Name() = %q, want %q", d.Name(), "cookie")
	}
}

func TestCookieDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		expectedParams []core.Parameter
	}{
		{
			name: "single cookie",
			headers: map[string]string{
				"Set-Cookie": "session=abc123; Path=/; HttpOnly",
			},
			expectedParams: []core.Parameter{
				{Name: "session", Location: core.ParamLocationCookie, Value: "abc123"},
			},
		},
		{
			name: "multiple cookies joined",
			headers: map[string]string{
				"Set-Cookie": "session=abc123; Path=/, user_id=42; Path=/",
			},
			expectedParams: []core.Parameter{
				{Name: "session", Location: core.ParamLocationCookie, Value: "abc123"},
				{Name: "user_id", Location: core.ParamLocationCookie, Value: "42"},
			},
		},
		{
			name: "cookie with Expires date containing comma",
			headers: map[string]string{
				"Set-Cookie": "token=xyz; Expires=Thu, 01 Dec 2025 16:00:00 GMT; Path=/",
			},
			expectedParams: []core.Parameter{
				{Name: "token", Location: core.ParamLocationCookie, Value: "xyz"},
			},
		},
		{
			name:    "no Set-Cookie header",
			headers: map[string]string{},
		},
		{
			name: "lowercase set-cookie",
			headers: map[string]string{
				"set-cookie": "lang=en; Path=/",
			},
			expectedParams: []core.Parameter{
				{Name: "lang", Location: core.ParamLocationCookie, Value: "en"},
			},
		},
		{
			name: "cookie with empty value",
			headers: map[string]string{
				"Set-Cookie": "deleted=; Path=/; Max-Age=0",
			},
			expectedParams: []core.Parameter{
				{Name: "deleted", Location: core.ParamLocationCookie, Value: ""},
			},
		},
	}

	d := NewCookieDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Headers: tt.headers}
			params, err := d.Discover(context.Background(), "http://example.com", resp)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			if len(params) != len(tt.expectedParams) {
				t.Fatalf("Discover() count = %d, want %d; got %v", len(params), len(tt.expectedParams), params)
			}

			for _, expected := range tt.expectedParams {
				found := false
				for _, p := range params {
					if p.Name == expected.Name && p.Location == expected.Location {
						found = true
						if p.Value != expected.Value {
							t.Errorf("param %q value = %q, want %q", expected.Name, p.Value, expected.Value)
						}
						break
					}
				}
				if !found {
					t.Errorf("missing expected param: Name=%q Location=%q", expected.Name, expected.Location)
				}
			}
		})
	}
}

func TestCookieDiscoverer_NilResponse(t *testing.T) {
	d := NewCookieDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}

func TestCookieDiscoverer_DeduplicatesNames(t *testing.T) {
	d := NewCookieDiscoverer()
	resp := &http.Response{
		Headers: map[string]string{
			"Set-Cookie": "session=abc; Path=/, session=def; Path=/",
		},
	}
	params, err := d.Discover(context.Background(), "http://example.com", resp)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(params) != 1 {
		t.Errorf("Discover() should deduplicate, got %d params", len(params))
	}
}
