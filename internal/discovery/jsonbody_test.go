package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestJSONBodyDiscoverer_Name(t *testing.T) {
	d := NewJSONBodyDiscoverer()
	if d.Name() != "jsonbody" {
		t.Errorf("Name() = %q, want %q", d.Name(), "jsonbody")
	}
}

func TestJSONBodyDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		contentType    string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name:        "flat JSON object",
			contentType: "application/json",
			body:        `{"username":"admin","email":"test@test.com","age":25}`,
			expectedParams: []core.Parameter{
				{Name: "username", Location: core.ParamLocationBody, Value: "admin", Type: "string"},
				{Name: "email", Location: core.ParamLocationBody, Value: "test@test.com", Type: "string"},
				{Name: "age", Location: core.ParamLocationBody, Value: "25", Type: "number"},
			},
		},
		{
			name:        "nested JSON object",
			contentType: "application/json; charset=utf-8",
			body:        `{"user":{"name":"admin","role":"editor"}}`,
			expectedParams: []core.Parameter{
				{Name: "user", Location: core.ParamLocationBody, Type: "object"},
				{Name: "user.name", Location: core.ParamLocationBody, Value: "admin", Type: "string"},
				{Name: "user.role", Location: core.ParamLocationBody, Value: "editor", Type: "string"},
			},
		},
		{
			name:        "skips read-only keys",
			contentType: "application/json",
			body:        `{"id":1,"name":"test","created_at":"2024-01-01","_links":{}}`,
			expectedParams: []core.Parameter{
				{Name: "name", Location: core.ParamLocationBody, Value: "test", Type: "string"},
			},
		},
		{
			name:        "boolean and array values",
			contentType: "application/json",
			body:        `{"active":true,"tags":["a","b"]}`,
			expectedParams: []core.Parameter{
				{Name: "active", Location: core.ParamLocationBody, Value: "true", Type: "boolean"},
				{Name: "tags", Location: core.ParamLocationBody, Type: "array"},
			},
		},
		{
			name:        "non-JSON content type",
			contentType: "text/html",
			body:        `{"username":"admin"}`,
			expectEmpty: true,
		},
		{
			name:        "non-JSON body",
			contentType: "application/json",
			body:        `not json at all`,
			expectEmpty: true,
		},
		{
			name:        "empty body",
			contentType: "application/json",
			body:        "",
			expectEmpty: true,
		},
		{
			name:        "JSON array (not object)",
			contentType: "application/json",
			body:        `[{"id":1}]`,
			expectEmpty: true,
		},
	}

	d := NewJSONBodyDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:        tt.body,
				ContentType: tt.contentType,
			}
			params, err := d.Discover(context.Background(), "http://example.com", resp)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			if tt.expectEmpty {
				if len(params) != 0 {
					t.Errorf("Discover() should return empty, got %v", params)
				}
				return
			}

			if len(params) != len(tt.expectedParams) {
				t.Fatalf("Discover() count = %d, want %d; got %v", len(params), len(tt.expectedParams), params)
			}

			for _, expected := range tt.expectedParams {
				found := false
				for _, p := range params {
					if p.Name == expected.Name && p.Location == expected.Location {
						found = true
						if expected.Value != "" && p.Value != expected.Value {
							t.Errorf("param %q value = %q, want %q", expected.Name, p.Value, expected.Value)
						}
						if p.Type != expected.Type {
							t.Errorf("param %q type = %q, want %q", expected.Name, p.Type, expected.Type)
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

func TestJSONBodyDiscoverer_NilResponse(t *testing.T) {
	d := NewJSONBodyDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}
