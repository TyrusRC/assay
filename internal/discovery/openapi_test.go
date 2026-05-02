package discovery

import (
	"context"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestOpenAPIDiscoverer_Name(t *testing.T) {
	d := NewOpenAPIDiscoverer()
	if d.Name() != "openapi" {
		t.Errorf("Name() = %q, want %q", d.Name(), "openapi")
	}
}

func TestOpenAPIDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		contentType    string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name:        "swagger 2.0 with query parameters",
			contentType: "application/json",
			body: `{
				"swagger": "2.0",
				"paths": {
					"/users": {
						"get": {
							"parameters": [
								{"name": "page", "in": "query", "type": "integer"},
								{"name": "limit", "in": "query", "type": "integer"}
							]
						}
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "page", Location: core.ParamLocationQuery},
				{Name: "limit", Location: core.ParamLocationQuery},
			},
		},
		{
			name:        "openapi 3.0 with mixed parameter locations",
			contentType: "application/json",
			body: `{
				"openapi": "3.0.0",
				"paths": {
					"/users/{userId}": {
						"get": {
							"parameters": [
								{"name": "userId", "in": "path"},
								{"name": "Authorization", "in": "header"},
								{"name": "format", "in": "query"}
							]
						}
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "userId", Location: core.ParamLocationPath},
				{Name: "Authorization", Location: core.ParamLocationHeader},
				{Name: "format", Location: core.ParamLocationQuery},
			},
		},
		{
			name:        "path template variables",
			contentType: "application/json",
			body: `{
				"openapi": "3.0.0",
				"paths": {
					"/users/{userId}/orders/{orderId}": {
						"get": {
							"parameters": []
						}
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "userId", Location: core.ParamLocationPath},
				{Name: "orderId", Location: core.ParamLocationPath},
			},
		},
		{
			name:        "body parameter",
			contentType: "application/json",
			body: `{
				"swagger": "2.0",
				"paths": {
					"/users": {
						"post": {
							"parameters": [
								{"name": "body", "in": "body"}
							]
						}
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "body", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "non-JSON content type",
			contentType: "text/html",
			body:        `{"swagger":"2.0"}`,
			expectEmpty: true,
		},
		{
			name:        "not an openapi/swagger document",
			contentType: "application/json",
			body:        `{"name":"test","version":"1.0"}`,
			expectEmpty: true,
		},
		{
			name:        "empty body",
			contentType: "application/json",
			body:        "",
			expectEmpty: true,
		},
		{
			name:        "deduplicates parameters",
			contentType: "application/json",
			body: `{
				"swagger": "2.0",
				"paths": {
					"/users": {
						"get": {
							"parameters": [
								{"name": "page", "in": "query"}
							]
						},
						"post": {
							"parameters": [
								{"name": "page", "in": "query"}
							]
						}
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "page", Location: core.ParamLocationQuery},
			},
		},
		{
			name:        "parameters with both explicit and path template",
			contentType: "application/json",
			body: `{
				"openapi": "3.0.0",
				"paths": {
					"/items/{itemId}": {
						"get": {
							"parameters": [
								{"name": "itemId", "in": "path"},
								{"name": "fields", "in": "query"}
							]
						}
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "itemId", Location: core.ParamLocationPath},
				{Name: "fields", Location: core.ParamLocationQuery},
			},
		},
	}

	d := NewOpenAPIDiscoverer()

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

func TestOpenAPIDiscoverer_NilResponse(t *testing.T) {
	d := NewOpenAPIDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}
