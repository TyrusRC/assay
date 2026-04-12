package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestJSRouteDiscoverer_Name(t *testing.T) {
	d := NewJSRouteDiscoverer()
	if d.Name() != "jsroute" {
		t.Errorf("Name() = %q, want %q", d.Name(), "jsroute")
	}
}

func TestJSRouteDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		contentType    string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name:        "fetch calls with query parameters",
			contentType: "application/javascript",
			body:        `fetch("/api/users?page=1&limit=10")`,
			expectedParams: []core.Parameter{
				{Name: "page", Location: core.ParamLocationQuery, Value: "1"},
				{Name: "limit", Location: core.ParamLocationQuery, Value: "10"},
			},
		},
		{
			name:        "axios calls with query parameters",
			contentType: "application/javascript",
			body:        `axios.get("/api/search?q=test&sort=name")`,
			expectedParams: []core.Parameter{
				{Name: "q", Location: core.ParamLocationQuery, Value: "test"},
				{Name: "sort", Location: core.ParamLocationQuery, Value: "name"},
			},
		},
		{
			name:        "API route patterns",
			contentType: "application/javascript",
			body:        `var url = "/api/v1/users?id=123"; var other = "/api/v2/orders?status=active";`,
			expectedParams: []core.Parameter{
				{Name: "id", Location: core.ParamLocationQuery, Value: "123"},
				{Name: "status", Location: core.ParamLocationQuery, Value: "active"},
			},
		},
		{
			name:        "fetch with single quotes",
			contentType: "text/javascript",
			body:        `fetch('/api/items?category=books')`,
			expectedParams: []core.Parameter{
				{Name: "category", Location: core.ParamLocationQuery, Value: "books"},
			},
		},
		{
			name:        "axios post call",
			contentType: "application/javascript",
			body:        `axios.post("/api/login?redirect=/home")`,
			expectedParams: []core.Parameter{
				{Name: "redirect", Location: core.ParamLocationQuery, Value: "/home"},
			},
		},
		{
			name:        "no query parameters in routes",
			contentType: "application/javascript",
			body:        `fetch("/api/users")`,
			expectEmpty: true,
		},
		{
			name:        "non-javascript content type",
			contentType: "text/html",
			body:        `fetch("/api/users?page=1")`,
			expectEmpty: true,
		},
		{
			name:        "empty body",
			contentType: "application/javascript",
			body:        "",
			expectEmpty: true,
		},
		{
			name:        "application/json content type",
			contentType: "application/json",
			body:        `{"endpoint": "/api/search?q=test"}`,
			expectedParams: []core.Parameter{
				{Name: "q", Location: core.ParamLocationQuery, Value: "test"},
			},
		},
		{
			name:        "deduplicates parameters",
			contentType: "application/javascript",
			body:        `fetch("/api/a?key=1"); fetch("/api/b?key=2")`,
			expectedParams: []core.Parameter{
				{Name: "key", Location: core.ParamLocationQuery},
			},
		},
	}

	d := NewJSRouteDiscoverer()

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

func TestJSRouteDiscoverer_NilResponse(t *testing.T) {
	d := NewJSRouteDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}
