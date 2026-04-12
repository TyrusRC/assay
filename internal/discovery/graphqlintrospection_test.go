package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestGraphQLIntrospectionDiscoverer_Name(t *testing.T) {
	d := NewGraphQLIntrospectionDiscoverer()
	if d.Name() != "graphql-introspection" {
		t.Errorf("Name() = %q, want %q", d.Name(), "graphql-introspection")
	}
}

func TestGraphQLIntrospectionDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name: "introspection with __schema and types",
			body: `{
				"data": {
					"__schema": {
						"types": [
							{
								"name": "User",
								"fields": [
									{"name": "username"},
									{"name": "email"},
									{"name": "role"}
								]
							}
						]
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "username", Location: core.ParamLocationBody},
				{Name: "email", Location: core.ParamLocationBody},
				{Name: "role", Location: core.ParamLocationBody},
			},
		},
		{
			name: "__type introspection",
			body: `{
				"data": {
					"__type": {
						"name": "Query",
						"fields": [
							{"name": "user"},
							{"name": "posts"},
							{"name": "comments"}
						]
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "user", Location: core.ParamLocationBody},
				{Name: "posts", Location: core.ParamLocationBody},
				{Name: "comments", Location: core.ParamLocationBody},
			},
		},
		{
			name: "multiple types with deduplication",
			body: `{
				"data": {
					"__schema": {
						"types": [
							{
								"name": "User",
								"fields": [
									{"name": "id"},
									{"name": "name"}
								]
							},
							{
								"name": "Post",
								"fields": [
									{"name": "id"},
									{"name": "title"},
									{"name": "content"}
								]
							}
						]
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "id", Location: core.ParamLocationBody},
				{Name: "name", Location: core.ParamLocationBody},
				{Name: "title", Location: core.ParamLocationBody},
				{Name: "content", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "no introspection data",
			body:        `{"data": {"users": [{"name": "test"}]}}`,
			expectEmpty: true,
		},
		{
			name:        "empty body",
			body:        "",
			expectEmpty: true,
		},
		{
			name:        "non-JSON body",
			body:        `<html><body>Not JSON</body></html>`,
			expectEmpty: true,
		},
		{
			name: "introspection with empty fields",
			body: `{
				"data": {
					"__schema": {
						"types": [
							{
								"name": "Empty",
								"fields": []
							}
						]
					}
				}
			}`,
			expectEmpty: true,
		},
		{
			name: "fields with args",
			body: `{
				"data": {
					"__schema": {
						"types": [
							{
								"name": "Query",
								"fields": [
									{"name": "user", "args": [{"name": "id"}, {"name": "email"}]},
									{"name": "search", "args": [{"name": "query"}]}
								]
							}
						]
					}
				}
			}`,
			expectedParams: []core.Parameter{
				{Name: "user", Location: core.ParamLocationBody},
				{Name: "id", Location: core.ParamLocationBody},
				{Name: "email", Location: core.ParamLocationBody},
				{Name: "search", Location: core.ParamLocationBody},
				{Name: "query", Location: core.ParamLocationBody},
			},
		},
	}

	d := NewGraphQLIntrospectionDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Body: tt.body}
			params, err := d.Discover(context.Background(), "http://example.com/graphql", resp)
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

func TestGraphQLIntrospectionDiscoverer_NilResponse(t *testing.T) {
	d := NewGraphQLIntrospectionDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}
