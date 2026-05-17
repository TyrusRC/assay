package openapi

import (
	"context"
	"sort"
	"strings"
	"testing"
)

func TestExpand_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		baseURL   string
		wantURLs  []string
		wantCount int
	}{
		{
			name: "minimal openapi 3.0 with single GET",
			spec: `{
				"openapi": "3.0.0",
				"paths": {
					"/pets": {
						"get": {"responses": {"200": {"description": "ok"}}}
					}
				}
			}`,
			baseURL:   "https://api.example.com",
			wantURLs:  []string{"https://api.example.com/pets"},
			wantCount: 1,
		},
		{
			name: "path parameter with example value",
			spec: `{
				"openapi": "3.0.0",
				"paths": {
					"/pets/{petId}": {
						"get": {
							"parameters": [
								{"name": "petId", "in": "path", "required": true,
								 "schema": {"type": "integer", "example": 42}}
							],
							"responses": {"200": {"description": "ok"}}
						}
					}
				}
			}`,
			baseURL:   "https://api.example.com",
			wantURLs:  []string{"https://api.example.com/pets/42"},
			wantCount: 1,
		},
		{
			name: "path parameter with enum picks first",
			spec: `{
				"openapi": "3.0.0",
				"paths": {
					"/orders/{status}": {
						"get": {
							"parameters": [
								{"name": "status", "in": "path", "required": true,
								 "schema": {"type": "string", "enum": ["paid", "pending", "cancelled"]}}
							],
							"responses": {"200": {"description": "ok"}}
						}
					}
				}
			}`,
			baseURL:   "https://api.example.com",
			wantURLs:  []string{"https://api.example.com/orders/paid"},
			wantCount: 1,
		},
		{
			name: "path parameter with default value",
			spec: `{
				"openapi": "3.0.0",
				"paths": {
					"/items/{id}": {
						"get": {
							"parameters": [
								{"name": "id", "in": "path", "required": true,
								 "schema": {"type": "string", "default": "abc"}}
							],
							"responses": {"200": {"description": "ok"}}
						}
					}
				}
			}`,
			baseURL:   "https://api.example.com",
			wantURLs:  []string{"https://api.example.com/items/abc"},
			wantCount: 1,
		},
		{
			name: "missing schema falls back to synthetic value",
			spec: `{
				"openapi": "3.0.0",
				"paths": {
					"/users/{userId}/posts/{postId}": {
						"get": {
							"parameters": [
								{"name": "userId", "in": "path", "required": true,
								 "schema": {"type": "integer"}},
								{"name": "postId", "in": "path", "required": true,
								 "schema": {"type": "string"}}
							],
							"responses": {"200": {"description": "ok"}}
						}
					}
				}
			}`,
			baseURL:   "https://api.example.com",
			wantURLs:  []string{"https://api.example.com/users/1/posts/sample"},
			wantCount: 1,
		},
		{
			name: "multiple methods per path",
			spec: `{
				"openapi": "3.0.0",
				"paths": {
					"/pets": {
						"get": {"responses": {"200": {"description": "ok"}}},
						"post": {"responses": {"201": {"description": "created"}}}
					}
				}
			}`,
			baseURL:   "https://api.example.com",
			wantURLs:  []string{"https://api.example.com/pets", "https://api.example.com/pets"},
			wantCount: 2,
		},
		{
			name: "uses spec servers[0] when baseURL is empty",
			spec: `{
				"openapi": "3.0.0",
				"servers": [{"url": "https://from-spec.example.com/v1"}],
				"paths": {
					"/things": {
						"get": {"responses": {"200": {"description": "ok"}}}
					}
				}
			}`,
			baseURL:   "",
			wantURLs:  []string{"https://from-spec.example.com/v1/things"},
			wantCount: 1,
		},
		{
			name: "swagger 2.0 host+basePath",
			spec: `{
				"swagger": "2.0",
				"host": "api.legacy.example.com",
				"basePath": "/v2",
				"schemes": ["https"],
				"paths": {
					"/foo": {
						"get": {"responses": {"200": {"description": "ok"}}}
					}
				}
			}`,
			baseURL:   "",
			wantURLs:  []string{"https://api.legacy.example.com/v2/foo"},
			wantCount: 1,
		},
		{
			name: "path-level parameters apply to all ops",
			spec: `{
				"openapi": "3.0.0",
				"paths": {
					"/pets/{petId}": {
						"parameters": [
							{"name": "petId", "in": "path", "required": true,
							 "schema": {"type": "integer", "example": 7}}
						],
						"get":    {"responses": {"200": {"description": "ok"}}},
						"delete": {"responses": {"204": {"description": "ok"}}}
					}
				}
			}`,
			baseURL:   "https://api.example.com",
			wantURLs:  []string{"https://api.example.com/pets/7", "https://api.example.com/pets/7"},
			wantCount: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eps, err := Expand(context.Background(), []byte(tc.spec), tc.baseURL)
			if err != nil {
				t.Fatalf("Expand() error = %v", err)
			}
			if len(eps) != tc.wantCount {
				t.Fatalf("len(endpoints) = %d, want %d (%v)", len(eps), tc.wantCount, eps)
			}
			got := make([]string, 0, len(eps))
			for _, e := range eps {
				got = append(got, e.URL)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.wantURLs...)
			sort.Strings(want)
			if !equalStringSlices(got, want) {
				t.Errorf("URLs =\n  got:  %v\n  want: %v", got, want)
			}
		})
	}
}

func TestExpand_InvalidJSON(t *testing.T) {
	_, err := Expand(context.Background(), []byte(`{not json`), "https://x.example.com")
	if err == nil {
		t.Fatal("Expand() with invalid JSON should error")
	}
}

func TestExpand_NotOpenAPISpec(t *testing.T) {
	// A JSON document that is valid JSON but not an OpenAPI spec.
	eps, err := Expand(context.Background(), []byte(`{"hello":"world"}`), "https://x.example.com")
	if err == nil {
		t.Fatal("Expand() with non-spec JSON should error")
	}
	if eps != nil {
		t.Errorf("endpoints should be nil, got %v", eps)
	}
}

func TestExpand_MethodSet(t *testing.T) {
	spec := `{
		"openapi": "3.0.0",
		"paths": {
			"/x": {
				"get": {"responses":{"200":{"description":"ok"}}},
				"post": {"responses":{"200":{"description":"ok"}}},
				"put": {"responses":{"200":{"description":"ok"}}},
				"patch": {"responses":{"200":{"description":"ok"}}},
				"delete": {"responses":{"200":{"description":"ok"}}},
				"summary": "not a method, should be ignored"
			}
		}
	}`
	eps, err := Expand(context.Background(), []byte(spec), "https://api.example.com")
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}
	methods := make(map[string]int)
	for _, e := range eps {
		methods[e.Method]++
	}
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		if methods[m] != 1 {
			t.Errorf("method %s count = %d, want 1", m, methods[m])
		}
	}
	if len(eps) != 5 {
		t.Errorf("got %d endpoints, want 5; methods=%v", len(eps), methods)
	}
}

func TestEndpoint_FieldsPopulated(t *testing.T) {
	spec := `{
		"openapi": "3.0.0",
		"paths": {
			"/pets": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {"type":"object"},
								"example": {"name":"rex"}
							}
						}
					},
					"responses": {"201":{"description":"created"}}
				}
			}
		}
	}`
	eps, err := Expand(context.Background(), []byte(spec), "https://api.example.com")
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	ep := eps[0]
	if ep.Method != "POST" {
		t.Errorf("Method = %q, want POST", ep.Method)
	}
	if ep.URL != "https://api.example.com/pets" {
		t.Errorf("URL = %q", ep.URL)
	}
	if !strings.Contains(ep.Body, "rex") {
		t.Errorf("Body should contain example value, got %q", ep.Body)
	}
	if ep.Headers["Content-Type"] != "application/json" {
		t.Errorf("Headers[Content-Type] = %q, want application/json", ep.Headers["Content-Type"])
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
