package apispec

import (
	"testing"
)

const oas3Sample = `{
  "openapi": "3.0.3",
  "info": {"title": "demo", "version": "1.0.0"},
  "servers": [{"url": "https://api.example.test/v1"}],
  "security": [{"bearerAuth": []}],
  "paths": {
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
          {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
        ]
      },
      "delete": {
        "operationId": "deleteUser",
        "security": []
      }
    },
    "/health": {
      "get": {"operationId": "health", "security": []}
    }
  }
}`

const swagger2Sample = `{
  "swagger": "2.0",
  "host": "api.example.test",
  "basePath": "/v2",
  "schemes": ["https"],
  "paths": {
    "/items": {
      "get": {"operationId": "listItems"}
    }
  }
}`

func TestParse_OAS3_PullsServerAndEndpoints(t *testing.T) {
	spec, err := Parse([]byte(oas3Sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if spec.Version != "3.0.3" {
		t.Errorf("Version = %q, want 3.0.3", spec.Version)
	}
	if len(spec.Servers) != 1 || spec.Servers[0] != "https://api.example.test/v1" {
		t.Errorf("Servers = %v", spec.Servers)
	}
	if len(spec.Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints (GET /users/{id}, DELETE /users/{id}, GET /health), got %d", len(spec.Endpoints))
	}
}

func TestParse_OAS3_HonorsPerOpSecurityOverride(t *testing.T) {
	spec, err := Parse([]byte(oas3Sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Root sets bearerAuth, /users/{id} GET inherits it; DELETE explicitly
	// overrides with empty security[] so it should NOT require auth.
	for _, ep := range spec.Endpoints {
		switch {
		case ep.Method == "GET" && ep.Path == "/users/{id}":
			if !ep.RequiresAuth {
				t.Error("GET /users/{id} should inherit root bearerAuth")
			}
		case ep.Method == "DELETE" && ep.Path == "/users/{id}":
			if ep.RequiresAuth {
				t.Error("DELETE /users/{id} explicitly drops security; RequiresAuth should be false")
			}
		case ep.Method == "GET" && ep.Path == "/health":
			if ep.RequiresAuth {
				t.Error("/health drops security; should not require auth")
			}
		}
	}
}

func TestParse_OAS3_ExtractsPathTemplateParam(t *testing.T) {
	spec, _ := Parse([]byte(oas3Sample))
	for _, ep := range spec.Endpoints {
		if ep.Path == "/users/{id}" && ep.Method == "GET" {
			found := false
			for _, p := range ep.Parameters {
				if p.Name == "id" && p.In == "path" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected path param 'id' on GET /users/{id}, got %+v", ep.Parameters)
			}
			return
		}
	}
	t.Error("GET /users/{id} not found")
}

func TestParse_Swagger2_BuildsServerFromHostBasePath(t *testing.T) {
	spec, err := Parse([]byte(swagger2Sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if spec.Version != "2.0" {
		t.Errorf("Version = %q, want 2.0", spec.Version)
	}
	if len(spec.Servers) != 1 || spec.Servers[0] != "https://api.example.test/v2" {
		t.Errorf("Servers = %v", spec.Servers)
	}
}

func TestParse_RejectsNonSpec(t *testing.T) {
	if _, err := Parse([]byte(`{"hello": "world"}`)); err == nil {
		t.Error("expected error parsing non-spec JSON")
	}
}

func TestResolveURL_SubstitutesPathVars(t *testing.T) {
	spec, _ := Parse([]byte(oas3Sample))
	var ep Endpoint
	for _, e := range spec.Endpoints {
		if e.Method == "GET" && e.Path == "/users/{id}" {
			ep = e
			break
		}
	}
	got, err := spec.ResolveURL("https://api.example.test", ep, map[string]string{"id": "42"})
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}
	if got != "https://api.example.test/users/42" {
		t.Errorf("ResolveURL = %q, want %q", got, "https://api.example.test/users/42")
	}
	// No value supplied → "1" default.
	got, _ = spec.ResolveURL("https://api.example.test", ep, nil)
	if got != "https://api.example.test/users/1" {
		t.Errorf("ResolveURL default = %q, want .../users/1", got)
	}
}
