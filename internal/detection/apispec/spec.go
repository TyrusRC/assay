// Package apispec ingests an OpenAPI / Swagger document and exercises
// every documented endpoint. It is the multiplier that turns the rest
// of the URL-level detector inventory into an API-fluent scanner: each
// (method, path, params) tuple becomes a target the existing detectors
// can attack with a valid request shape.
//
// This file owns the spec-loading and endpoint-extraction half. The
// runner that exercises endpoints lives in runner.go.
package apispec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Endpoint is the canonical record we extract from an OpenAPI document.
// One entry per (method, path) so a runner can exercise each verb
// independently — verb tampering depends on knowing what verbs are
// documented vs what the server actually accepts.
type Endpoint struct {
	Method      string         // e.g. "GET", "POST"
	Path        string         // path template, e.g. "/users/{id}"
	OperationID string         // when present in the spec
	Parameters  []SpecParameter
	HasBody     bool
	BodyMediaTypes []string
	RequiresAuth bool          // any non-empty security entry on op or root
}

// SpecParameter mirrors the OpenAPI parameter object, narrowed to the
// fields downstream attacks care about.
type SpecParameter struct {
	Name     string // parameter name
	In       string // query, path, header, cookie
	Required bool
	Type     string // schema.type when scalar; "" otherwise
}

// Spec is a parsed OpenAPI / Swagger document. We only keep the bits we
// use; the original JSON tree stays opaque.
type Spec struct {
	Version   string // "2.0", "3.0.x", "3.1.x"
	Servers   []string
	Endpoints []Endpoint
}

// pathVarRe matches OpenAPI path templates like /users/{id}.
var pathVarRe = regexp.MustCompile(`\{([^}]+)\}`)

// LoadFromURL fetches a spec at specURL and parses it. When the URL hosts
// a Swagger UI it usually exposes the JSON at /openapi.json or /v3/api-docs;
// this loader doesn't probe — callers pass the JSON URL directly.
func LoadFromURL(ctx context.Context, client *skwshttp.Client, specURL string) (*Spec, error) {
	if client == nil {
		return nil, fmt.Errorf("apispec: nil client")
	}
	resp, err := client.Get(ctx, specURL)
	if err != nil || resp == nil {
		return nil, fmt.Errorf("apispec: fetch %s: %w", specURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("apispec: %s returned status %d", specURL, resp.StatusCode)
	}
	return Parse([]byte(resp.Body))
}

// Parse parses a raw spec body. JSON only — YAML support is intentionally
// deferred (most public APIs ship JSON-formatted /openapi.json or
// /v2/api-docs anyway, and we'd rather not pull a YAML dep in for one
// caller).
func Parse(body []byte) (*Spec, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("apispec: parse json: %w", err)
	}

	spec := &Spec{}
	if v, _ := doc["openapi"].(string); v != "" {
		spec.Version = v
	} else if v, _ := doc["swagger"].(string); v != "" {
		spec.Version = v
	} else {
		return nil, fmt.Errorf("apispec: missing openapi/swagger version field")
	}

	spec.Servers = extractServers(doc)
	rootSecurity := extractSecurityRequirementCount(doc["security"])

	pathsRaw, _ := doc["paths"].(map[string]interface{})
	for pathStr, methodsRaw := range pathsRaw {
		methods, _ := methodsRaw.(map[string]interface{})
		// Path-level parameters apply to every operation under the path.
		pathParams := extractParameters(methods["parameters"])

		for verb, opRaw := range methods {
			vu := strings.ToUpper(verb)
			if !isHTTPVerb(vu) {
				continue
			}
			op, _ := opRaw.(map[string]interface{})

			ep := Endpoint{
				Method: vu,
				Path:   pathStr,
			}
			ep.OperationID, _ = op["operationId"].(string)

			ep.Parameters = append(ep.Parameters, pathParams...)
			ep.Parameters = append(ep.Parameters, extractParameters(op["parameters"])...)
			ep.Parameters = ensurePathTemplateParams(pathStr, ep.Parameters)

			if rb, ok := op["requestBody"].(map[string]interface{}); ok {
				ep.HasBody = true
				if content, ok := rb["content"].(map[string]interface{}); ok {
					for mt := range content {
						ep.BodyMediaTypes = append(ep.BodyMediaTypes, mt)
					}
				}
			}

			opSec := extractSecurityRequirementCount(op["security"])
			if opSec > 0 || (op["security"] == nil && rootSecurity > 0) {
				ep.RequiresAuth = true
			}

			spec.Endpoints = append(spec.Endpoints, ep)
		}
	}

	return spec, nil
}

// ResolveURL renders a spec path against a base URL, substituting any
// {var} placeholders with the supplied values (or "1" as a safe default
// for numeric-looking ids). The returned URL is suitable for passing to
// the standard URL-level detectors.
func (s *Spec) ResolveURL(baseURL string, ep Endpoint, pathVars map[string]string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	rendered := pathVarRe.ReplaceAllStringFunc(ep.Path, func(m string) string {
		name := strings.Trim(m, "{}")
		if v, ok := pathVars[name]; ok && v != "" {
			return v
		}
		return "1"
	})
	out := *base
	// Preserve any base path on the host.
	out.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(rendered, "/")
	return out.String(), nil
}

// extractServers pulls the OpenAPI v3 servers[].url list and the v2
// host/basePath/schemes combo. The first non-empty entry is used by the
// runner unless the caller supplies a base URL of their own.
func extractServers(doc map[string]interface{}) []string {
	if servers, ok := doc["servers"].([]interface{}); ok {
		var out []string
		for _, s := range servers {
			if m, ok := s.(map[string]interface{}); ok {
				if u, _ := m["url"].(string); u != "" {
					out = append(out, u)
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	host, _ := doc["host"].(string)
	basePath, _ := doc["basePath"].(string)
	schemes, _ := doc["schemes"].([]interface{})
	if host != "" {
		scheme := "https"
		if len(schemes) > 0 {
			if s, ok := schemes[0].(string); ok {
				scheme = s
			}
		}
		return []string{scheme + "://" + host + basePath}
	}
	return nil
}

// extractParameters reads a parameters[] block, supporting both the OAS3
// and Swagger 2 shapes (the field names happen to overlap).
func extractParameters(raw interface{}) []SpecParameter {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var out []SpecParameter
	for _, p := range list {
		m, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		required, _ := m["required"].(bool)
		ptype := ""
		if schema, ok := m["schema"].(map[string]interface{}); ok {
			ptype, _ = schema["type"].(string)
		} else if t, ok := m["type"].(string); ok {
			ptype = t
		}
		if name == "" || in == "" {
			continue
		}
		out = append(out, SpecParameter{
			Name:     name,
			In:       in,
			Required: required,
			Type:     ptype,
		})
	}
	return out
}

// ensurePathTemplateParams guarantees every {var} appearing in path
// gets a "path" SpecParameter even when the spec author forgot the
// explicit parameters[] entry.
func ensurePathTemplateParams(path string, existing []SpecParameter) []SpecParameter {
	have := map[string]bool{}
	for _, p := range existing {
		if p.In == "path" {
			have[p.Name] = true
		}
	}
	for _, m := range pathVarRe.FindAllStringSubmatch(path, -1) {
		name := m[1]
		if have[name] {
			continue
		}
		existing = append(existing, SpecParameter{Name: name, In: "path", Required: true})
	}
	return existing
}

// extractSecurityRequirementCount returns the number of security
// requirements declared. Zero means "no auth"; non-zero means any caller
// must satisfy at least one of the requirements.
func extractSecurityRequirementCount(raw interface{}) int {
	list, ok := raw.([]interface{})
	if !ok {
		return 0
	}
	return len(list)
}

func isHTTPVerb(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE":
		return true
	}
	return false
}
