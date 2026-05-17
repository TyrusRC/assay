package openapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Endpoint is a concrete request synthesized from one (path, method)
// pair in an OpenAPI spec. URL has all path parameters substituted with
// sample values; Body and Headers carry whatever requestBody example
// the spec provided (Body is empty for verbs that take no payload).
type Endpoint struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// httpMethods enumerates the operation keys recognized in a paths-item.
// Anything else (summary, description, parameters, $ref…) is skipped.
var httpMethods = map[string]string{
	"get":     "GET",
	"post":    "POST",
	"put":     "PUT",
	"patch":   "PATCH",
	"delete":  "DELETE",
	"head":    "HEAD",
	"options": "OPTIONS",
	"trace":   "TRACE",
}

var pathParamRegex = regexp.MustCompile(`\{([^/}]+)\}`)

// Expand parses an OpenAPI 3.x (or Swagger 2.0) spec and returns one
// Endpoint per (path, method) pair, with path parameters substituted
// from example/enum/default values where available.
//
// baseURL overrides any servers entry in the spec. Empty baseURL falls
// back to servers[0].url (OpenAPI 3) or scheme://host+basePath
// (Swagger 2.0).
func Expand(_ context.Context, specJSON []byte, baseURL string) ([]Endpoint, error) {
	if len(specJSON) == 0 {
		return nil, errors.New("openapi: empty spec")
	}

	var doc map[string]any
	if err := json.Unmarshal(specJSON, &doc); err != nil {
		return nil, fmt.Errorf("openapi: parse spec: %w", err)
	}

	_, hasOpenAPI := doc["openapi"]
	_, hasSwagger := doc["swagger"]
	if !hasOpenAPI && !hasSwagger {
		return nil, errors.New("openapi: not an OpenAPI/Swagger document (missing openapi/swagger field)")
	}

	base := resolveBaseURL(doc, baseURL)

	pathsRaw, ok := doc["paths"].(map[string]any)
	if !ok {
		return nil, nil
	}

	var out []Endpoint
	for pathTpl, itemRaw := range pathsRaw {
		item, ok := itemRaw.(map[string]any)
		if !ok {
			continue
		}

		// Path-level parameters apply to every operation under this path.
		pathLevelParams := extractParams(item["parameters"])

		for key, opRaw := range item {
			method, isMethod := httpMethods[strings.ToLower(key)]
			if !isMethod {
				continue
			}
			op, ok := opRaw.(map[string]any)
			if !ok {
				continue
			}

			opParams := extractParams(op["parameters"])
			merged := mergeParams(pathLevelParams, opParams)
			url := substitutePath(base, pathTpl, merged)

			headers := map[string]string{}
			body := ""
			if rb, ok := op["requestBody"].(map[string]any); ok {
				body, headers = extractRequestBody(rb)
			}

			out = append(out, Endpoint{
				Method:  method,
				URL:     url,
				Headers: headers,
				Body:    body,
			})
		}
	}

	return out, nil
}

// resolveBaseURL picks the base URL for the spec. Priority:
//  1. caller-supplied baseURL (most specific intent),
//  2. spec.servers[0].url for OpenAPI 3,
//  3. scheme+host+basePath reconstruction for Swagger 2.0.
func resolveBaseURL(doc map[string]any, override string) string {
	if override != "" {
		return strings.TrimRight(override, "/")
	}
	if servers, ok := doc["servers"].([]any); ok && len(servers) > 0 {
		if s, ok := servers[0].(map[string]any); ok {
			if u, _ := s["url"].(string); u != "" {
				return strings.TrimRight(u, "/")
			}
		}
	}
	// Swagger 2.0 fallback.
	host, _ := doc["host"].(string)
	basePath, _ := doc["basePath"].(string)
	scheme := "https"
	if schemes, ok := doc["schemes"].([]any); ok && len(schemes) > 0 {
		if s, ok := schemes[0].(string); ok && s != "" {
			scheme = s
		}
	}
	if host != "" {
		return strings.TrimRight(scheme+"://"+host+basePath, "/")
	}
	return ""
}

// param captures the bits of an OpenAPI Parameter Object we use during
// path substitution. We deliberately keep this minimal — the expander
// doesn't aim to be a full validator.
type param struct {
	Name     string
	In       string
	Required bool
	Schema   map[string]any
}

// extractParams normalizes the parameters array of an op or path-item.
func extractParams(raw any) []param {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]param, 0, len(arr))
	for _, r := range arr {
		p, ok := r.(map[string]any)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		in, _ := p["in"].(string)
		req, _ := p["required"].(bool)
		schema, _ := p["schema"].(map[string]any)
		if schema == nil {
			// Swagger 2.0 inlines schema fields on the parameter itself.
			schema = p
		}
		out = append(out, param{Name: name, In: in, Required: req, Schema: schema})
	}
	return out
}

// mergeParams overrides path-level params with op-level params of the
// same (name, in) tuple.
func mergeParams(base, override []param) []param {
	type key struct{ name, in string }
	seen := make(map[key]int, len(base)+len(override))
	out := make([]param, 0, len(base)+len(override))
	for _, p := range base {
		seen[key{p.Name, p.In}] = len(out)
		out = append(out, p)
	}
	for _, p := range override {
		k := key{p.Name, p.In}
		if i, ok := seen[k]; ok {
			out[i] = p
			continue
		}
		seen[k] = len(out)
		out = append(out, p)
	}
	return out
}

// substitutePath replaces `{name}` placeholders in pathTpl with sample
// values from matching path-parameters, then joins to base.
func substitutePath(base, pathTpl string, params []param) string {
	byName := make(map[string]param, len(params))
	for _, p := range params {
		if p.In == "path" {
			byName[p.Name] = p
		}
	}
	resolved := pathParamRegex.ReplaceAllStringFunc(pathTpl, func(match string) string {
		name := match[1 : len(match)-1]
		if p, ok := byName[name]; ok {
			return sampleValue(p.Schema)
		}
		// Unknown placeholder — synthesize from name.
		return "sample"
	})
	if base == "" {
		return resolved
	}
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}
	return base + resolved
}

// sampleValue picks a concrete value for a schema object, preferring
// example, then enum[0], then default; falling back to a type-shaped
// synthetic value.
func sampleValue(schema map[string]any) string {
	if schema == nil {
		return "sample"
	}
	if ex, ok := schema["example"]; ok {
		return toString(ex)
	}
	if enumRaw, ok := schema["enum"].([]any); ok && len(enumRaw) > 0 {
		return toString(enumRaw[0])
	}
	if def, ok := schema["default"]; ok {
		return toString(def)
	}
	typ, _ := schema["type"].(string)
	switch typ {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "string":
		return "sample"
	default:
		return "sample"
	}
}

// toString renders an arbitrary JSON-decoded value as a path-safe
// string. Numbers stringify without trailing `.0` decoration.
func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers always decode to float64. Drop fractional zero
		// so {"example": 42} renders as "42", not "42.0".
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case nil:
		return ""
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "sample"
		}
		return string(b)
	}
}

// extractRequestBody pulls the first JSON content example off a
// requestBody object and returns (body, headers). We default to
// application/json since that's what most modern specs use; non-JSON
// content types are passed through with whatever example the spec
// supplied.
func extractRequestBody(rb map[string]any) (string, map[string]string) {
	headers := map[string]string{}
	content, ok := rb["content"].(map[string]any)
	if !ok {
		return "", headers
	}
	// Prefer application/json when present.
	preferred := []string{"application/json"}
	for ct := range content {
		if ct != "application/json" {
			preferred = append(preferred, ct)
		}
	}
	for _, ct := range preferred {
		mediaRaw, ok := content[ct].(map[string]any)
		if !ok {
			continue
		}
		headers["Content-Type"] = ct
		if ex, ok := mediaRaw["example"]; ok {
			if ct == "application/json" {
				if b, err := json.Marshal(ex); err == nil {
					return string(b), headers
				}
			}
			return toString(ex), headers
		}
		// No example? Leave Body empty but signal Content-Type.
		return "", headers
	}
	return "", headers
}
