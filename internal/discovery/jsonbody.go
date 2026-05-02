package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// readOnlyKeys are JSON fields that are typically not injectable.
var readOnlyKeys = map[string]bool{
	"id":         true,
	"_id":        true,
	"created_at": true,
	"updated_at": true,
	"created":    true,
	"updated":    true,
	"_links":     true,
	"_embedded":  true,
	"self":       true,
	"href":       true,
	"version":    true,
	"timestamp":  true,
}

// JSONBodyDiscoverer extracts injectable parameters from JSON response bodies.
type JSONBodyDiscoverer struct{}

// NewJSONBodyDiscoverer creates a new JSONBodyDiscoverer.
func NewJSONBodyDiscoverer() *JSONBodyDiscoverer {
	return &JSONBodyDiscoverer{}
}

// Name returns the discoverer identifier.
func (j *JSONBodyDiscoverer) Name() string {
	return "jsonbody"
}

// Discover extracts parameters from a JSON response body.
// Only processes responses with Content-Type application/json.
// Extracts top-level keys and one level of nested keys, skipping read-only fields.
func (j *JSONBodyDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	// Only process JSON responses
	if !strings.Contains(resp.ContentType, "application/json") {
		return nil, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &data); err != nil {
		return nil, nil // Not a JSON object, skip
	}

	var params []core.Parameter
	seen := make(map[string]bool)

	for key, value := range data {
		if readOnlyKeys[strings.ToLower(key)] {
			continue
		}

		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     key,
				Location: core.ParamLocationBody,
				Value:    jsonValueToString(value),
				Type:     jsonTypeString(value),
			})
		}

		// One level deep for nested objects
		if nested, ok := value.(map[string]interface{}); ok {
			for nestedKey, nestedValue := range nested {
				fullKey := key + "." + nestedKey
				if readOnlyKeys[strings.ToLower(nestedKey)] {
					continue
				}
				if !seen[fullKey] {
					seen[fullKey] = true
					params = append(params, core.Parameter{
						Name:     fullKey,
						Location: core.ParamLocationBody,
						Value:    jsonValueToString(nestedValue),
						Type:     jsonTypeString(nestedValue),
					})
				}
			}
		}
	}

	return params, nil
}

// jsonValueToString converts a JSON value to its string representation.
func jsonValueToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		// Use fmt for clean number formatting
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// jsonTypeString returns the type string for a JSON value.
func jsonTypeString(v interface{}) string {
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "string"
	}
}
