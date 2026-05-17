package openapisemantic

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Spec is a minimal subset of an OpenAPI 3.x document — only the fields the
// semantic detector actually uses. The original tree stays opaque elsewhere.
type Spec struct {
	OpenAPI string              `json:"openapi"`
	Paths   map[string]PathItem `json:"paths"`
}

// PathItem groups operations under a single path. Each verb is a separate
// Operation entry. Unknown / un-modeled fields are silently skipped.
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

// Operation is the slice of an OpenAPI operation we care about: its request
// body schema and (when present) a 2xx response — that's enough for every
// probe in this package.
type Operation struct {
	OperationID string       `json:"operationId,omitempty"`
	RequestBody *RequestBody `json:"requestBody,omitempty"`
}

// RequestBody mirrors the OAS request body object. Required defaults to false.
type RequestBody struct {
	Required bool                 `json:"required,omitempty"`
	Content  map[string]MediaType `json:"content,omitempty"`
}

// MediaType holds the schema attached to a content type. We only inspect the
// JSON variant in practice.
type MediaType struct {
	Schema *Schema `json:"schema,omitempty"`
}

// Schema is the recursive descent of an OpenAPI schema, narrowed to the
// fields the semantic probes inspect. It keeps a free-form Extras map to
// stash anything we'd otherwise drop on re-marshaling (e.g. example values
// the caller may want to preserve).
type Schema struct {
	Type                 string             `json:"type,omitempty"`
	Format               string             `json:"format,omitempty"`
	Nullable             bool               `json:"nullable,omitempty"`
	Required             []string           `json:"required,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	AdditionalProperties *AdditionalProps   `json:"additionalProperties,omitempty"`
	OneOf                []*Schema          `json:"oneOf,omitempty"`
	AnyOf                []*Schema          `json:"anyOf,omitempty"`
	Discriminator        *Discriminator     `json:"discriminator,omitempty"`
	Enum                 []interface{}      `json:"enum,omitempty"`
	Default              interface{}        `json:"default,omitempty"`
	Example              interface{}        `json:"example,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
}

// Discriminator names the property whose value selects a oneOf/anyOf branch.
type Discriminator struct {
	PropertyName string            `json:"propertyName,omitempty"`
	Mapping      map[string]string `json:"mapping,omitempty"`
}

// AdditionalProps captures the dual nature of OpenAPI's additionalProperties
// field — it's either a boolean (allow / deny extras) or a schema describing
// what extras must look like. We decode both.
type AdditionalProps struct {
	Allowed bool    // true when missing or set to true; false when explicit false
	Schema  *Schema // non-nil when the field was a schema object
	Set     bool    // explicitly present in the source document
}

// UnmarshalJSON decodes additionalProperties from either a bool or an object.
func (a *AdditionalProps) UnmarshalJSON(data []byte) error {
	a.Set = true
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "true" {
		a.Allowed = true
		return nil
	}
	if trimmed == "false" {
		a.Allowed = false
		return nil
	}
	// Object form — a schema constraint on extras.
	var s Schema
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("openapisemantic: additionalProperties: %w", err)
	}
	a.Schema = &s
	a.Allowed = true
	return nil
}

// ParseSpec parses a JSON OpenAPI document into the minimal Spec used by the
// detector. YAML is intentionally unsupported — callers ship JSON.
func ParseSpec(body []byte) (*Spec, error) {
	var spec Spec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, fmt.Errorf("openapisemantic: parse spec: %w", err)
	}
	if spec.Paths == nil {
		spec.Paths = map[string]PathItem{}
	}
	return &spec, nil
}

// JSONSchema returns the schema attached to a request body's application/json
// (or compatible json+...) entry, or nil if absent. Centralized so probes
// don't reimplement the media-type fallback.
func (op *Operation) JSONSchema() *Schema {
	if op == nil || op.RequestBody == nil {
		return nil
	}
	for mt, m := range op.RequestBody.Content {
		mtLower := strings.ToLower(mt)
		if mtLower == "application/json" || strings.HasSuffix(mtLower, "+json") {
			return m.Schema
		}
	}
	return nil
}

// Operations yields each declared operation in the spec along with its
// (method, path). The iteration order is unspecified because PathItem is
// stored in a map — callers that need stable ordering must sort.
func (s *Spec) Operations() []OperationRef {
	if s == nil {
		return nil
	}
	out := make([]OperationRef, 0, len(s.Paths)*2)
	for p, item := range s.Paths {
		if item.Get != nil {
			out = append(out, OperationRef{Method: "GET", Path: p, Op: item.Get})
		}
		if item.Post != nil {
			out = append(out, OperationRef{Method: "POST", Path: p, Op: item.Post})
		}
		if item.Put != nil {
			out = append(out, OperationRef{Method: "PUT", Path: p, Op: item.Put})
		}
		if item.Patch != nil {
			out = append(out, OperationRef{Method: "PATCH", Path: p, Op: item.Patch})
		}
		if item.Delete != nil {
			out = append(out, OperationRef{Method: "DELETE", Path: p, Op: item.Delete})
		}
	}
	return out
}

// OperationRef is a flattened (method, path, op) triple.
type OperationRef struct {
	Method string
	Path   string
	Op     *Operation
}
