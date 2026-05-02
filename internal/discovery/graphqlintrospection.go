package discovery

import (
	"context"
	"encoding/json"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// GraphQLIntrospectionDiscoverer extracts field and argument names from GraphQL introspection responses.
type GraphQLIntrospectionDiscoverer struct{}

// NewGraphQLIntrospectionDiscoverer creates a new GraphQLIntrospectionDiscoverer.
func NewGraphQLIntrospectionDiscoverer() *GraphQLIntrospectionDiscoverer {
	return &GraphQLIntrospectionDiscoverer{}
}

// Name returns the discoverer identifier.
func (g *GraphQLIntrospectionDiscoverer) Name() string {
	return "graphql-introspection"
}

// Discover extracts parameters from GraphQL introspection responses.
func (g *GraphQLIntrospectionDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &doc); err != nil {
		return nil, nil
	}

	dataRaw, ok := doc["data"]
	if !ok {
		return nil, nil
	}

	data, ok := dataRaw.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	// Handle __schema
	if schemaRaw, ok := data["__schema"]; ok {
		schema, ok := schemaRaw.(map[string]interface{})
		if ok {
			g.extractFromTypes(schema, seen, &params)
		}
	}

	// Handle __type
	if typeRaw, ok := data["__type"]; ok {
		typeObj, ok := typeRaw.(map[string]interface{})
		if ok {
			g.extractFields(typeObj, seen, &params)
		}
	}

	if len(params) == 0 {
		return nil, nil
	}

	return params, nil
}

// extractFromTypes extracts fields from schema types array.
func (g *GraphQLIntrospectionDiscoverer) extractFromTypes(schema map[string]interface{}, seen map[string]bool, params *[]core.Parameter) {
	typesRaw, ok := schema["types"]
	if !ok {
		return
	}

	types, ok := typesRaw.([]interface{})
	if !ok {
		return
	}

	for _, tRaw := range types {
		t, ok := tRaw.(map[string]interface{})
		if !ok {
			continue
		}
		g.extractFields(t, seen, params)
	}
}

// extractFields extracts field names and argument names from a type object.
func (g *GraphQLIntrospectionDiscoverer) extractFields(typeObj map[string]interface{}, seen map[string]bool, params *[]core.Parameter) {
	fieldsRaw, ok := typeObj["fields"]
	if !ok {
		return
	}

	fields, ok := fieldsRaw.([]interface{})
	if !ok {
		return
	}

	for _, fRaw := range fields {
		f, ok := fRaw.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := f["name"].(string)
		if name != "" && !seen[name] {
			seen[name] = true
			*params = append(*params, core.Parameter{
				Name:     name,
				Location: core.ParamLocationBody,
			})
		}

		// Extract args
		if argsRaw, ok := f["args"]; ok {
			args, ok := argsRaw.([]interface{})
			if !ok {
				continue
			}
			for _, aRaw := range args {
				a, ok := aRaw.(map[string]interface{})
				if !ok {
					continue
				}
				argName, _ := a["name"].(string)
				if argName != "" && !seen[argName] {
					seen[argName] = true
					*params = append(*params, core.Parameter{
						Name:     argName,
						Location: core.ParamLocationBody,
					})
				}
			}
		}
	}
}
