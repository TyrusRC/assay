package discovery

import (
	"context"
	"encoding/json"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// GraphQLIntrospectionDiscoverer extracts field and argument names from GraphQL introspection responses.
type GraphQLIntrospectionDiscoverer struct{ client *http.Client }

// NewGraphQLIntrospectionDiscoverer creates a new GraphQLIntrospectionDiscoverer.
func NewGraphQLIntrospectionDiscoverer() *GraphQLIntrospectionDiscoverer {
	return &GraphQLIntrospectionDiscoverer{}
}

// WithClient lets the discoverer POST an introspection query itself (to the
// target and to /graphql at the host root), instead of only parsing a handed
// response. The client carries the scan's scope and rate limit.
func (g *GraphQLIntrospectionDiscoverer) WithClient(c *http.Client) *GraphQLIntrospectionDiscoverer {
	g.client = c
	return g
}

// Name returns the discoverer identifier.
func (g *GraphQLIntrospectionDiscoverer) Name() string {
	return "graphql-introspection"
}

// introspectionQuery is a minimal introspection body: enough to list types,
// their fields, and each field's argument names.
const introspectionQuery = `{"query":"query{__schema{types{name fields{name args{name}}}}}"}`

// Discover extracts parameters from GraphQL introspection. It first parses the
// handed response, then (with a client) POSTs an introspection query to the
// target and to /graphql at the host root.
func (g *GraphQLIntrospectionDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	if resp != nil && resp.Body != "" {
		if params := g.parseBody(resp.Body); len(params) > 0 {
			return params, nil
		}
	}
	if g.client == nil {
		return nil, nil
	}
	candidates := []string{targetURL}
	if gqlURL, ok := hostRootURL(targetURL, "/graphql"); ok && gqlURL != targetURL {
		candidates = append(candidates, gqlURL)
	}
	for _, u := range candidates {
		rr, err := g.client.PostJSON(ctx, u, introspectionQuery)
		if err != nil || rr == nil {
			continue
		}
		if params := g.parseBody(rr.Body); len(params) > 0 {
			return params, nil
		}
	}
	return nil, nil
}

// parseBody extracts field/argument names from a GraphQL introspection response.
func (g *GraphQLIntrospectionDiscoverer) parseBody(body string) []core.Parameter {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil
	}

	dataRaw, ok := doc["data"]
	if !ok {
		return nil
	}

	data, ok := dataRaw.(map[string]interface{})
	if !ok {
		return nil
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

	return params
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
