package discovery

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// OpenAPIDiscoverer extracts parameters from OpenAPI/Swagger JSON specs.
type OpenAPIDiscoverer struct{}

// NewOpenAPIDiscoverer creates a new OpenAPIDiscoverer.
func NewOpenAPIDiscoverer() *OpenAPIDiscoverer {
	return &OpenAPIDiscoverer{}
}

// Name returns the discoverer identifier.
func (o *OpenAPIDiscoverer) Name() string {
	return "openapi"
}

var pathVarRegex = regexp.MustCompile(`\{(\w+)\}`)

// Discover extracts parameters from OpenAPI/Swagger specifications.
func (o *OpenAPIDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	if !strings.Contains(strings.ToLower(resp.ContentType), "application/json") {
		return nil, nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &doc); err != nil {
		return nil, nil
	}

	// Check if it's an OpenAPI/Swagger doc
	_, hasSwagger := doc["swagger"]
	_, hasOpenAPI := doc["openapi"]
	if !hasSwagger && !hasOpenAPI {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	pathsRaw, ok := doc["paths"]
	if !ok {
		return nil, nil
	}

	paths, ok := pathsRaw.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	for pathStr, methodsRaw := range paths {
		// Extract path template variables
		pvMatches := pathVarRegex.FindAllStringSubmatch(pathStr, -1)
		for _, pvm := range pvMatches {
			name := pvm[1]
			key := name + "|" + core.ParamLocationPath
			if !seen[key] {
				seen[key] = true
				params = append(params, core.Parameter{
					Name:     name,
					Location: core.ParamLocationPath,
				})
			}
		}

		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for _, opRaw := range methods {
			op, ok := opRaw.(map[string]interface{})
			if !ok {
				continue
			}
			paramsRaw, ok := op["parameters"]
			if !ok {
				continue
			}
			paramList, ok := paramsRaw.([]interface{})
			if !ok {
				continue
			}
			for _, pRaw := range paramList {
				p, ok := pRaw.(map[string]interface{})
				if !ok {
					continue
				}
				name, _ := p["name"].(string)
				in, _ := p["in"].(string)
				if name == "" || in == "" {
					continue
				}
				loc := o.mapLocation(in)
				key := name + "|" + loc
				if seen[key] {
					continue
				}
				seen[key] = true
				params = append(params, core.Parameter{
					Name:     name,
					Location: loc,
				})
			}
		}
	}

	if len(params) == 0 {
		return nil, nil
	}

	return params, nil
}

// mapLocation converts OpenAPI "in" values to core param locations.
func (o *OpenAPIDiscoverer) mapLocation(in string) string {
	switch in {
	case "query":
		return core.ParamLocationQuery
	case "path":
		return core.ParamLocationPath
	case "header":
		return core.ParamLocationHeader
	case "body":
		return core.ParamLocationBody
	case "cookie":
		return core.ParamLocationCookie
	default:
		return core.ParamLocationQuery
	}
}
