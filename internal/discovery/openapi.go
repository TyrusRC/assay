package discovery

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// OpenAPIDiscoverer extracts parameters from OpenAPI/Swagger JSON specs.
type OpenAPIDiscoverer struct{ client *http.Client }

// NewOpenAPIDiscoverer creates a new OpenAPIDiscoverer.
func NewOpenAPIDiscoverer() *OpenAPIDiscoverer {
	return &OpenAPIDiscoverer{}
}

// WithClient lets the discoverer fetch the spec from its conventional locations
// itself, instead of only parsing the scanned URL's response. The client carries
// the scan's scope and rate limit.
func (o *OpenAPIDiscoverer) WithClient(c *http.Client) *OpenAPIDiscoverer {
	o.client = c
	return o
}

// Name returns the discoverer identifier.
func (o *OpenAPIDiscoverer) Name() string {
	return "openapi"
}

var pathVarRegex = regexp.MustCompile(`\{(\w+)\}`)

// commonSpecPaths are the conventional locations of an OpenAPI/Swagger document.
var commonSpecPaths = []string{
	"/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
	"/swagger/v1/swagger.json", "/openapi/v3",
}

// Discover extracts parameters from OpenAPI/Swagger specifications. It first
// parses the response it was handed (the scanned URL may be a spec), then, with
// a client set, fetches each conventional spec path at the host root.
func (o *OpenAPIDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	if resp != nil {
		if params := o.parseBody(resp.Body); len(params) > 0 {
			return params, nil
		}
	}
	if o.client == nil {
		return nil, nil
	}
	for _, sp := range commonSpecPaths {
		specURL, ok := hostRootURL(targetURL, sp)
		if !ok {
			break
		}
		rr, err := o.client.Get(ctx, specURL)
		if err != nil || rr == nil {
			continue
		}
		if params := o.parseBody(rr.Body); len(params) > 0 {
			return params, nil
		}
	}
	return nil, nil
}

// parseBody parses an OpenAPI/Swagger JSON document into parameters. It returns
// nil when body is not a spec.
func (o *OpenAPIDiscoverer) parseBody(body string) []core.Parameter {
	if strings.TrimSpace(body) == "" {
		return nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil
	}

	// Check if it's an OpenAPI/Swagger doc
	_, hasSwagger := doc["swagger"]
	_, hasOpenAPI := doc["openapi"]
	if !hasSwagger && !hasOpenAPI {
		return nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	pathsRaw, ok := doc["paths"]
	if !ok {
		return nil
	}

	paths, ok := pathsRaw.(map[string]interface{})
	if !ok {
		return nil
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
		return nil
	}

	return params
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
