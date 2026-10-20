package discovery

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
	"gopkg.in/yaml.v3"
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
	"/openapi.json", "/openapi.yaml", "/openapi.yml",
	"/swagger.json", "/swagger.yaml", "/swagger.yml",
	"/v3/api-docs", "/api-docs",
	"/swagger/v1/swagger.json", "/openapi/v3",
	"/api/swagger.json", "/api/openapi.json",
}

// Discover extracts parameters from OpenAPI/Swagger specifications. It first
// parses the response it was handed (the scanned URL may be a spec), then, with
// a client set, fetches each conventional spec path at the host root.
func (o *OpenAPIDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	baseHost, _ := hostRootURL(targetURL, "")
	if resp != nil {
		if params := o.parseBody(resp.Body, baseHost); len(params) > 0 {
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
		if params := o.parseBody(rr.Body, baseHost); len(params) > 0 {
			return params, nil
		}
	}
	return nil, nil
}

// parseBody parses an OpenAPI/Swagger document (JSON or YAML) into parameters.
// baseHost is scheme://host used to build SourceURL for each parameter.
// It returns nil when body is not a spec.
func (o *OpenAPIDiscoverer) parseBody(body, baseHost string) []core.Parameter {
	if strings.TrimSpace(body) == "" {
		return nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		// JSON failed — try YAML. Many API specs (including vAPI) serve
		// YAML at /openapi.yaml; without this path the discoverer silently
		// returns nil and the entire injection phase is skipped.
		if yamlErr := yaml.Unmarshal([]byte(body), &doc); yamlErr != nil {
			return nil
		}
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

	// Resolve base URL: prefer the spec's servers[0].url, fall back to baseHost.
	specBase := baseHost
	if serversRaw, ok := doc["servers"]; ok {
		if servers, ok := serversRaw.([]interface{}); ok && len(servers) > 0 {
			if srv, ok := servers[0].(map[string]interface{}); ok {
				if sURL, ok := srv["url"].(string); ok && sURL != "" && strings.HasPrefix(sURL, "http") {
					specBase = strings.TrimRight(sURL, "/")
				}
			}
		}
	}

	for pathStr, methodsRaw := range paths {
		// Build the concrete endpoint URL for this path. Replace {var}
		// with a placeholder so the URL is valid for requests.
		concretePath := pathVarRegex.ReplaceAllString(pathStr, "test")
		endpointURL := specBase + concretePath

		// Extract path template variables — each gets a SegmentIndex.
		pvMatches := pathVarRegex.FindAllStringSubmatch(pathStr, -1)
		segments := strings.Split(strings.TrimLeft(pathStr, "/"), "/")
		for _, pvm := range pvMatches {
			name := pvm[1]
			key := name + "|" + core.ParamLocationPath + "|" + pathStr
			if !seen[key] {
				seen[key] = true
				segIdx := 0
				for i, seg := range segments {
					if seg == "{"+name+"}" {
						segIdx = i
						break
					}
				}
				params = append(params, core.Parameter{
					Name:         name,
					Location:     core.ParamLocationPath,
					SourceURL:    endpointURL,
					SegmentIndex: segIdx,
				})
			}
		}

		methods, ok := methodsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for methodName, opRaw := range methods {
			op, ok := opRaw.(map[string]interface{})
			if !ok {
				continue
			}
			httpMethod := strings.ToUpper(methodName)

			// Extract from "parameters" array (query, header, path, cookie)
			if paramsRaw, ok := op["parameters"]; ok {
				if paramList, ok := paramsRaw.([]interface{}); ok {
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
						key := name + "|" + loc + "|" + pathStr
						if seen[key] {
							continue
						}
						seen[key] = true
						params = append(params, core.Parameter{
							Name:      name,
							Location:  loc,
							SourceURL: endpointURL,
							Method:    httpMethod,
						})
					}
				}
			}

			// Extract from "requestBody" (OpenAPI 3.x body parameters).
			o.extractRequestBodyParams(op, seen, &params, endpointURL, httpMethod, pathStr)
		}
	}

	if len(params) == 0 {
		return nil
	}

	return params
}

// extractRequestBodyParams walks requestBody.content.*.schema.properties and
// adds each property name as a body parameter. This covers OpenAPI 3.x specs
// where parameters live in requestBody rather than the parameters array.
func (o *OpenAPIDiscoverer) extractRequestBodyParams(
	op map[string]interface{}, seen map[string]bool, params *[]core.Parameter,
	endpointURL, httpMethod, pathStr string,
) {
	rbRaw, ok := op["requestBody"]
	if !ok {
		return
	}
	rb, ok := rbRaw.(map[string]interface{})
	if !ok {
		return
	}
	contentRaw, ok := rb["content"]
	if !ok {
		return
	}
	content, ok := contentRaw.(map[string]interface{})
	if !ok {
		return
	}
	for mediaType, mediaRaw := range content {
		media, ok := mediaRaw.(map[string]interface{})
		if !ok {
			continue
		}
		schemaRaw, ok := media["schema"]
		if !ok {
			continue
		}
		schema, ok := schemaRaw.(map[string]interface{})
		if !ok {
			continue
		}
		propsRaw, ok := schema["properties"]
		if !ok {
			continue
		}
		props, ok := propsRaw.(map[string]interface{})
		if !ok {
			continue
		}
		// mediaType is the content-type key (e.g., "application/json",
		// "application/xml"). Propagate it to the parameter so
		// SendPayloadAt dispatches to JSON/XML body injection.
		ct := mediaType
		for name := range props {
			key := name + "|" + core.ParamLocationBody + "|" + pathStr
			if seen[key] {
				continue
			}
			seen[key] = true
			*params = append(*params, core.Parameter{
				Name:        name,
				Location:    core.ParamLocationBody,
				ContentType: ct,
				SourceURL:   endpointURL,
				Method:      httpMethod,
			})
		}
	}
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
