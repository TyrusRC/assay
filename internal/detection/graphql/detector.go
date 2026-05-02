// Package graphql provides GraphQL API vulnerability detection.
// It detects common GraphQL security issues including introspection exposure,
// batch query attacks, depth limit bypass, field suggestion exploitation,
// injection vulnerabilities, and authorization bypass.
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detector performs GraphQL vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool

	// Compiled regex patterns
	sqlErrorPatterns   []*regexp.Regexp
	nosqlErrorPatterns []*regexp.Regexp
	suggestionPattern  *regexp.Regexp
	depthErrorPatterns []*regexp.Regexp
}

// New creates a new GraphQL Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client: client,
	}
	d.initPatterns()
	return d
}

// initPatterns initializes compiled regex patterns.
func (d *Detector) initPatterns() {
	// SQL error patterns
	d.sqlErrorPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)you have an error in your sql syntax`),
		regexp.MustCompile(`(?i)mysql.*error`),
		regexp.MustCompile(`(?i)ERROR:\s*syntax error at or near`),
		regexp.MustCompile(`(?i)postgresql.*error`),
		regexp.MustCompile(`(?i)unclosed quotation mark`),
		regexp.MustCompile(`(?i)microsoft sql server`),
		regexp.MustCompile(`(?i)ORA-\d{5}`),
		regexp.MustCompile(`(?i)SQLITE_ERROR`),
		regexp.MustCompile(`(?i)sql\s*syntax.*error`),
	}

	// NoSQL error patterns
	d.nosqlErrorPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)unrecognized expression.*\$`),
		regexp.MustCompile(`(?i)mongodb.*error`),
		regexp.MustCompile(`(?i)cannot.*\$gt`),
		regexp.MustCompile(`(?i)cannot.*\$ne`),
		regexp.MustCompile(`(?i)cannot.*\$where`),
		regexp.MustCompile(`(?i)json\s*parse.*error.*\{`),
		regexp.MustCompile(`(?i)unexpected.*token.*\{`),
	}

	// Field suggestion pattern
	d.suggestionPattern = regexp.MustCompile(`(?i)did you mean ['"]?(\w+)['"]?(?:\s*or\s*['"]?(\w+)['"]?)?`)

	// Depth/complexity error patterns
	d.depthErrorPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)query.*exceed.*depth`),
		regexp.MustCompile(`(?i)max.*depth.*exceeded`),
		regexp.MustCompile(`(?i)query.*complexity.*exceed`),
		regexp.MustCompile(`(?i)too.*nested`),
		regexp.MustCompile(`(?i)depth.*limit`),
	}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "graphql"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "GraphQL API vulnerability detector for introspection, batch attacks, depth bypass, field suggestions, and injection"
}

// CommonEndpoints returns common GraphQL endpoint paths.
func CommonEndpoints() []string {
	return []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/v2/graphql",
		"/graphql/v1",
		"/graphql/api",
		"/query",
		"/api/query",
		"/gql",
		"/api/gql",
		"/graphiql",
		"/playground",
		"/api",
		"/graph",
	}
}

// IsGraphQLEndpoint checks if a response indicates a GraphQL endpoint.
func (d *Detector) IsGraphQLEndpoint(contentType, body string) bool {
	// Check content type
	if strings.Contains(contentType, "application/graphql") {
		return true
	}
	if strings.Contains(contentType, "graphql-response") {
		return true
	}

	// Must be JSON for further analysis
	if !strings.Contains(contentType, "application/json") && contentType != "" {
		return false
	}

	// Check for GraphQL response structure
	if body == "" {
		return false
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		return false
	}

	// GraphQL responses have "data" or "errors" fields
	if _, hasData := response["data"]; hasData {
		return true
	}
	if _, hasErrors := response["errors"]; hasErrors {
		// Check if errors look like GraphQL errors
		if errors, ok := response["errors"].([]interface{}); ok {
			for _, e := range errors {
				if errMap, ok := e.(map[string]interface{}); ok {
					if _, hasMessage := errMap["message"]; hasMessage {
						msg := fmt.Sprintf("%v", errMap["message"])
						if strings.Contains(msg, "query") ||
							strings.Contains(msg, "field") ||
							strings.Contains(msg, "Cannot") {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// Detect performs GraphQL vulnerability detection on a target URL.
func (d *Detector) Detect(ctx context.Context, targetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		IsGraphQL: false,
		Endpoint:  targetURL,
		Findings:  make([]*core.Finding, 0),
	}

	// Test introspection first - this also validates it's a GraphQL endpoint
	introspectionQuery := d.BuildIntrospectionQuery()
	body, err := d.BuildGraphQLRequest(introspectionQuery, nil)
	if err != nil {
		return result, fmt.Errorf("building introspection request: %w", err)
	}

	resp, err := d.client.PostJSON(ctx, targetURL, body)
	if err != nil {
		return result, fmt.Errorf("failed to send introspection query: %w", err)
	}

	// Check if this is a GraphQL endpoint
	if !d.IsGraphQLEndpoint(resp.ContentType, resp.Body) {
		return result, nil
	}
	result.IsGraphQL = true

	// Analyze introspection response
	introResult := d.AnalyzeIntrospectionResponse(resp.Body)
	if introResult.Enabled {
		result.IntrospectionOK = true
		result.SchemaTypes = introResult.Types

		finding := d.CreateFinding(
			VulnIntrospectionEnabled,
			targetURL,
			fmt.Sprintf("GraphQL introspection is enabled, exposing %d types", len(introResult.Types)),
			resp.Body,
		)
		finding.Confidence = core.ConfidenceConfirmed
		result.Findings = append(result.Findings, finding)
	}

	// Test batch queries
	if opts.TestBatchQueries {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		batchQueries := []string{
			`query { __typename }`,
			`query { __typename }`,
		}
		batchBody, err := d.BuildBatchQuery(batchQueries)
		if err != nil {
			return result, fmt.Errorf("building batch query: %w", err)
		}

		batchResp, err := d.client.PostJSON(ctx, targetURL, batchBody)
		if err == nil {
			batchResult := d.AnalyzeBatchResponse(batchResp.Body)
			if batchResult.Vulnerable {
				finding := d.CreateFinding(
					VulnBatchQueryAttack,
					targetURL,
					batchResult.Evidence,
					batchResp.Body,
				)
				finding.Confidence = core.ConfidenceConfirmed
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	// Test depth limit
	if opts.TestDepthLimit {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		deepQuery := d.BuildDeepQuery(opts.MaxDepth)
		deepBody, err := d.BuildGraphQLRequest(deepQuery, nil)
		if err != nil {
			return result, fmt.Errorf("building depth test request: %w", err)
		}

		deepResp, err := d.client.PostJSON(ctx, targetURL, deepBody)
		if err == nil {
			depthResult := d.AnalyzeDepthResponse(deepResp.Body, opts.MaxDepth)
			if depthResult.Vulnerable {
				finding := d.CreateFinding(
					VulnDepthLimitBypass,
					targetURL,
					depthResult.Evidence,
					deepResp.Body,
				)
				finding.Confidence = core.ConfidenceHigh
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	// Test field suggestion disclosure
	if opts.TestFieldSuggestion {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Query with intentionally misspelled field
		suggestionQuery := `query { user { usrname } }`
		suggestionBody, err := d.BuildGraphQLRequest(suggestionQuery, nil)
		if err != nil {
			return result, fmt.Errorf("building field suggestion request: %w", err)
		}

		suggestionResp, err := d.client.PostJSON(ctx, targetURL, suggestionBody)
		if err == nil {
			suggestionResult := d.AnalyzeFieldSuggestionResponse(suggestionResp.Body)
			if suggestionResult.HasSuggestions {
				finding := d.CreateFinding(
					VulnFieldSuggestion,
					targetURL,
					fmt.Sprintf("Field suggestions exposed: %v", suggestionResult.SuggestedFields),
					suggestionResp.Body,
				)
				finding.Confidence = core.ConfidenceConfirmed
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	// Test injection vulnerabilities
	if opts.TestInjection {
		payloads := d.GetInjectionPayloads()
		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			// Test injection in a common argument
			injectionQuery := fmt.Sprintf(`query { user(id: "%s") { id } }`, payload.Value)
			injectionBody, err := d.BuildGraphQLRequest(injectionQuery, nil)
			if err != nil {
				return result, fmt.Errorf("building injection test request: %w", err)
			}

			injectionResp, err := d.client.PostJSON(ctx, targetURL, injectionBody)
			if err == nil {
				injectionResult := d.AnalyzeInjectionResponse(injectionResp.Body)
				if injectionResult.Vulnerable {
					finding := d.CreateFinding(
						VulnInjectionInArgs,
						targetURL,
						fmt.Sprintf("%s injection detected: %s", injectionResult.InjectionType, payload.Description),
						injectionResp.Body,
					)
					finding.Confidence = core.ConfidenceHigh
					finding.Parameter = "id"
					finding.Metadata = map[string]interface{}{
						"payload":       payload.Value,
						"injectionType": string(injectionResult.InjectionType),
						"databaseType":  injectionResult.DatabaseType,
					}
					result.Findings = append(result.Findings, finding)
					break // Found injection, no need to test more payloads
				}
			}
		}
	}

	return result, nil
}

// DiscoverEndpoints discovers GraphQL endpoints at common paths.
func (d *Detector) DiscoverEndpoints(ctx context.Context, baseURL string) ([]string, error) {
	discovered := make([]string, 0)

	// Normalize base URL
	baseURL = strings.TrimSuffix(baseURL, "/")

	for _, endpoint := range CommonEndpoints() {
		select {
		case <-ctx.Done():
			return discovered, ctx.Err()
		default:
		}

		testURL := baseURL + endpoint

		// Send a simple introspection probe
		body, err := d.BuildGraphQLRequest(`query { __typename }`, nil)
		if err != nil {
			continue
		}
		resp, err := d.client.PostJSON(ctx, testURL, body)
		if err != nil {
			continue
		}

		if d.IsGraphQLEndpoint(resp.ContentType, resp.Body) {
			discovered = append(discovered, testURL)
		}
	}

	return discovered, nil
}
