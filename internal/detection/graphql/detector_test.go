package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// TestNewDetector tests the constructor.
func TestNewDetector(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

// TestDetector_Name tests the Name method.
func TestDetector_Name(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	if detector.Name() != "graphql" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "graphql")
	}
}

// TestDetector_Description tests the Description method.
func TestDetector_Description(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)
	desc := detector.Description()

	if desc == "" {
		t.Error("Description() should not be empty")
	}

	if !strings.Contains(desc, "GraphQL") {
		t.Error("Description() should mention GraphQL")
	}
}

// TestDefaultOptions tests default options initialization.
func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
	if opts.MaxDepth <= 0 {
		t.Error("DefaultOptions() MaxDepth should be positive")
	}
	if opts.MaxBatchSize <= 0 {
		t.Error("DefaultOptions() MaxBatchSize should be positive")
	}
}

// TestDetector_WithVerbose tests the WithVerbose builder.
func TestDetector_WithVerbose(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}
}

// TestVulnerabilityType_String tests string conversion.
func TestVulnerabilityType_String(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		want     string
	}{
		{VulnIntrospectionEnabled, "introspection-enabled"},
		{VulnBatchQueryAttack, "batch-query-attack"},
		{VulnDepthLimitBypass, "depth-limit-bypass"},
		{VulnFieldSuggestion, "field-suggestion-disclosure"},
		{VulnInjectionInArgs, "injection-in-arguments"},
		{VulnAuthorizationBypass, "authorization-bypass"},
		{VulnerabilityType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.vulnType.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCommonEndpoints tests that common endpoints are defined.
func TestCommonEndpoints(t *testing.T) {
	endpoints := CommonEndpoints()

	if len(endpoints) == 0 {
		t.Error("CommonEndpoints() should return at least one endpoint")
	}

	// Check for essential endpoints
	expected := []string{"/graphql", "/api/graphql", "/v1/graphql"}
	for _, ep := range expected {
		found := false
		for _, ce := range endpoints {
			if ce == ep {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CommonEndpoints() missing essential endpoint: %s", ep)
		}
	}
}

// TestDetector_IsGraphQLEndpoint tests GraphQL endpoint detection.
func TestDetector_IsGraphQLEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        bool
	}{
		{
			name:        "json response with data field",
			contentType: "application/json",
			body:        `{"data": {"__typename": "Query"}}`,
			want:        true,
		},
		{
			name:        "json response with errors field",
			contentType: "application/json",
			body:        `{"errors": [{"message": "Cannot query field"}]}`,
			want:        true,
		},
		{
			name:        "graphql content type",
			contentType: "application/graphql",
			body:        ``,
			want:        true,
		},
		{
			name:        "graphql-response content type",
			contentType: "application/graphql-response+json",
			body:        `{"data": null}`,
			want:        true,
		},
		{
			name:        "html page",
			contentType: "text/html",
			body:        `<html><body>Hello</body></html>`,
			want:        false,
		},
		{
			name:        "plain json without graphql structure",
			contentType: "application/json",
			body:        `{"name": "test", "value": 123}`,
			want:        false,
		},
		{
			name:        "empty response",
			contentType: "",
			body:        "",
			want:        false,
		},
	}

	client := skhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.IsGraphQLEndpoint(tt.contentType, tt.body)
			if got != tt.want {
				t.Errorf("IsGraphQLEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDetector_BuildIntrospectionQuery tests introspection query building.
func TestDetector_BuildIntrospectionQuery(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	query := detector.BuildIntrospectionQuery()

	if query == "" {
		t.Error("BuildIntrospectionQuery() should not return empty string")
	}

	if !strings.Contains(query, "__schema") {
		t.Error("BuildIntrospectionQuery() should contain __schema")
	}

	if !strings.Contains(query, "types") {
		t.Error("BuildIntrospectionQuery() should query types")
	}
}

// TestDetector_BuildTypeQuery tests type query building.
func TestDetector_BuildTypeQuery(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	query := detector.BuildTypeQuery("User")

	if query == "" {
		t.Error("BuildTypeQuery() should not return empty string")
	}

	if !strings.Contains(query, "__type") {
		t.Error("BuildTypeQuery() should contain __type")
	}

	if !strings.Contains(query, "User") {
		t.Error("BuildTypeQuery() should contain the type name")
	}
}

// TestDetector_BuildBatchQuery tests batch query building.
func TestDetector_BuildBatchQuery(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	queries := []string{
		`query { user(id: 1) { name } }`,
		`query { user(id: 2) { name } }`,
		`query { user(id: 3) { name } }`,
	}

	batch, err := detector.BuildBatchQuery(queries)
	if err != nil {
		t.Fatalf("BuildBatchQuery() unexpected error: %v", err)
	}

	if batch == "" {
		t.Error("BuildBatchQuery() should not return empty string")
	}

	// Should be a JSON array
	var parsed []interface{}
	if err := json.Unmarshal([]byte(batch), &parsed); err != nil {
		t.Errorf("BuildBatchQuery() should return valid JSON array: %v", err)
	}

	if len(parsed) != 3 {
		t.Errorf("BuildBatchQuery() returned %d items, want 3", len(parsed))
	}
}

// TestDetector_BuildAliasBatchQuery tests alias-based batch query building.
func TestDetector_BuildAliasBatchQuery(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	query := detector.BuildAliasBatchQuery("user", "id", []string{"1", "2", "3"})

	if query == "" {
		t.Error("BuildAliasBatchQuery() should not return empty string")
	}

	// Should contain aliases
	if !strings.Contains(query, "q0:") && !strings.Contains(query, "alias0:") {
		t.Error("BuildAliasBatchQuery() should contain query aliases")
	}
}

// TestDetector_BuildDeepQuery tests deep query building.
func TestDetector_BuildDeepQuery(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	tests := []struct {
		depth        int
		expectedNest int
	}{
		{1, 1},
		{5, 5},
		{10, 10},
		{100, 100},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			query := detector.BuildDeepQuery(tt.depth)

			if query == "" {
				t.Error("BuildDeepQuery() should not return empty string")
			}

			// Count nesting by counting opening braces
			braceCount := strings.Count(query, "{")
			// Account for the outer query structure
			if braceCount < tt.expectedNest {
				t.Errorf("BuildDeepQuery(%d) has %d nesting levels, want at least %d",
					tt.depth, braceCount, tt.expectedNest)
			}
		})
	}
}

// TestDetector_GetInjectionPayloads tests injection payload retrieval.
func TestDetector_GetInjectionPayloads(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	payloads := detector.GetInjectionPayloads()

	if len(payloads) == 0 {
		t.Error("GetInjectionPayloads() should return at least one payload")
	}

	// Check for basic SQL injection payloads
	hasSQLi := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "'") || strings.Contains(p.Value, "OR") {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Error("GetInjectionPayloads() should include SQL injection payloads")
	}

	// Check for NoSQL injection payloads
	hasNoSQLi := false
	for _, p := range payloads {
		if strings.Contains(p.Value, "$") || strings.Contains(p.Value, "{") {
			hasNoSQLi = true
			break
		}
	}
	if !hasNoSQLi {
		t.Error("GetInjectionPayloads() should include NoSQL injection payloads")
	}
}

// TestDetector_AnalyzeIntrospectionResponse tests introspection response analysis.
func TestDetector_AnalyzeIntrospectionResponse(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		response string
		enabled  bool
	}{
		{
			name: "full introspection enabled",
			response: `{
				"data": {
					"__schema": {
						"types": [
							{"name": "Query"},
							{"name": "User"},
							{"name": "Mutation"}
						]
					}
				}
			}`,
			enabled: true,
		},
		{
			name: "introspection disabled",
			response: `{
				"errors": [
					{"message": "Introspection is disabled"}
				]
			}`,
			enabled: false,
		},
		{
			name: "partial schema with queryType",
			response: `{
				"data": {
					"__schema": {
						"queryType": {"name": "Query"}
					}
				}
			}`,
			enabled: true,
		},
		{
			name:     "empty response",
			response: `{}`,
			enabled:  false,
		},
		{
			name:     "invalid json",
			response: `not json`,
			enabled:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeIntrospectionResponse(tt.response)
			if result.Enabled != tt.enabled {
				t.Errorf("AnalyzeIntrospectionResponse() enabled = %v, want %v",
					result.Enabled, tt.enabled)
			}
		})
	}
}

// TestDetector_AnalyzeBatchResponse tests batch response analysis.
func TestDetector_AnalyzeBatchResponse(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name       string
		response   string
		vulnerable bool
	}{
		{
			name: "batch queries accepted",
			response: `[
				{"data": {"user": {"id": "1"}}},
				{"data": {"user": {"id": "2"}}},
				{"data": {"user": {"id": "3"}}}
			]`,
			vulnerable: true,
		},
		{
			name:       "batch queries rejected",
			response:   `{"errors": [{"message": "Batch queries not allowed"}]}`,
			vulnerable: false,
		},
		{
			name:       "single response",
			response:   `{"data": {"user": {"id": "1"}}}`,
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeBatchResponse(tt.response)
			if result.Vulnerable != tt.vulnerable {
				t.Errorf("AnalyzeBatchResponse() vulnerable = %v, want %v",
					result.Vulnerable, tt.vulnerable)
			}
		})
	}
}

// TestDetector_AnalyzeDepthResponse tests depth limit bypass detection.
func TestDetector_AnalyzeDepthResponse(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name       string
		response   string
		depth      int
		vulnerable bool
	}{
		{
			name:       "deep query accepted",
			response:   `{"data": {"user": {"posts": {"comments": {"author": {"name": "test"}}}}}}`,
			depth:      10,
			vulnerable: true,
		},
		{
			name:       "depth limit enforced",
			response:   `{"errors": [{"message": "Query exceeds maximum depth"}]}`,
			depth:      10,
			vulnerable: false,
		},
		{
			name:       "complexity error",
			response:   `{"errors": [{"message": "Query complexity exceeds limit"}]}`,
			depth:      10,
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeDepthResponse(tt.response, tt.depth)
			if result.Vulnerable != tt.vulnerable {
				t.Errorf("AnalyzeDepthResponse() vulnerable = %v, want %v",
					result.Vulnerable, tt.vulnerable)
			}
		})
	}
}

// TestDetector_AnalyzeFieldSuggestionResponse tests field suggestion detection.
func TestDetector_AnalyzeFieldSuggestionResponse(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name            string
		response        string
		hasSuggestions  bool
		suggestedFields []string
	}{
		{
			name: "field suggestions present",
			response: `{
				"errors": [{
					"message": "Cannot query field 'usrname' on type 'User'. Did you mean 'username' or 'user_name'?"
				}]
			}`,
			hasSuggestions:  true,
			suggestedFields: []string{"username", "user_name"},
		},
		{
			name: "no suggestions",
			response: `{
				"errors": [{
					"message": "Cannot query field 'xyz' on type 'User'"
				}]
			}`,
			hasSuggestions:  false,
			suggestedFields: nil,
		},
		{
			name:            "successful response",
			response:        `{"data": {"user": {"name": "test"}}}`,
			hasSuggestions:  false,
			suggestedFields: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeFieldSuggestionResponse(tt.response)
			if result.HasSuggestions != tt.hasSuggestions {
				t.Errorf("AnalyzeFieldSuggestionResponse() hasSuggestions = %v, want %v",
					result.HasSuggestions, tt.hasSuggestions)
			}
			if tt.hasSuggestions && len(result.SuggestedFields) == 0 {
				t.Error("AnalyzeFieldSuggestionResponse() should extract suggested fields")
			}
		})
	}
}

// TestDetector_AnalyzeInjectionResponse tests injection detection in responses.
func TestDetector_AnalyzeInjectionResponse(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name       string
		response   string
		vulnerable bool
	}{
		{
			name:       "SQL error in response",
			response:   `{"errors": [{"message": "You have an error in your SQL syntax"}]}`,
			vulnerable: true,
		},
		{
			name:       "MongoDB error",
			response:   `{"errors": [{"message": "Unrecognized expression '$gt'"}]}`,
			vulnerable: true,
		},
		{
			name:       "normal error",
			response:   `{"errors": [{"message": "User not found"}]}`,
			vulnerable: false,
		},
		{
			name:       "successful response",
			response:   `{"data": {"user": {"name": "test"}}}`,
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeInjectionResponse(tt.response)
			if result.Vulnerable != tt.vulnerable {
				t.Errorf("AnalyzeInjectionResponse() vulnerable = %v, want %v",
					result.Vulnerable, tt.vulnerable)
			}
		})
	}
}

// TestDetector_CreateFinding tests finding creation.
func TestDetector_CreateFinding(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	finding := detector.CreateFinding(
		VulnIntrospectionEnabled,
		"https://example.com/graphql",
		"Full schema exposed via introspection",
		`{"data": {"__schema": {}}}`,
	)

	if finding == nil {
		t.Fatal("CreateFinding() returned nil")
	}

	if finding.URL != "https://example.com/graphql" {
		t.Errorf("CreateFinding() URL = %q, want %q", finding.URL, "https://example.com/graphql")
	}

	if finding.Type != "GraphQL Introspection Enabled" {
		t.Errorf("CreateFinding() Type = %q, unexpected", finding.Type)
	}

	if len(finding.APITop10) == 0 {
		t.Error("CreateFinding() should have API Top 10 mapping")
	}

	if len(finding.CWE) == 0 {
		t.Error("CreateFinding() should have CWE mapping")
	}

	if finding.Remediation == "" {
		t.Error("CreateFinding() should have remediation")
	}
}

// TestDetector_CreateFinding_AllTypes tests finding creation for all vulnerability types.
func TestDetector_CreateFinding_AllTypes(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	vulnTypes := []VulnerabilityType{
		VulnIntrospectionEnabled,
		VulnBatchQueryAttack,
		VulnDepthLimitBypass,
		VulnFieldSuggestion,
		VulnInjectionInArgs,
		VulnAuthorizationBypass,
	}

	for _, vt := range vulnTypes {
		t.Run(vt.String(), func(t *testing.T) {
			finding := detector.CreateFinding(vt, "https://example.com/graphql", "test", "{}")

			if finding == nil {
				t.Fatal("CreateFinding() returned nil")
			}

			if finding.Severity == "" {
				t.Error("CreateFinding() should set severity")
			}

			if !finding.Severity.IsValid() {
				t.Errorf("CreateFinding() severity %q is not valid", finding.Severity)
			}
		})
	}
}

// TestDetector_Detect_IntrospectionEnabled tests introspection detection with mock server.
func TestDetector_Detect_IntrospectionEnabled(t *testing.T) {
	// Create a mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return introspection result
		response := `{
			"data": {
				"__schema": {
					"queryType": {"name": "Query"},
					"types": [
						{"name": "Query"},
						{"name": "User"},
						{"name": "Post"}
					]
				}
			}
		}`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if !result.IsGraphQL {
		t.Error("Detect() should identify GraphQL endpoint")
	}

	// Should find introspection vulnerability
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Type, "Introspection") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Detect() should find introspection enabled vulnerability")
	}
}

// TestDetector_Detect_BatchQueryVulnerable tests batch query detection.
func TestDetector_Detect_BatchQueryVulnerable(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")

		// Read body to check for batch query
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		bodyStr := string(body[:n])

		// If batch query (starts with '['), return batch response
		if strings.HasPrefix(strings.TrimSpace(bodyStr), "[") {
			response := `[
				{"data": {"user": {"id": "1"}}},
				{"data": {"user": {"id": "2"}}}
			]`
			w.Write([]byte(response))
			return
		}

		// Regular response
		w.Write([]byte(`{"data": {"__schema": {"queryType": {"name": "Query"}}}}`))
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()
	opts.TestBatchQueries = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should find batch query vulnerability
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Type, "Batch") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Detect() should find batch query vulnerability")
	}
}

// TestDetector_Detect_DepthLimitBypass tests depth limit bypass detection.
func TestDetector_Detect_DepthLimitBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Accept deep queries without error
		response := `{"data": {"user": {"posts": {"comments": {"author": {"posts": {"title": "test"}}}}}}}`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()
	opts.TestDepthLimit = true
	opts.MaxDepth = 10

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should find depth limit bypass vulnerability
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Type, "Depth") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Detect() should find depth limit bypass vulnerability")
	}
}

// TestDetector_Detect_FieldSuggestion tests field suggestion detection.
func TestDetector_Detect_FieldSuggestion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		bodyStr := string(body[:n])

		// Check for misspelled field
		if strings.Contains(bodyStr, "usrname") {
			response := `{
				"errors": [{
					"message": "Cannot query field 'usrname' on type 'User'. Did you mean 'username'?"
				}]
			}`
			w.Write([]byte(response))
			return
		}

		// Default introspection response
		w.Write([]byte(`{"data": {"__schema": {"queryType": {"name": "Query"}}}}`))
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()
	opts.TestFieldSuggestion = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should find field suggestion vulnerability
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Type, "Field Suggestion") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Detect() should find field suggestion disclosure vulnerability")
	}
}

// TestDetector_Detect_InjectionVulnerable tests injection detection.
func TestDetector_Detect_InjectionVulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		bodyStr := string(body[:n])

		// Check for SQL injection payload
		if strings.Contains(bodyStr, "'") && strings.Contains(bodyStr, "OR") {
			response := `{
				"errors": [{
					"message": "You have an error in your SQL syntax; check the manual"
				}]
			}`
			w.Write([]byte(response))
			return
		}

		// Default response
		w.Write([]byte(`{"data": {"__schema": {"queryType": {"name": "Query"}}}}`))
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()
	opts.TestInjection = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should find injection vulnerability
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Type, "Injection") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Detect() should find injection vulnerability")
	}
}

// TestDetector_Detect_NonGraphQLEndpoint tests handling of non-GraphQL endpoints.
func TestDetector_Detect_NonGraphQLEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Not a GraphQL endpoint</body></html>"))
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.IsGraphQL {
		t.Error("Detect() should not identify non-GraphQL endpoint as GraphQL")
	}
}

// TestDetector_Detect_ContextCancellation tests context cancellation handling.
func TestDetector_Detect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Simulate slow server
		w.Write([]byte(`{"data": {}}`))
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(ctx, server.URL, opts)
	if err == nil {
		t.Error("Detect() should return error on context cancellation")
	}
}

// TestDetector_DiscoverEndpoints tests endpoint discovery.
func TestDetector_DiscoverEndpoints(t *testing.T) {
	// Create server that responds to /graphql only
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data": {"__typename": "Query"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := skhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoints, err := detector.DiscoverEndpoints(ctx, server.URL)
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}

	found := false
	for _, ep := range endpoints {
		if strings.Contains(ep, "/graphql") {
			found = true
			break
		}
	}
	if !found {
		t.Error("DiscoverEndpoints() should find /graphql endpoint")
	}
}

// TestDetectionResult_HasVulnerabilities tests vulnerability checking.
func TestDetectionResult_HasVulnerabilities(t *testing.T) {
	tests := []struct {
		name     string
		findings []*core.Finding
		want     bool
	}{
		{
			name:     "no findings",
			findings: nil,
			want:     false,
		},
		{
			name:     "empty findings",
			findings: []*core.Finding{},
			want:     false,
		},
		{
			name: "has findings",
			findings: []*core.Finding{
				core.NewFinding("test", core.SeverityHigh),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DetectionResult{Findings: tt.findings}
			if got := result.HasVulnerabilities(); got != tt.want {
				t.Errorf("HasVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIntrospectionResult_ExtractedTypes tests type extraction from introspection.
func TestIntrospectionResult_ExtractedTypes(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	response := `{
		"data": {
			"__schema": {
				"types": [
					{"name": "Query"},
					{"name": "User"},
					{"name": "Post"},
					{"name": "__Schema"},
					{"name": "__Type"}
				]
			}
		}
	}`

	result := detector.AnalyzeIntrospectionResponse(response)

	if !result.Enabled {
		t.Fatal("AnalyzeIntrospectionResponse() should detect enabled introspection")
	}

	// Should extract user-defined types (excluding __ prefixed types)
	expectedTypes := []string{"Query", "User", "Post"}
	for _, et := range expectedTypes {
		found := false
		for _, at := range result.Types {
			if at == et {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AnalyzeIntrospectionResponse() should extract type %q", et)
		}
	}

	// Should not include internal types
	for _, at := range result.Types {
		if strings.HasPrefix(at, "__") {
			t.Errorf("AnalyzeIntrospectionResponse() should not include internal type %q", at)
		}
	}
}

// TestInjectionPayload_Types tests injection payload categorization.
func TestInjectionPayload_Types(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	payloads := detector.GetInjectionPayloads()

	hasSQLi := false
	hasNoSQLi := false

	for _, p := range payloads {
		switch p.Type {
		case InjectionTypeSQL:
			hasSQLi = true
		case InjectionTypeNoSQL:
			hasNoSQLi = true
		}
	}

	if !hasSQLi {
		t.Error("GetInjectionPayloads() should include SQL injection payloads")
	}
	if !hasNoSQLi {
		t.Error("GetInjectionPayloads() should include NoSQL injection payloads")
	}
}

// TestDetector_BuildGraphQLRequest tests GraphQL request building.
func TestDetector_BuildGraphQLRequest(t *testing.T) {
	client := skhttp.NewClient()
	detector := New(client)

	query := `query { user(id: "1") { name } }`
	variables := map[string]interface{}{"id": "1"}

	body, err := detector.BuildGraphQLRequest(query, variables)
	if err != nil {
		t.Fatalf("BuildGraphQLRequest() unexpected error: %v", err)
	}

	if body == "" {
		t.Error("BuildGraphQLRequest() should not return empty string")
	}

	// Parse and validate JSON structure
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Errorf("BuildGraphQLRequest() should return valid JSON: %v", err)
	}

	if _, ok := parsed["query"]; !ok {
		t.Error("BuildGraphQLRequest() should include 'query' field")
	}

	if _, ok := parsed["variables"]; !ok {
		t.Error("BuildGraphQLRequest() should include 'variables' field")
	}
}

// TestOWASPMapping tests OWASP API Security mapping.
func TestOWASPMapping(t *testing.T) {
	tests := []struct {
		vulnType    VulnerabilityType
		expectedAPI string // OWASP API Top 10 mapping
	}{
		{VulnIntrospectionEnabled, "API3"}, // Excessive Data Exposure
		{VulnBatchQueryAttack, "API4"},     // Lack of Resources & Rate Limiting
		{VulnDepthLimitBypass, "API4"},     // Lack of Resources & Rate Limiting
		{VulnFieldSuggestion, "API3"},      // Excessive Data Exposure
		{VulnInjectionInArgs, "API8"},      // Injection
		{VulnAuthorizationBypass, "API1"},  // Broken Object Level Authorization
	}

	client := skhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.vulnType.String(), func(t *testing.T) {
			finding := detector.CreateFinding(tt.vulnType, "https://example.com", "test", "{}")

			found := false
			for _, api := range finding.APITop10 {
				if strings.Contains(api, tt.expectedAPI) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("CreateFinding(%v) should map to OWASP API %s, got %v",
					tt.vulnType, tt.expectedAPI, finding.APITop10)
			}
		})
	}
}
