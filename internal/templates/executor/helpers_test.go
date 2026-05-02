package executor

import (
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
)

func TestBuildVariables_BaseURLIncludesPath(t *testing.T) {
	exec := New(nil)

	tests := []struct {
		name        string
		targetURL   string
		wantBaseURL string
		wantRootURL string
		wantFQDN    string
	}{
		{
			name:        "URL with path",
			targetURL:   "https://example.com/admin/login",
			wantBaseURL: "https://example.com/admin/login",
			wantRootURL: "https://example.com",
			wantFQDN:    "example.com",
		},
		{
			name:        "URL without path",
			targetURL:   "https://example.com",
			wantBaseURL: "https://example.com",
			wantRootURL: "https://example.com",
			wantFQDN:    "example.com",
		},
		{
			name:        "URL with port and path",
			targetURL:   "http://example.com:8080/api/v1",
			wantBaseURL: "http://example.com:8080/api/v1",
			wantRootURL: "http://example.com:8080",
			wantFQDN:    "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &templates.Template{}
			vars := exec.buildVariables(tmpl, tt.targetURL)

			baseURL, ok := vars["BaseURL"].(string)
			if !ok {
				t.Fatal("BaseURL not found or not a string")
			}
			if baseURL != tt.wantBaseURL {
				t.Errorf("BaseURL = %q, want %q", baseURL, tt.wantBaseURL)
			}

			rootURL, ok := vars["RootURL"].(string)
			if !ok {
				t.Fatal("RootURL not found or not a string")
			}
			if rootURL != tt.wantRootURL {
				t.Errorf("RootURL = %q, want %q", rootURL, tt.wantRootURL)
			}

			fqdn, ok := vars["FQDN"].(string)
			if !ok {
				t.Fatal("FQDN not found or not a string")
			}
			if fqdn != tt.wantFQDN {
				t.Errorf("FQDN = %q, want %q", fqdn, tt.wantFQDN)
			}
		})
	}
}

func TestBuildURL(t *testing.T) {
	exec := New(nil)

	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"http://example.com", "/test", "http://example.com/test"},
		{"http://example.com/", "/test", "http://example.com/test"},
		{"http://example.com", "{{BaseURL}}/test", "http://example.com/test"},
		{"https://example.com:8080", "/api/v1", "https://example.com:8080/api/v1"},
	}

	for _, tt := range tests {
		result := exec.buildURL(tt.base, tt.path)
		if result != tt.expected {
			t.Errorf("buildURL(%q, %q) = %q, want %q", tt.base, tt.path, result, tt.expected)
		}
	}
}

func TestInterpolate(t *testing.T) {
	exec := New(nil)

	vars := map[string]interface{}{
		"Host":   "example.com",
		"Port":   8080,
		"Scheme": "https",
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"{{Host}}", "example.com"},
		{"{{Scheme}}://{{Host}}:{{Port}}", "https://example.com:8080"},
		{"no vars here", "no vars here"},
	}

	for _, tt := range tests {
		result := exec.interpolate(tt.input, vars)
		if result != tt.expected {
			t.Errorf("interpolate(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseRawRequest(t *testing.T) {
	raw := `GET /api/users HTTP/1.1
Host: example.com
Accept: application/json

{"query": "test"}`

	method, path, body, headers := parseRawRequest(raw)

	if method != "GET" {
		t.Errorf("method = %q, want GET", method)
	}
	if path != "/api/users" {
		t.Errorf("path = %q, want /api/users", path)
	}
	if headers["Host"] != "example.com" {
		t.Errorf("Host header = %q, want example.com", headers["Host"])
	}
	if body != `{"query": "test"}` {
		t.Errorf("body = %q, want {\"query\": \"test\"}", body)
	}
}

func TestApplyFuzzType(t *testing.T) {
	tests := []struct {
		original string
		payload  string
		fuzzType string
		expected string
	}{
		{"value", "payload", "replace", "payload"},
		{"value", "pre-", "prefix", "pre-value"},
		{"value", "-post", "postfix", "value-post"},
		{"value", "default", "", "default"},
	}

	for _, tt := range tests {
		result := applyFuzzType(tt.original, tt.payload, tt.fuzzType)
		if result != tt.expected {
			t.Errorf("applyFuzzType(%q, %q, %q) = %q, want %q",
				tt.original, tt.payload, tt.fuzzType, result, tt.expected)
		}
	}
}

// TestRunExtractors_InternalExtractorStoresInVars verifies that internal extractors
// store their extracted values into the vars map instead of the result map.
func TestRunExtractors_InternalExtractorStoresInVars(t *testing.T) {
	exec := New(nil)

	resp := &matchers.Response{
		Body: `{"token": "abc123", "user": "alice"}`,
		Headers: map[string]string{
			"X-Session": "sess-xyz",
		},
	}

	tests := []struct {
		name         string
		extractors   []templates.Extractor
		initialVars  map[string]interface{}
		wantVarsKey  string
		wantVarsVal  string
		wantInResult bool
		resultKey    string
	}{
		{
			name: "internal json extractor stores token in vars",
			extractors: []templates.Extractor{
				{
					Type:     "json",
					Name:     "token",
					JSON:     []string{"token"},
					Internal: true,
				},
			},
			initialVars:  map[string]interface{}{},
			wantVarsKey:  "token",
			wantVarsVal:  "abc123",
			wantInResult: false,
			resultKey:    "token",
		},
		{
			name: "non-internal json extractor goes to result only",
			extractors: []templates.Extractor{
				{
					Type:     "json",
					Name:     "user",
					JSON:     []string{"user"},
					Internal: false,
				},
			},
			initialVars:  map[string]interface{}{},
			wantVarsKey:  "user",
			wantVarsVal:  "",
			wantInResult: true,
			resultKey:    "user",
		},
		{
			name: "internal kval extractor stores header value in vars",
			extractors: []templates.Extractor{
				{
					Type:     "kval",
					Name:     "session",
					KVal:     []string{"X-Session"},
					Internal: true,
				},
			},
			initialVars:  map[string]interface{}{},
			wantVarsKey:  "session",
			wantVarsVal:  "sess-xyz",
			wantInResult: false,
			resultKey:    "session",
		},
		{
			name: "internal regex extractor stores match in vars",
			extractors: []templates.Extractor{
				{
					Type:     "regex",
					Name:     "extracted_user",
					Regex:    []string{`"user":\s*"(\w+)"`},
					Group:    1,
					Internal: true,
				},
			},
			initialVars:  map[string]interface{}{},
			wantVarsKey:  "extracted_user",
			wantVarsVal:  "alice",
			wantInResult: false,
			resultKey:    "extracted_user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := make(map[string]interface{})
			for k, v := range tt.initialVars {
				vars[k] = v
			}

			result := exec.runExtractors(tt.extractors, resp, vars)

			if tt.wantInResult {
				if _, ok := result[tt.resultKey]; !ok {
					t.Errorf("expected result[%q] to exist, but it does not", tt.resultKey)
				}
				if val, ok := vars[tt.wantVarsKey]; ok && tt.wantVarsVal == "" {
					t.Errorf("non-internal extractor should not write to vars, but vars[%q] = %v", tt.wantVarsKey, val)
				}
			} else {
				if _, ok := result[tt.resultKey]; ok {
					t.Errorf("internal extractor should not appear in result map, but result[%q] exists", tt.resultKey)
				}
				val, ok := vars[tt.wantVarsKey]
				if !ok {
					t.Errorf("internal extractor should set vars[%q], but it was not found", tt.wantVarsKey)
					return
				}
				if val != tt.wantVarsVal {
					t.Errorf("vars[%q] = %q, want %q", tt.wantVarsKey, val, tt.wantVarsVal)
				}
			}
		})
	}
}

// TestRunExtractors_DSLExtractor verifies that DSL expressions are evaluated
// and their results stored correctly.
func TestRunExtractors_DSLExtractor(t *testing.T) {
	exec := New(nil)

	resp := &matchers.Response{
		Body:    "hello world",
		Headers: map[string]string{},
	}

	tests := []struct {
		name        string
		extractors  []templates.Extractor
		initialVars map[string]interface{}
		wantKey     string
		wantVal     string
	}{
		{
			name: "dsl toLower expression stored in result",
			extractors: []templates.Extractor{
				{
					Type:     "dsl",
					Name:     "lower_host",
					DSL:      []string{`toLower("EXAMPLE")`},
					Internal: false,
				},
			},
			initialVars: map[string]interface{}{},
			wantKey:     "lower_host",
			wantVal:     "example",
		},
		{
			name: "dsl toUpper expression stored as internal var",
			extractors: []templates.Extractor{
				{
					Type:     "dsl",
					Name:     "upper_val",
					DSL:      []string{`toUpper("test")`},
					Internal: true,
				},
			},
			initialVars: map[string]interface{}{},
			wantKey:     "upper_val",
			wantVal:     "TEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := make(map[string]interface{})
			for k, v := range tt.initialVars {
				vars[k] = v
			}

			result := exec.runExtractors(tt.extractors, resp, vars)

			ext := tt.extractors[0]
			if ext.Internal {
				val, ok := vars[tt.wantKey]
				if !ok {
					t.Errorf("internal DSL extractor should set vars[%q], not found", tt.wantKey)
					return
				}
				if val != tt.wantVal {
					t.Errorf("vars[%q] = %q, want %q", tt.wantKey, val, tt.wantVal)
				}
				if _, inResult := result[tt.wantKey]; inResult {
					t.Errorf("internal extractor should not appear in result map")
				}
			} else {
				vals, ok := result[tt.wantKey]
				if !ok {
					t.Errorf("DSL extractor should store in result[%q], not found", tt.wantKey)
					return
				}
				if len(vals) == 0 || vals[0] != tt.wantVal {
					t.Errorf("result[%q] = %v, want [%q]", tt.wantKey, vals, tt.wantVal)
				}
			}
		})
	}
}

// TestMergeExtractedIntoVars verifies that mergeExtractedIntoVars copies first
// values from ExtractedData into the vars map.
func TestMergeExtractedIntoVars(t *testing.T) {
	exec := New(nil)

	tests := []struct {
		name          string
		extractedData map[string][]string
		initialVars   map[string]interface{}
		wantVars      map[string]interface{}
	}{
		{
			name: "merges single value",
			extractedData: map[string][]string{
				"token": {"abc123"},
			},
			initialVars: map[string]interface{}{},
			wantVars: map[string]interface{}{
				"token": "abc123",
			},
		},
		{
			name: "uses only first value when multiple present",
			extractedData: map[string][]string{
				"id": {"first", "second", "third"},
			},
			initialVars: map[string]interface{}{},
			wantVars: map[string]interface{}{
				"id": "first",
			},
		},
		{
			name: "skips empty slices",
			extractedData: map[string][]string{
				"empty": {},
				"valid": {"value"},
			},
			initialVars: map[string]interface{}{},
			wantVars: map[string]interface{}{
				"valid": "value",
			},
		},
		{
			name:          "nil extracted data is a no-op",
			extractedData: nil,
			initialVars:   map[string]interface{}{"existing": "stays"},
			wantVars:      map[string]interface{}{"existing": "stays"},
		},
		{
			name: "overwrites existing var with new extraction",
			extractedData: map[string][]string{
				"key": {"new_value"},
			},
			initialVars: map[string]interface{}{"key": "old_value"},
			wantVars:    map[string]interface{}{"key": "new_value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := make(map[string]interface{})
			for k, v := range tt.initialVars {
				vars[k] = v
			}

			result := &templates.ExecutionResult{
				ExtractedData: tt.extractedData,
			}

			exec.mergeExtractedIntoVars(result, vars)

			for k, want := range tt.wantVars {
				got, ok := vars[k]
				if !ok {
					t.Errorf("vars[%q] not found, want %q", k, want)
					continue
				}
				if got != want {
					t.Errorf("vars[%q] = %v, want %v", k, got, want)
				}
			}

			// Ensure no unexpected keys were added when data is nil
			if tt.extractedData == nil {
				for k := range vars {
					if _, expected := tt.wantVars[k]; !expected {
						t.Errorf("unexpected key %q added to vars", k)
					}
				}
			}
		})
	}
}

// TestExtractDSL verifies the extractDSL helper evaluates expressions correctly.
func TestExtractDSL(t *testing.T) {
	engine := matchers.NewDSLEngine()

	tests := []struct {
		name        string
		expressions []string
		ctx         map[string]interface{}
		want        []string
	}{
		{
			name:        "toLower expression",
			expressions: []string{`toLower("HELLO")`},
			ctx:         map[string]interface{}{},
			want:        []string{"hello"},
		},
		{
			name:        "toUpper expression",
			expressions: []string{`toUpper("world")`},
			ctx:         map[string]interface{}{},
			want:        []string{"WORLD"},
		},
		{
			name:        "multiple expressions",
			expressions: []string{`toLower("A")`, `toUpper("b")`},
			ctx:         map[string]interface{}{},
			want:        []string{"a", "B"},
		},
		{
			name:        "empty expressions list",
			expressions: []string{},
			ctx:         map[string]interface{}{},
			want:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDSL(engine, tt.expressions, tt.ctx)
			if len(got) != len(tt.want) {
				t.Errorf("extractDSL() returned %d results, want %d: got=%v want=%v",
					len(got), len(tt.want), got, tt.want)
				return
			}
			for i, v := range tt.want {
				if got[i] != v {
					t.Errorf("extractDSL()[%d] = %q, want %q", i, got[i], v)
				}
			}
		})
	}
}
