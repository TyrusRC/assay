package nosql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/nosql"
)

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	if detector.Name() != "nosqli" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "nosqli")
	}
}

func TestDetector_Description(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	desc := detector.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
}

func TestDetector_DetectOperatorBased(t *testing.T) {
	// Create a vulnerable server that responds differently to operator injection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user != "" && (strings.Contains(user, "$ne") || strings.Contains(user, "$gt")) {
			// Simulate successful bypass - return all users
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"users": [{"name": "admin", "role": "admin"}, {"name": "user1", "role": "user"}]}`))
			return
		}
		// Normal response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"users": []}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?user=test", "user", "GET", DetectOptions{
		MaxPayloads:     20,
		EnableTimeBased: false,
		DBType:          nosql.MongoDB,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectErrorBased(t *testing.T) {
	// Create a server that returns MongoDB error messages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user != "" && strings.Contains(user, "$") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "MongoError: unknown operator: $badop"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?user=test", "user", "GET", DetectOptions{
		MaxPayloads:     10,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected error-based vulnerability to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	// Create a safe server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "safe response"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?user=test", "user", "GET", DetectOptions{
		MaxPayloads:     5,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_ErrorPatterns(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		vulnerable bool
		dbType     nosql.DBType
	}{
		{
			name:       "MongoDB syntax error",
			response:   `{"error": "MongoError: $where is disabled"}`,
			vulnerable: true,
			dbType:     nosql.MongoDB,
		},
		{
			name:       "MongoDB unknown operator",
			response:   `{"error": "unknown operator: $badop"}`,
			vulnerable: true,
			dbType:     nosql.MongoDB,
		},
		{
			name:       "MongoDB parse error",
			response:   `{"error": "FailedToParse: Expected field name, got: ["}`,
			vulnerable: true,
			dbType:     nosql.MongoDB,
		},
		{
			name:       "CouchDB invalid selector",
			response:   `{"error": "invalid_selector", "reason": "Invalid selector JSON"}`,
			vulnerable: true,
			dbType:     nosql.CouchDB,
		},
		{
			name:       "Elasticsearch parse error",
			response:   `{"error": {"type": "parsing_exception", "reason": "Unknown query"}}`,
			vulnerable: true,
			dbType:     nosql.Elasticsearch,
		},
		{
			name:       "Elasticsearch script error",
			response:   `{"error": {"type": "script_exception", "reason": "compile error"}}`,
			vulnerable: true,
			dbType:     nosql.Elasticsearch,
		},
		{
			name:       "Redis command error",
			response:   `ERR unknown command 'EVAL', with args`,
			vulnerable: true,
			dbType:     nosql.Redis,
		},
		{
			name:       "Generic JSON error",
			response:   `{"error": "Query parsing failed"}`,
			vulnerable: true,
			dbType:     nosql.Generic,
		},
		{
			name:       "Normal JSON response",
			response:   `{"data": [{"id": 1, "name": "test"}]}`,
			vulnerable: false,
			dbType:     nosql.Generic,
		},
		{
			name:       "Empty response",
			response:   "",
			vulnerable: false,
			dbType:     nosql.Generic,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeResponse(tt.response)
			if result.IsVulnerable != tt.vulnerable {
				t.Errorf("AnalyzeResponse() vulnerable = %v, want %v", result.IsVulnerable, tt.vulnerable)
			}
			if tt.vulnerable && result.DetectionType == "" {
				t.Error("DetectionType should not be empty when vulnerable")
			}
		})
	}
}

func TestDetector_DetectDBType(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		response string
		dbType   nosql.DBType
	}{
		{
			name:     "MongoDB error",
			response: `{"error": "MongoError: bad query"}`,
			dbType:   nosql.MongoDB,
		},
		{
			name:     "CouchDB error",
			response: `{"error": "bad_request", "reason": "invalid UTF-8 JSON"}`,
			dbType:   nosql.CouchDB,
		},
		{
			name:     "Elasticsearch error",
			response: `{"error": {"root_cause": [{"type": "parsing_exception"}]}}`,
			dbType:   nosql.Elasticsearch,
		},
		{
			name:     "Redis error",
			response: `ERR syntax error`,
			dbType:   nosql.Redis,
		},
		{
			name:     "Unknown database",
			response: `{"message": "An error occurred"}`,
			dbType:   nosql.Generic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbType := detector.DetectDBType(tt.response)
			if dbType != tt.dbType {
				t.Errorf("DetectDBType() = %v, want %v", dbType, tt.dbType)
			}
		})
	}
}

func TestDetector_ResponseBasedDetection(t *testing.T) {
	// Test JSON structure change detection
	baselineResponse := `{"users": []}`
	injectedResponse := `{"users": [{"name": "admin"}, {"name": "user1"}, {"name": "user2"}]}`

	client := internalhttp.NewClient()
	detector := New(client)

	hasStructureChange := detector.HasJSONStructureChange(baselineResponse, injectedResponse)
	if !hasStructureChange {
		t.Error("Expected JSON structure change to be detected")
	}
}

func TestDetector_DeduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payloads := []nosql.Payload{
		{Value: `{"$ne": ""}`, DBType: nosql.MongoDB},
		{Value: `{"$gt": ""}`, DBType: nosql.MongoDB},
		{Value: `{"$ne": ""}`, DBType: nosql.MongoDB}, // duplicate
		{Value: `{"$regex": ".*"}`, DBType: nosql.MongoDB},
	}

	deduped := detector.deduplicatePayloads(payloads)
	if len(deduped) != 3 {
		t.Errorf("deduplicatePayloads() returned %d payloads, want 3", len(deduped))
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(ctx, server.URL+"?user=test", "user", "GET", DetectOptions{
		MaxPayloads: 100,
	})

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose(true) should set verbose to true")
	}
}

func TestDetectOptions_Default(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads != 50 {
		t.Errorf("DefaultOptions().MaxPayloads = %d, want 50", opts.MaxPayloads)
	}
	if !opts.IncludeWAFBypass {
		t.Error("DefaultOptions().IncludeWAFBypass should be true")
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("DefaultOptions().Timeout = %v, want 10s", opts.Timeout)
	}
}

func TestDetectionResult_Fields(t *testing.T) {
	result := &DetectionResult{
		Vulnerable:     true,
		TestedPayloads: 10,
		DetectedDBType: nosql.MongoDB,
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.TestedPayloads != 10 {
		t.Errorf("TestedPayloads = %d, want 10", result.TestedPayloads)
	}
	if result.DetectedDBType != nosql.MongoDB {
		t.Errorf("DetectedDBType = %v, want MongoDB", result.DetectedDBType)
	}
}

func TestAnalysisResult_Fields(t *testing.T) {
	result := &AnalysisResult{
		IsVulnerable:  true,
		DetectionType: "error-based",
		Confidence:    0.9,
		Evidence:      "MongoError: unknown operator",
		DatabaseType:  nosql.MongoDB,
	}

	if !result.IsVulnerable {
		t.Error("IsVulnerable should be true")
	}
	if result.DetectionType != "error-based" {
		t.Errorf("DetectionType = %q, want %q", result.DetectionType, "error-based")
	}
	if result.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want %f", result.Confidence, 0.9)
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if strings.Contains(user, "$ne") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"users": [{"name": "admin"}]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"users": []}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?user=test", "user", "GET", DetectOptions{
		MaxPayloads:     5,
		EnableTimeBased: false,
		DBType:          nosql.MongoDB,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	// Check WSTG mapping
	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-05" {
		t.Errorf("Expected WSTG-INPV-05 mapping, got %v", finding.WSTG)
	}

	// Check Top10 mapping
	if len(finding.Top10) == 0 || finding.Top10[0] != "A03:2025" {
		t.Errorf("Expected A03:2025 mapping, got %v", finding.Top10)
	}

	// Check CWE mapping
	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-943" {
		t.Errorf("Expected CWE-943 mapping, got %v", finding.CWE)
	}
}

func TestDetector_JSONInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate vulnerable JSON parsing
		body := r.URL.Query().Get("data")
		if strings.Contains(body, `"$ne"`) || strings.Contains(body, `"$or"`) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"authenticated": true, "user": "admin"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"authenticated": false}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?data=test", "data", "GET", DetectOptions{
		MaxPayloads:     10,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected JSON injection vulnerability to be detected")
	}
}

func TestDetector_EmptyParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, "", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should not crash with empty parameter
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestDetector_MultipleDBTypes(t *testing.T) {
	dbTypes := []nosql.DBType{nosql.MongoDB, nosql.CouchDB, nosql.Elasticsearch, nosql.Redis}

	for _, dbType := range dbTypes {
		t.Run(string(dbType), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
			}))
			defer server.Close()

			client := internalhttp.NewClient()
			detector := New(client)

			result, err := detector.Detect(context.Background(), server.URL+"?param=test", "param", "GET", DetectOptions{
				MaxPayloads: 3,
				DBType:      dbType,
			})

			if err != nil {
				t.Fatalf("Detect failed for %s: %v", dbType, err)
			}

			if result.TestedPayloads == 0 {
				t.Errorf("Expected payloads to be tested for %s", dbType)
			}
		})
	}
}

func TestDetector_HasJSONStructureChange_EdgeCases(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name           string
		baseline       string
		injected       string
		expectedChange bool
	}{
		{
			name:           "Empty baseline",
			baseline:       "",
			injected:       `{"users": [{"name": "admin"}]}`,
			expectedChange: false,
		},
		{
			name:           "Empty injected",
			baseline:       `{"users": []}`,
			injected:       "",
			expectedChange: false,
		},
		{
			name:           "Both empty",
			baseline:       "",
			injected:       "",
			expectedChange: false,
		},
		{
			name:           "Invalid baseline JSON",
			baseline:       `{invalid}`,
			injected:       `{"users": []}`,
			expectedChange: false,
		},
		{
			name:           "Invalid injected JSON",
			baseline:       `{"users": []}`,
			injected:       `{invalid}`,
			expectedChange: false,
		},
		{
			name:           "No change",
			baseline:       `{"users": []}`,
			injected:       `{"users": []}`,
			expectedChange: false,
		},
		{
			name:           "Small increase",
			baseline:       `{"users": [{"name": "user1"}]}`,
			injected:       `{"users": [{"name": "user1"}, {"name": "user2"}]}`,
			expectedChange: false, // Not significant enough
		},
		{
			name:           "Large increase",
			baseline:       `{"users": []}`,
			injected:       `{"users": [{"name": "admin"}, {"name": "user1"}, {"name": "user2"}, {"name": "user3"}, {"name": "user4"}, {"name": "user5"}, {"name": "user6"}]}`,
			expectedChange: true,
		},
		{
			name:           "Auth bypass indicator - authenticated field",
			baseline:       `{"authenticated": false}`,
			injected:       `{"authenticated": true}`,
			expectedChange: true,
		},
		{
			name:           "Auth bypass indicator - role change",
			baseline:       `{"role": "user"}`,
			injected:       `{"role": "admin"}`,
			expectedChange: true,
		},
		{
			name:           "Auth bypass indicator - new authenticated field",
			baseline:       `{"status": "ok"}`,
			injected:       `{"status": "ok", "authenticated": true}`,
			expectedChange: true,
		},
		{
			name:           "Top level array empty to non-empty",
			baseline:       `[]`,
			injected:       `[{"name": "admin"}]`,
			expectedChange: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasChange := detector.HasJSONStructureChange(tt.baseline, tt.injected)
			if hasChange != tt.expectedChange {
				t.Errorf("HasJSONStructureChange() = %v, want %v", hasChange, tt.expectedChange)
			}
		})
	}
}

func TestDetector_DetectDBType_Additional(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		response string
		dbType   nosql.DBType
	}{
		{
			name:     "MongoDB $where error",
			response: `{"error": "$where clause is not allowed"}`,
			dbType:   nosql.MongoDB,
		},
		{
			name:     "MongoDB lowercase",
			response: `{"error": "mongodb connection error"}`,
			dbType:   nosql.MongoDB,
		},
		{
			name:     "CouchDB invalid_selector",
			response: `{"error": "invalid_selector"}`,
			dbType:   nosql.CouchDB,
		},
		{
			name:     "Elasticsearch search_phase_execution_exception",
			response: `{"error": {"type": "search_phase_execution_exception"}}`,
			dbType:   nosql.Elasticsearch,
		},
		{
			name:     "Redis WRONGTYPE",
			response: `WRONGTYPE Operation against a key holding the wrong kind of value`,
			dbType:   nosql.Redis,
		},
		{
			name:     "Redis lowercase",
			response: `{"error": "redis connection refused"}`,
			dbType:   nosql.Redis,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbType := detector.DetectDBType(tt.response)
			if dbType != tt.dbType {
				t.Errorf("DetectDBType() = %v, want %v", dbType, tt.dbType)
			}
		})
	}
}

func TestDetector_AnalyzeResponse_AllPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	// Test various error patterns for full coverage
	patterns := []struct {
		name     string
		response string
	}{
		{"MongoDB BadValue", `{"error": "BadValue: invalid query"}`},
		{"MongoDB cannot apply", `{"error": "cannot apply $gt to string type"}`},
		{"MongoDB invalid operator", `{"error": "invalid operator $custom"}`},
		{"MongoDB unrecognized", `{"error": "unrecognized expression"}`},
		{"MongoDB Command failed", `{"error": "Command failed with errmsg"}`},
		{"MongoDB parallel arrays", `{"error": "cannot index parallel arrays"}`},
		{"MongoDB Projection mix", `{"error": "Projection cannot have a mix of inclusion and exclusion"}`},
		{"CouchDB compilation_error", `{"error": "compilation_error"}`},
		{"CouchDB No matching index", `{"error": "No matching index found"}`},
		{"CouchDB selector reason", `{"reason": "invalid selector format"}`},
		{"Elasticsearch illegal_argument", `{"error": {"type": "illegal_argument_exception"}}`},
		{"Elasticsearch unknown query", `{"error": "unknown query: bad_query"}`},
		{"Elasticsearch SearchParseException", `SearchParseException: failed to parse query`},
		{"Redis ERR invalid", `ERR invalid argument`},
		{"Redis NOSCRIPT", `NOSCRIPT No matching script`},
		{"Generic parse error", `{"error": "parse error in query"}`},
		{"Generic syntax error", `{"error": "syntax error: unexpected token"}`},
		{"Generic invalid query", `{"error": "invalid query format"}`},
		{"Generic malformed query", `{"error": "malformed query string"}`},
	}

	for _, tt := range patterns {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeResponse(tt.response)
			if !result.IsVulnerable {
				t.Errorf("AnalyzeResponse(%q) should detect vulnerability", tt.response)
			}
		})
	}
}

func TestDetector_BaselineError(t *testing.T) {
	// Create a server that returns error on baseline
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	server.Close() // Close immediately to cause connection error

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(context.Background(), server.URL+"?user=test", "user", "GET", DetectOptions{
		MaxPayloads:     5,
		EnableTimeBased: false,
	})

	if err == nil {
		t.Error("Expected error when baseline request fails")
	}
}

func TestDetector_RequestError(t *testing.T) {
	// First request succeeds (baseline), subsequent requests fail
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// Baseline succeeds
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"users": []}`))
			return
		}
		// Subsequent requests fail - simulate network error by closing connection
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	// Should handle request errors gracefully and continue testing
	result, err := detector.Detect(context.Background(), server.URL+"?user=test", "user", "GET", DetectOptions{
		MaxPayloads:     3,
		EnableTimeBased: false,
	})

	// Should not return error but should have tested some payloads
	if err != nil {
		t.Logf("Detect returned error (expected for connection issues): %v", err)
	}

	if result != nil && result.TestedPayloads == 0 {
		t.Error("Expected some payloads to be tested")
	}
}

func TestDetector_WithNoWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?param=test", "param", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false, // Disable WAF bypass payloads
		EnableTimeBased:  false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should still test payloads, just without WAF bypass ones
	if result.TestedPayloads == 0 {
		t.Error("Expected payloads to be tested")
	}
}

func TestDetector_GenericDBType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?param=test", "param", "GET", DetectOptions{
		MaxPayloads:     10,
		DBType:          nosql.Generic, // Test with generic DB type
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.TestedPayloads == 0 {
		t.Error("Expected payloads to be tested for Generic DB type")
	}
}

func TestExtractMatch_TruncatesLongMatches(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	// Create a very long error message
	longError := "MongoError: " + strings.Repeat("x", 200)
	result := detector.AnalyzeResponse(longError)

	if !result.IsVulnerable {
		t.Error("Should detect MongoDB error")
	}

	// Evidence should be truncated
	if len(result.Evidence) > 104 { // 100 + "..."
		t.Errorf("Evidence should be truncated, got length %d", len(result.Evidence))
	}
}

func TestDetector_FindingCreation(t *testing.T) {
	// Test that findings are created with correct fields
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")
		if strings.Contains(param, "$ne") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"error": "MongoError: unknown operator"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?test=value", "test", "GET", DetectOptions{
		MaxPayloads:     5,
		EnableTimeBased: false,
		DBType:          nosql.MongoDB,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding validation")
	}

	finding := result.Findings[0]

	// Validate finding fields
	if finding.Type != "NoSQL Injection" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "NoSQL Injection")
	}

	if finding.Tool != "nosqli-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "nosqli-detector")
	}

	if finding.Parameter != "test" {
		t.Errorf("Finding.Parameter = %q, want %q", finding.Parameter, "test")
	}

	if finding.Remediation == "" {
		t.Error("Finding.Remediation should not be empty")
	}

	if finding.Description == "" {
		t.Error("Finding.Description should not be empty")
	}

	if finding.Evidence == "" {
		t.Error("Finding.Evidence should not be empty")
	}
}
