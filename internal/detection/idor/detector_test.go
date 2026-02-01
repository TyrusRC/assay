package idor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

// TestNew verifies that New creates a valid Detector instance.
func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}
	if detector.client == nil {
		t.Error("Detector client is nil")
	}
}

// TestWithVerbose tests the verbose option setter.
func TestWithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose to true")
	}
}

// TestDefaultOptions verifies default detection options.
func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxRequests <= 0 {
		t.Error("MaxRequests should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
	if len(opts.IDTypes) == 0 {
		t.Error("IDTypes should not be empty")
	}
}

// TestDetectNumericIDInQuery tests detection of numeric ID manipulation in query parameters.
func TestDetectNumericIDInQuery(t *testing.T) {
	// Create a vulnerable server that returns different user data based on ID
	userData := map[string]string{
		"1":   `{"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789"}`,
		"2":   `{"id": 2, "name": "Bob", "email": "bob@example.com", "ssn": "987-65-4321"}`,
		"999": `{"error": "User not found"}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		if data, ok := userData[userID]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(data))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "User not found"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?user_id=1", DetectOptions{
		MaxRequests: 10,
		IDTypes:     []IDType{IDTypeNumeric},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected IDOR vulnerability to be detected for numeric ID")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

// TestDetectNumericIDInPath tests detection of numeric ID manipulation in URL path.
func TestDetectNumericIDInPath(t *testing.T) {
	userData := map[string]string{
		"1": `{"id": 1, "name": "Alice", "role": "admin"}`,
		"2": `{"id": 2, "name": "Bob", "role": "user"}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract ID from path like /users/123/profile
		parts := strings.Split(r.URL.Path, "/")
		for i, part := range parts {
			if part == "users" && i+1 < len(parts) {
				userID := parts[i+1]
				if data, ok := userData[userID]; ok {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(data))
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Not found"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/users/1/profile", DetectOptions{
		MaxRequests: 10,
		IDTypes:     []IDType{IDTypeNumeric},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected IDOR vulnerability to be detected for path-based numeric ID")
	}
}

// TestDetectUUIDInQuery tests detection of UUID manipulation in query parameters.
func TestDetectUUIDInQuery(t *testing.T) {
	userData := map[string]string{
		"550e8400-e29b-41d4-a716-446655440000": `{"id": "550e8400-e29b-41d4-a716-446655440000", "name": "Alice"}`,
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8": `{"id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "name": "Bob"}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("id")
		if data, ok := userData[userID]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(data))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Not found"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?id=550e8400-e29b-41d4-a716-446655440000", DetectOptions{
		MaxRequests: 10,
		IDTypes:     []IDType{IDTypeUUID},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// UUID-based IDOR is harder to detect without known UUIDs
	// The detector should at least attempt the test
	if result.TestedIDs == 0 {
		t.Error("Expected at least some IDs to be tested")
	}
}

// TestDetectBase64EncodedID tests detection of base64-encoded ID manipulation.
func TestDetectBase64EncodedID(t *testing.T) {
	// Encode IDs as base64
	id1 := base64.StdEncoding.EncodeToString([]byte("user:1"))
	id2 := base64.StdEncoding.EncodeToString([]byte("user:2"))

	userData := map[string]string{
		id1: `{"id": 1, "name": "Alice", "credit_card": "4111-1111-1111-1111"}`,
		id2: `{"id": 2, "name": "Bob", "credit_card": "5500-0000-0000-0004"}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if data, ok := userData[token]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(data))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Access denied"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?token="+id1, DetectOptions{
		MaxRequests: 10,
		IDTypes:     []IDType{IDTypeBase64},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected IDOR vulnerability to be detected for base64-encoded ID")
	}
}

// TestDetectHexEncodedID tests detection of hex-encoded ID manipulation.
func TestDetectHexEncodedID(t *testing.T) {
	// Encode IDs as hex
	id1 := hex.EncodeToString([]byte("user_1"))
	id2 := hex.EncodeToString([]byte("user_2"))

	userData := map[string]string{
		id1: `{"id": 1, "name": "Alice"}`,
		id2: `{"id": 2, "name": "Bob"}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("ref")
		if data, ok := userData[token]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(data))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Invalid reference"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?ref="+id1, DetectOptions{
		MaxRequests: 10,
		IDTypes:     []IDType{IDTypeHex},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected IDOR vulnerability to be detected for hex-encoded ID")
	}
}

// TestDetectJSONBodyID tests detection of ID manipulation in JSON request body.
func TestDetectJSONBodyID(t *testing.T) {
	userData := map[int]string{
		1: `{"id": 1, "name": "Alice", "balance": 10000}`,
		2: `{"id": 2, "name": "Bob", "balance": 500}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			UserID int `json:"user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if data, ok := userData[body.UserID]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(data))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "User not found"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectInBody(context.Background(), server.URL, "POST",
		`{"user_id": 1}`, "application/json", DetectOptions{
			MaxRequests: 10,
			IDTypes:     []IDType{IDTypeNumeric},
		})

	if err != nil {
		t.Fatalf("DetectInBody failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected IDOR vulnerability to be detected for JSON body ID")
	}
}

// TestDetectFormBodyID tests detection of ID manipulation in form data.
func TestDetectFormBodyID(t *testing.T) {
	orderData := map[string]string{
		"1001": `Order #1001: Total $500, Status: Shipped`,
		"1002": `Order #1002: Total $1200, Status: Processing`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		orderID := r.FormValue("order_id")
		if data, ok := orderData[orderID]; ok {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(data))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Order not found"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectInBody(context.Background(), server.URL, "POST",
		"order_id=1001", "application/x-www-form-urlencoded", DetectOptions{
			MaxRequests: 10,
			IDTypes:     []IDType{IDTypeNumeric},
		})

	if err != nil {
		t.Fatalf("DetectInBody failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected IDOR vulnerability to be detected for form body ID")
	}
}

// TestResponseComparison tests response comparison for detecting IDOR.
func TestResponseComparison(t *testing.T) {
	tests := []struct {
		name           string
		resp1          *internalhttp.Response
		resp2          *internalhttp.Response
		expectDiff     bool
		expectSensData bool
	}{
		{
			name: "same responses",
			resp1: &internalhttp.Response{
				StatusCode: 200,
				Body:       `{"id": 1, "name": "Test"}`,
			},
			resp2: &internalhttp.Response{
				StatusCode: 200,
				Body:       `{"id": 1, "name": "Test"}`,
			},
			expectDiff:     false,
			expectSensData: false,
		},
		{
			name: "different user data",
			resp1: &internalhttp.Response{
				StatusCode: 200,
				Body:       `{"id": 1, "name": "Alice", "email": "alice@example.com"}`,
			},
			resp2: &internalhttp.Response{
				StatusCode: 200,
				Body:       `{"id": 2, "name": "Bob", "email": "bob@example.com"}`,
			},
			expectDiff:     true,
			expectSensData: true,
		},
		{
			name: "access denied vs success",
			resp1: &internalhttp.Response{
				StatusCode: 200,
				Body:       `{"id": 1, "name": "Alice"}`,
			},
			resp2: &internalhttp.Response{
				StatusCode: 403,
				Body:       `{"error": "Access denied"}`,
			},
			expectDiff:     true,
			expectSensData: false,
		},
		{
			name: "sensitive data exposure",
			resp1: &internalhttp.Response{
				StatusCode: 200,
				Body:       `{"id": 1, "ssn": "123-45-6789", "credit_card": "4111-1111-1111-1111"}`,
			},
			resp2: &internalhttp.Response{
				StatusCode: 200,
				Body:       `{"id": 2, "ssn": "987-65-4321", "credit_card": "5500-0000-0000-0004"}`,
			},
			expectDiff:     true,
			expectSensData: true,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := detector.compareResponses(tt.resp1, tt.resp2)

			if diff.HasSignificantDifference != tt.expectDiff {
				t.Errorf("HasSignificantDifference = %v, want %v", diff.HasSignificantDifference, tt.expectDiff)
			}

			if tt.expectSensData {
				hasSensitive := detector.containsSensitiveData(tt.resp2.Body)
				if !hasSensitive {
					t.Error("Expected sensitive data to be detected")
				}
			}
		})
	}
}

// TestStatusCodeAnalysis tests the status code analysis for IDOR detection.
func TestStatusCodeAnalysis(t *testing.T) {
	tests := []struct {
		name           string
		baselineCode   int
		testCode       int
		expectIDOR     bool
		expectedReason string
	}{
		{
			name:         "both 200 OK",
			baselineCode: 200,
			testCode:     200,
			expectIDOR:   true, // Might indicate IDOR if content differs
		},
		{
			name:         "200 to 403 Forbidden",
			baselineCode: 200,
			testCode:     403,
			expectIDOR:   false, // Proper authorization
		},
		{
			name:         "403 to 200",
			baselineCode: 403,
			testCode:     200,
			expectIDOR:   true, // Authorization bypass
		},
		{
			name:         "200 to 404 Not Found",
			baselineCode: 200,
			testCode:     404,
			expectIDOR:   false, // Resource not found
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := detector.analyzeStatusCodes(tt.baselineCode, tt.testCode)
			if analysis.PotentialIDOR != tt.expectIDOR {
				t.Errorf("analyzeStatusCodes() PotentialIDOR = %v, want %v", analysis.PotentialIDOR, tt.expectIDOR)
			}
		})
	}
}

// TestContentLengthComparison tests content length comparison for IDOR detection.
func TestContentLengthComparison(t *testing.T) {
	tests := []struct {
		name       string
		len1       int
		len2       int
		expectDiff bool
	}{
		{
			name:       "similar lengths",
			len1:       100,
			len2:       105,
			expectDiff: false,
		},
		{
			name:       "significantly different",
			len1:       100,
			len2:       500,
			expectDiff: true,
		},
		{
			name:       "empty vs content",
			len1:       0,
			len2:       100,
			expectDiff: true,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isDiff := detector.hasSignificantLengthDiff(tt.len1, tt.len2)
			if isDiff != tt.expectDiff {
				t.Errorf("hasSignificantLengthDiff(%d, %d) = %v, want %v", tt.len1, tt.len2, isDiff, tt.expectDiff)
			}
		})
	}
}

// TestSensitiveDataDetection tests detection of sensitive data in responses.
func TestSensitiveDataDetection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "SSN",
			body:     `{"ssn": "123-45-6789"}`,
			expected: true,
		},
		{
			name:     "credit card",
			body:     `{"card": "4111-1111-1111-1111"}`,
			expected: true,
		},
		{
			name:     "email",
			body:     `{"email": "user@example.com", "name": "User"}`,
			expected: true,
		},
		{
			name:     "password hash",
			body:     `{"password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}`,
			expected: true,
		},
		{
			name:     "API key",
			body:     `{"api_key": "sk-proj-abc123xyz789"}`,
			expected: true,
		},
		{
			name:     "safe content",
			body:     `{"message": "Hello World", "status": "ok"}`,
			expected: false,
		},
		{
			name:     "phone number",
			body:     `{"phone": "+1-555-123-4567"}`,
			expected: true,
		},
		{
			name:     "address",
			body:     `{"address": "123 Main St, City, State 12345"}`,
			expected: true,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.containsSensitiveData(tt.body)
			if result != tt.expected {
				t.Errorf("containsSensitiveData() = %v, want %v for body: %s", result, tt.expected, tt.body)
			}
		})
	}
}

// TestIDExtraction tests extraction of IDs from various locations.
func TestIDExtraction(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		body           string
		contentType    string
		expectedParams []IDParameter
	}{
		{
			name: "query parameter numeric",
			url:  "http://example.com/api?user_id=123",
			expectedParams: []IDParameter{
				{Name: "user_id", Value: "123", Type: IDTypeNumeric, Location: LocationQuery},
			},
		},
		{
			name: "path parameter numeric",
			url:  "http://example.com/users/456/profile",
			expectedParams: []IDParameter{
				{Name: "456", Value: "456", Type: IDTypeNumeric, Location: LocationPath},
			},
		},
		{
			name: "UUID in query",
			url:  "http://example.com/api?id=550e8400-e29b-41d4-a716-446655440000",
			expectedParams: []IDParameter{
				{Name: "id", Value: "550e8400-e29b-41d4-a716-446655440000", Type: IDTypeUUID, Location: LocationQuery},
			},
		},
		{
			name:        "JSON body ID",
			url:         "http://example.com/api",
			body:        `{"user_id": 789, "action": "view"}`,
			contentType: "application/json",
			expectedParams: []IDParameter{
				{Name: "user_id", Value: "789", Type: IDTypeNumeric, Location: LocationBody},
			},
		},
		{
			name:        "form body ID",
			url:         "http://example.com/api",
			body:        "order_id=1001&action=view",
			contentType: "application/x-www-form-urlencoded",
			expectedParams: []IDParameter{
				{Name: "order_id", Value: "1001", Type: IDTypeNumeric, Location: LocationBody},
			},
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := detector.extractIDParameters(tt.url, tt.body, tt.contentType)

			if len(params) < len(tt.expectedParams) {
				t.Errorf("Expected at least %d parameters, got %d", len(tt.expectedParams), len(params))
				return
			}

			for _, expected := range tt.expectedParams {
				found := false
				for _, param := range params {
					if param.Name == expected.Name &&
						param.Value == expected.Value &&
						param.Type == expected.Type &&
						param.Location == expected.Location {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected parameter not found: %+v", expected)
				}
			}
		})
	}
}

// TestIDManipulation tests ID manipulation strategies.
func TestIDManipulation(t *testing.T) {
	tests := []struct {
		name             string
		originalID       string
		idType           IDType
		expectedContains []string
	}{
		{
			name:       "numeric increment",
			originalID: "100",
			idType:     IDTypeNumeric,
			expectedContains: []string{
				"99",  // decrement
				"101", // increment
				"1",   // common ID
			},
		},
		{
			name:       "base64 manipulation",
			originalID: base64.StdEncoding.EncodeToString([]byte("user:1")),
			idType:     IDTypeBase64,
			expectedContains: []string{
				base64.StdEncoding.EncodeToString([]byte("user:2")),
				base64.StdEncoding.EncodeToString([]byte("user:0")),
			},
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manipulated := detector.generateManipulatedIDs(tt.originalID, tt.idType)

			if len(manipulated) == 0 {
				t.Error("Expected manipulated IDs, got none")
				return
			}

			for _, expected := range tt.expectedContains {
				found := false
				for _, id := range manipulated {
					if id == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected manipulated ID %q not found in %v", expected, manipulated)
				}
			}
		})
	}
}

// TestConfidenceScoring tests confidence scoring based on evidence.
func TestConfidenceScoring(t *testing.T) {
	tests := []struct {
		name               string
		statusCodeMatch    bool
		contentDiff        bool
		sensitiveData      bool
		expectedConfidence core.Confidence
	}{
		{
			name:               "all indicators",
			statusCodeMatch:    true,
			contentDiff:        true,
			sensitiveData:      true,
			expectedConfidence: core.ConfidenceHigh,
		},
		{
			name:               "status and content diff",
			statusCodeMatch:    true,
			contentDiff:        true,
			sensitiveData:      false,
			expectedConfidence: core.ConfidenceMedium,
		},
		{
			name:               "only status code",
			statusCodeMatch:    true,
			contentDiff:        false,
			sensitiveData:      false,
			expectedConfidence: core.ConfidenceLow,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := &IDOREvidence{
				StatusCodeIndicatesAccess: tt.statusCodeMatch,
				ContentDifferent:          tt.contentDiff,
				SensitiveDataExposed:      tt.sensitiveData,
			}

			confidence := detector.calculateConfidence(evidence)
			if confidence != tt.expectedConfidence {
				t.Errorf("calculateConfidence() = %v, want %v", confidence, tt.expectedConfidence)
			}
		})
	}
}

// TestOWASPMapping verifies correct OWASP framework mappings.
func TestOWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("id")
		if userID == "1" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 1, "name": "Alice", "email": "alice@example.com"}`))
		} else if userID == "2" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 2, "name": "Bob", "email": "bob@example.com"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?id=1", DetectOptions{
		MaxRequests: 10,
		IDTypes:     []IDType{IDTypeNumeric},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Skip("No findings to verify OWASP mapping")
		return
	}

	finding := result.Findings[0]

	// Verify WSTG mapping
	expectedWSTG := []string{"WSTG-ATHZ-04"}
	if len(finding.WSTG) == 0 || finding.WSTG[0] != expectedWSTG[0] {
		t.Errorf("Expected WSTG %v, got %v", expectedWSTG, finding.WSTG)
	}

	// Verify Top 10 mapping
	expectedTop10 := []string{"A01:2021"}
	if len(finding.Top10) == 0 || finding.Top10[0] != expectedTop10[0] {
		t.Errorf("Expected Top10 %v, got %v", expectedTop10, finding.Top10)
	}

	// Verify API Top 10 mapping
	expectedAPITop10 := []string{"API1:2023"}
	if len(finding.APITop10) == 0 || finding.APITop10[0] != expectedAPITop10[0] {
		t.Errorf("Expected APITop10 %v, got %v", expectedAPITop10, finding.APITop10)
	}

	// Verify CWE mapping
	expectedCWE := []string{"CWE-639"}
	if len(finding.CWE) == 0 || finding.CWE[0] != expectedCWE[0] {
		t.Errorf("Expected CWE %v, got %v", expectedCWE, finding.CWE)
	}
}

// TestSafeServer verifies no false positives on properly secured endpoints.
func TestSafeServer(t *testing.T) {
	// Server that properly validates authorization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate proper authorization check - only allow ID 1
		userID := r.URL.Query().Get("id")
		if userID == "1" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 1, "name": "Your Profile"}`))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Access denied"}`))
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?id=1", DetectOptions{
		MaxRequests: 5,
		IDTypes:     []IDType{IDTypeNumeric},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability on properly secured server")
	}
}

// TestContextCancellation tests that detection respects context cancellation.
func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := detector.Detect(ctx, server.URL+"?id=1", DetectOptions{
		MaxRequests: 100,
	})

	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
}

// TestMultipleIDParameters tests detection with multiple ID parameters.
func TestMultipleIDParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		orderID := r.URL.Query().Get("order_id")

		// Both IDs are vulnerable
		if userID != "" && orderID != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"user_id": ` + userID + `, "order_id": ` + orderID + `, "data": "sensitive"}`))
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?user_id=1&order_id=100", DetectOptions{
		MaxRequests: 20,
		IDTypes:     []IDType{IDTypeNumeric},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect vulnerability in at least one parameter
	if !result.Vulnerable {
		t.Error("Expected IDOR vulnerability with multiple ID parameters")
	}
}

// TestIDTypeDetection tests automatic ID type detection.
func TestIDTypeDetection(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected IDType
	}{
		{
			name:     "numeric",
			value:    "12345",
			expected: IDTypeNumeric,
		},
		{
			name:     "UUID v4",
			value:    "550e8400-e29b-41d4-a716-446655440000",
			expected: IDTypeUUID,
		},
		{
			name:     "base64",
			value:    base64.StdEncoding.EncodeToString([]byte("user:123")),
			expected: IDTypeBase64,
		},
		{
			name:     "hex",
			value:    "deadbeef1234567890abcdef",
			expected: IDTypeHex,
		},
		{
			name:     "alphanumeric",
			value:    "user_abc123",
			expected: IDTypeAlphanumeric,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected := detector.detectIDType(tt.value)
			if detected != tt.expected {
				t.Errorf("detectIDType(%q) = %v, want %v", tt.value, detected, tt.expected)
			}
		})
	}
}

// TestAuthorizationBypass tests detection of authorization bypass scenarios.
func TestAuthorizationBypass(t *testing.T) {
	// Server where changing ID bypasses authorization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		id, _ := strconv.Atoi(userID)

		// Vulnerable: returns data for any valid ID without checking ownership
		if id >= 1 && id <= 100 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"user_id": ` + userID + `, "balance": 10000, "ssn": "123-45-6789"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "User not found"}`))
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?user_id=1", DetectOptions{
		MaxRequests: 10,
		IDTypes:     []IDType{IDTypeNumeric},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected authorization bypass detection")
	}

	// Should have high severity due to sensitive data exposure
	if len(result.Findings) > 0 && result.Findings[0].Severity != core.SeverityHigh &&
		result.Findings[0].Severity != core.SeverityCritical {
		t.Errorf("Expected high/critical severity, got %v", result.Findings[0].Severity)
	}
}

// BenchmarkDetect benchmarks the detection performance.
func BenchmarkDetect(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 1}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(context.Background(), server.URL+"?id=1", DetectOptions{
			MaxRequests: 5,
			IDTypes:     []IDType{IDTypeNumeric},
		})
	}
}

// TestTableDrivenIDManipulation provides comprehensive ID manipulation tests.
func TestTableDrivenIDManipulation(t *testing.T) {
	testCases := []struct {
		name         string
		originalID   string
		idType       IDType
		minVariants  int
		mustInclude  []string
		mustNotEqual []string
	}{
		{
			name:        "small numeric",
			originalID:  "5",
			idType:      IDTypeNumeric,
			minVariants: 3,
			mustInclude: []string{"4", "6", "1"},
		},
		{
			name:        "large numeric",
			originalID:  "999999",
			idType:      IDTypeNumeric,
			minVariants: 3,
			mustInclude: []string{"999998", "1000000"},
		},
		{
			name:         "uuid",
			originalID:   "550e8400-e29b-41d4-a716-446655440000",
			idType:       IDTypeUUID,
			minVariants:  1,
			mustNotEqual: []string{"550e8400-e29b-41d4-a716-446655440000"},
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			variants := detector.generateManipulatedIDs(tc.originalID, tc.idType)

			if len(variants) < tc.minVariants {
				t.Errorf("Expected at least %d variants, got %d", tc.minVariants, len(variants))
			}

			for _, must := range tc.mustInclude {
				found := false
				for _, v := range variants {
					if v == must {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected variant %q not found", must)
				}
			}

			for _, mustNot := range tc.mustNotEqual {
				for _, v := range variants {
					if v == mustNot {
						t.Errorf("Variant should not equal original: %q", mustNot)
					}
				}
			}
		})
	}
}
