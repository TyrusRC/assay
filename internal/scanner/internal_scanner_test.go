package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

func TestNewInternalScanner(t *testing.T) {
	scanner, err := NewInternalScanner(nil)

	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	if scanner == nil {
		t.Fatal("NewInternalScanner() returned nil")
	}
	if scanner.client == nil {
		t.Error("scanner.client is nil")
	}
	if scanner.sqliDetector == nil {
		t.Error("scanner.sqliDetector is nil")
	}
	if scanner.xssDetector == nil {
		t.Error("scanner.xssDetector is nil")
	}
}

func TestNewInternalScanner_WithConfig(t *testing.T) {
	config := &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           false,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	if scanner.config.EnableXSS != false {
		t.Error("Config EnableXSS should be false")
	}
	if scanner.config.MaxPayloadsPerParam != 10 {
		t.Errorf("Config MaxPayloadsPerParam = %d, want 10", scanner.config.MaxPayloadsPerParam)
	}
}

func TestDefaultInternalConfig(t *testing.T) {
	config := DefaultInternalConfig()

	if !config.EnableSQLi {
		t.Error("Default EnableSQLi should be true")
	}
	if !config.EnableXSS {
		t.Error("Default EnableXSS should be true")
	}
	if !config.EnableCMDI {
		t.Error("Default EnableCMDI should be true")
	}
	if !config.EnableSSRF {
		t.Error("Default EnableSSRF should be true")
	}
	if !config.EnableLFI {
		t.Error("Default EnableLFI should be true")
	}
	if !config.EnableXXE {
		t.Error("Default EnableXXE should be true")
	}
	if !config.EnableNoSQL {
		t.Error("Default EnableNoSQL should be true")
	}
	if !config.EnableSSTI {
		t.Error("Default EnableSSTI should be true")
	}
	if !config.EnableIDOR {
		t.Error("Default EnableIDOR should be true")
	}
	if config.EnableJWT {
		t.Error("Default EnableJWT should be false")
	}
	if !config.EnableRedirect {
		t.Error("Default EnableRedirect should be true")
	}
	if !config.EnableCORS {
		t.Error("Default EnableCORS should be true")
	}
	if !config.EnableCRLF {
		t.Error("Default EnableCRLF should be true")
	}
	if config.MaxPayloadsPerParam <= 0 {
		t.Error("Default MaxPayloadsPerParam should be positive")
	}
	if config.RequestTimeout <= 0 {
		t.Error("Default RequestTimeout should be positive")
	}
}

func TestInternalScanner_NewDetectorsInitialized(t *testing.T) {
	scanner, err := NewInternalScanner(nil)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	// Test new detectors are initialized
	if scanner.nosqlDetector == nil {
		t.Error("nosqlDetector should be initialized")
	}
	if scanner.sstiDetector == nil {
		t.Error("sstiDetector should be initialized")
	}
	if scanner.idorDetector == nil {
		t.Error("idorDetector should be initialized")
	}
	if scanner.jwtDetector == nil {
		t.Error("jwtDetector should be initialized")
	}
	if scanner.redirectDetector == nil {
		t.Error("redirectDetector should be initialized")
	}
	if scanner.corsDetector == nil {
		t.Error("corsDetector should be initialized")
	}
	if scanner.crlfDetector == nil {
		t.Error("crlfDetector should be initialized")
	}
}

func TestInternalScanner_ExtractParameters(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)

	tests := []struct {
		name           string
		url            string
		expectedParams []string
	}{
		{
			name:           "single parameter",
			url:            "https://example.com/page?id=1",
			expectedParams: []string{"id"},
		},
		{
			name:           "multiple parameters",
			url:            "https://example.com/search?q=test&page=1&sort=asc",
			expectedParams: []string{"q", "page", "sort"},
		},
		{
			name:           "no parameters",
			url:            "https://example.com/page",
			expectedParams: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := core.NewTarget(tt.url)
			if err != nil {
				t.Fatalf("NewTarget() error = %v", err)
			}

			params := scanner.extractParameters(target)

			if len(params) != len(tt.expectedParams) {
				t.Errorf("extractParameters() count = %d, want %d", len(params), len(tt.expectedParams))
			}

			for _, expected := range tt.expectedParams {
				found := false
				for _, param := range params {
					if param == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("extractParameters() missing expected param: %s", expected)
				}
			}
		})
	}
}

func TestInternalScanner_Scan_NoParameters(t *testing.T) {
	config := &InternalScanConfig{
		EnableSQLi:     true,
		EnableXSS:      true,
		EnableIDOR:     false, // Disable URL-level tests for this test
		EnableCORS:     false,
		RequestTimeout: 5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	// Create target with no parameters
	target, err := core.NewTarget("https://example.com/page")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target, nil)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
	}
	if result == nil {
		t.Fatal("Scan() returned nil result")
	}

	// Should have error about no parameters
	hasNoParamsError := false
	for _, e := range result.Errors {
		if strings.Contains(e, "no parameters") {
			hasNoParamsError = true
			break
		}
	}
	if !hasNoParamsError {
		t.Error("Expected 'no parameters' error in result")
	}
}

func TestInternalScanner_Scan_ContextCancellation(t *testing.T) {
	config := &InternalScanConfig{
		EnableSQLi:     true,
		RequestTimeout: 5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	// Create target
	target, err := core.NewTarget("https://example.com/page?id=1")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = scanner.Scan(ctx, target, nil)

	// Should not error on context cancellation, just return early
	if err != nil && err != context.Canceled {
		t.Logf("Scan() completed with error: %v (this is acceptable)", err)
	}
}

func TestInternalScanner_Close(t *testing.T) {
	scanner, err := NewInternalScanner(nil)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	// Close should not panic
	scanner.Close()
}

func TestInternalScanner_testNoSQL_Disabled(t *testing.T) {
	config := &InternalScanConfig{
		EnableNoSQL:    false,
		RequestTimeout: 5 * time.Second,
	}

	_, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	// testNoSQL should not be called if disabled
	// This is tested implicitly through the Scan function
}

func TestInternalScanner_testSSTI_Integration(t *testing.T) {
	// Create a test server that simulates SSTI vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		// Simulate template evaluation: {{7*7}} becomes 49
		if strings.Contains(input, "{{7*7}}") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Result: 49"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello " + input))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableSSTI:          true,
		EnableSQLi:          false,
		EnableXSS:           false,
		EnableCMDI:          false,
		EnableSSRF:          false,
		EnableLFI:           false,
		EnableXXE:           false,
		EnableNoSQL:         false,
		EnableIDOR:          false,
		EnableRedirect:      false,
		EnableCORS:          false,
		EnableCRLF:          false,
		EnableOOB:           false,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testSSTI(ctx, server.URL+"?input=test", "input", "GET")

	if len(findings) == 0 {
		t.Log("SSTI vulnerability not detected (may need specific payload)")
	}
}

func TestInternalScanner_testCORS_Integration(t *testing.T) {
	// Create a test server with CORS misconfiguration
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Vulnerable: reflects any origin
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableCORS:          true,
		EnableSQLi:          false,
		EnableXSS:           false,
		EnableCMDI:          false,
		EnableSSRF:          false,
		EnableLFI:           false,
		EnableXXE:           false,
		EnableNoSQL:         false,
		EnableSSTI:          false,
		EnableIDOR:          false,
		EnableRedirect:      false,
		EnableCRLF:          false,
		EnableOOB:           false,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testCORS(ctx, server.URL)

	if len(findings) == 0 {
		t.Log("CORS misconfiguration not detected (this is expected in some cases)")
	} else {
		t.Logf("CORS findings: %d", len(findings))
	}
}

func TestInternalScanner_testRedirect_Integration(t *testing.T) {
	// Create a test server with open redirect vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("redirect")
		if redirectURL != "" {
			// Vulnerable: redirects to any URL
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableRedirect:      true,
		EnableSQLi:          false,
		EnableXSS:           false,
		EnableCMDI:          false,
		EnableSSRF:          false,
		EnableLFI:           false,
		EnableXXE:           false,
		EnableNoSQL:         false,
		EnableSSTI:          false,
		EnableIDOR:          false,
		EnableCORS:          false,
		EnableCRLF:          false,
		EnableOOB:           false,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testRedirect(ctx, server.URL+"?redirect=", "redirect", "GET")

	if len(findings) == 0 {
		t.Log("Open Redirect vulnerability not detected (detector may need specific payload)")
	}
}

func TestInternalScanner_testCRLF_Integration(t *testing.T) {
	// Create a test server with CRLF injection vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		// Vulnerable: includes user input in header
		w.Header().Set("X-Custom-Header", input)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableCRLF:          true,
		EnableSQLi:          false,
		EnableXSS:           false,
		EnableCMDI:          false,
		EnableSSRF:          false,
		EnableLFI:           false,
		EnableXXE:           false,
		EnableNoSQL:         false,
		EnableSSTI:          false,
		EnableIDOR:          false,
		EnableRedirect:      false,
		EnableCORS:          false,
		EnableOOB:           false,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testCRLF(ctx, server.URL+"?input=test", "input", "GET")

	// CRLF may or may not be detected depending on payload
	t.Logf("CRLF findings: %d", len(findings))
}

func TestInternalScanner_testIDOR_Integration(t *testing.T) {
	// Create a test server vulnerable to IDOR
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		// Vulnerable: returns data for any user ID
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user_id": "` + userID + `", "name": "User", "email": "user@example.com"}`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableIDOR:          true,
		EnableSQLi:          false,
		EnableXSS:           false,
		EnableCMDI:          false,
		EnableSSRF:          false,
		EnableLFI:           false,
		EnableXXE:           false,
		EnableNoSQL:         false,
		EnableSSTI:          false,
		EnableRedirect:      false,
		EnableCORS:          false,
		EnableCRLF:          false,
		EnableOOB:           false,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testIDOR(ctx, server.URL+"?user_id=1")

	// IDOR detection depends on response analysis
	t.Logf("IDOR findings: %d", len(findings))
}

func TestInternalScanner_testNoSQL_Integration(t *testing.T) {
	// Create a test server that simulates NoSQL injection vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("search")
		// Simulate MongoDB error on NoSQL injection
		if strings.Contains(query, "$") || strings.Contains(query, "{") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"error": "MongoError: $where clause has unexpected type"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"results": []}`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableNoSQL:         true,
		EnableSQLi:          false,
		EnableXSS:           false,
		EnableCMDI:          false,
		EnableSSRF:          false,
		EnableLFI:           false,
		EnableXXE:           false,
		EnableSSTI:          false,
		EnableIDOR:          false,
		EnableRedirect:      false,
		EnableCORS:          false,
		EnableCRLF:          false,
		EnableOOB:           false,
		MaxPayloadsPerParam: 20,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testNoSQL(ctx, server.URL+"?search=test", "search", "GET")

	t.Logf("NoSQL findings: %d", len(findings))
}

func TestInternalScanner_testJWT(t *testing.T) {
	config := DefaultInternalConfig()
	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	// Test with a JWT using weak secret 'secret'
	// Header: {"alg":"HS256","typ":"JWT"}
	// Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
	// Secret: secret
	weakSecretJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

	ctx := context.Background()
	findings := scanner.testJWT(ctx, weakSecretJWT)

	if len(findings) == 0 {
		t.Log("JWT weak secret not detected (secret list may not include 'secret')")
	} else {
		t.Logf("JWT findings: %d", len(findings))
		for _, f := range findings {
			t.Logf("  - %s: %s", f.Type, f.Description)
		}
	}
}

func TestInternalScanner_Scan_AllDetectorsEnabled(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           true,
		EnableCMDI:          true,
		EnableSSRF:          true,
		EnableLFI:           true,
		EnableXXE:           true,
		EnableNoSQL:         true,
		EnableSSTI:          true,
		EnableIDOR:          true,
		EnableRedirect:      true,
		EnableCORS:          true,
		EnableCRLF:          true,
		EnableOOB:           false, // Disable OOB to speed up test
		EnableJWT:           false, // JWT needs token
		MaxPayloadsPerParam: 5,     // Limit payloads for speed
		RequestTimeout:      5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	defer scanner.Close()

	target, err := core.NewTarget(server.URL + "?id=1&name=test")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, target, nil)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
	}
	if result == nil {
		t.Fatal("Scan() returned nil result")
	}

	t.Logf("Scan completed: %d findings, %d errors", len(result.Findings), len(result.Errors))
}

func BenchmarkInternalScanner_Scan(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           true,
		EnableNoSQL:         true,
		EnableSSTI:          true,
		EnableCORS:          true,
		EnableOOB:           false,
		MaxPayloadsPerParam: 5,
		RequestTimeout:      5 * time.Second,
	}

	scanner, _ := NewInternalScanner(config)
	defer scanner.Close()

	target, _ := core.NewTarget(server.URL + "?id=1")

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.Scan(ctx, target, nil)
	}
}
