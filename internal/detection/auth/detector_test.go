package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose() did not set verbose flag")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxAttempts <= 0 {
		t.Error("MaxAttempts should be positive")
	}
}

func TestDetector_DetectDefaultCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Simulate default credentials being valid
		if creds.Username == "admin" && creds.Password == "admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "token": "eyJ..."}`))
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"success": false, "error": "Invalid credentials"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectDefaultCredentials(
		context.Background(),
		server.URL,
		DetectOptions{MaxAttempts: 15},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected default credentials to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_NoDefaultCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Invalid credentials"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectDefaultCredentials(
		context.Background(),
		server.URL,
		DetectOptions{MaxAttempts: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no default credentials on secure server")
	}
}

func TestDetector_DetectUserEnumeration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Vulnerable: Different error messages for valid/invalid users
		if creds.Username == "admin" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Incorrect password"}`))
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "User not found"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectUserEnumeration(
		context.Background(),
		server.URL,
		DetectOptions{MaxAttempts: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected user enumeration to be detected")
	}
}

func TestDetector_NoUserEnumeration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same response for all users (secure)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Invalid credentials"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectUserEnumeration(
		context.Background(),
		server.URL,
		DetectOptions{MaxAttempts: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no user enumeration on secure server")
	}
}

func TestDetector_DetectMissingRateLimit(t *testing.T) {
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		// No rate limiting - always responds
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Invalid credentials"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectMissingRateLimit(
		context.Background(),
		server.URL,
		DetectOptions{RateLimitAttempts: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected missing rate limiting to be detected")
	}
}

func TestDetector_RateLimitPresent(t *testing.T) {
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount > 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "Too many requests"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Invalid credentials"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectMissingRateLimit(
		context.Background(),
		server.URL,
		DetectOptions{RateLimitAttempts: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected rate limiting to be detected as present")
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := detector.DetectDefaultCredentials(ctx, server.URL, DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_SuccessDetection(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   bool
	}{
		{name: "200 with success", statusCode: 200, body: `{"success": true}`, expected: true},
		{name: "200 with token", statusCode: 200, body: `{"token": "abc123"}`, expected: true},
		{name: "302 redirect", statusCode: 302, body: "", expected: true},
		{name: "401 unauthorized", statusCode: 401, body: `{"error": "Invalid"}`, expected: false},
		{name: "403 forbidden", statusCode: 403, body: "", expected: false},
		{name: "200 with error", statusCode: 200, body: `{"error": "Invalid credentials"}`, expected: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{
				StatusCode: tt.statusCode,
				Body:       tt.body,
			}
			result := detector.isLoginSuccess(resp)
			if result != tt.expected {
				t.Errorf("isLoginSuccess() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if creds.Username == "admin" && creds.Password == "admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token": "abc"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectDefaultCredentials(
		context.Background(),
		server.URL,
		DetectOptions{MaxAttempts: 5},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability")
	}

	finding := result.Findings[0]
	if finding.Type != "Default Credentials" {
		t.Errorf("Expected type 'Default Credentials', got %s", finding.Type)
	}
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}
