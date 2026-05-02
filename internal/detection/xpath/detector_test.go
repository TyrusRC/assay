package xpath

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

	if opts.MaxPayloads <= 0 {
		t.Error("MaxPayloads should be positive")
	}
}

func TestDetector_DetectXPathErrorBased(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("name")
		if strings.Contains(input, "'") || strings.Contains(input, "\"") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("XPathException: Invalid expression - unterminated string"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Result: user data"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?name=admin",
		"name", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected XPath injection to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectXPathBoolBased(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("user")
		if strings.Contains(input, "' or '1'='1") || strings.Contains(input, "true()") {
			// Boolean true condition returns all data
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin\nroot\njohn\njane\nuser1\nuser2\nuser3\nuser4\nuser5\nuser6"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("admin"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?user=admin",
		"user", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected boolean-based XPath injection to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?name=test",
		"name", "GET",
		DetectOptions{MaxPayloads: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
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

	_, err := detector.Detect(ctx, server.URL+"?name=test", "name", "GET", DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_ErrorPatternDetection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{name: "XPathException", body: "XPathException: syntax error", expected: true},
		{name: "DOMXPath", body: "DOMXPath::query() failed", expected: true},
		{name: "lxml.etree", body: "lxml.etree.XPathEvalError", expected: true},
		{name: "unterminated string", body: "Error: unterminated string literal", expected: true},
		{name: "normal response", body: "User profile page", expected: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasXPathError(tt.body)
			if result != tt.expected {
				t.Errorf("hasXPathError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		if strings.Contains(input, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("XPath error: invalid predicate"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?q=test",
		"q", "GET",
		DetectOptions{MaxPayloads: 5},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability")
	}

	finding := result.Findings[0]
	if finding.Type != "XPath Injection" {
		t.Errorf("Expected type 'XPath Injection', got %s", finding.Type)
	}
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}
