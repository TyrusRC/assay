package headerinj

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
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

func TestDetector_DetectHeaderInjection(t *testing.T) {
	// Server that reflects input into response headers (simulating CRLF vulnerability)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect")
		if redirect != "" {
			// Simulate vulnerable header injection:
			// Check for both raw and URL-encoded CRLF
			if strings.Contains(redirect, "\r\n") || strings.Contains(redirect, "\n") ||
				strings.Contains(redirect, "%0d%0a") || strings.Contains(redirect, "%0a") ||
				strings.Contains(redirect, "X-Injected") {
				w.Header().Set("X-Injected", "true")
			}
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?redirect=https://safe.com",
		"redirect", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected header injection to be detected")
	}
}

func TestDetector_DetectCRLFInBody(t *testing.T) {
	// Server that reflects CRLF payload in response body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("name")
		if strings.Contains(input, "\r\n") || strings.Contains(input, "\n") {
			// Reflects the payload including the injected content
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello " + input))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello " + input))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?name=user",
		"name", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected CRLF injection in body to be detected")
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
		server.URL+"?input=test",
		"input", "GET",
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

	_, err := detector.Detect(ctx, server.URL+"?input=test", "input", "GET", DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("url")
		if strings.Contains(input, "\r\n") || strings.Contains(input, "\n") ||
			strings.Contains(input, "%0d%0a") || strings.Contains(input, "%0a") ||
			strings.Contains(input, "X-Injected") {
			w.Header().Set("X-Injected", "true")
		}
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?url=https://safe.com",
		"url", "GET",
		DetectOptions{MaxPayloads: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability")
	}

	finding := result.Findings[0]
	if finding.Type != "HTTP Header Injection" {
		t.Errorf("Expected type 'HTTP Header Injection', got %s", finding.Type)
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}

func TestDetector_InjectedHeaderCheck(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		marker   string
		expected bool
	}{
		{name: "injected header present", headers: map[string]string{"X-Injected": "true"}, marker: "X-Injected", expected: true},
		{name: "no injected header", headers: map[string]string{"Content-Type": "text/html"}, marker: "X-Injected", expected: false},
		{name: "empty marker", headers: map[string]string{}, marker: "", expected: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasInjectedHeader(tt.headers, tt.marker)
			if result != tt.expected {
				t.Errorf("hasInjectedHeader() = %v, want %v", result, tt.expected)
			}
		})
	}
}
