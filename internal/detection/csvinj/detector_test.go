package csvinj

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector.Name() != "csvinj" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "csvinj")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads <= 0 {
		t.Error("DefaultOptions() MaxPayloads should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()

	detector := New(client).WithVerbose(true)
	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}

	detector2 := New(client).WithVerbose(false)
	if detector2.verbose {
		t.Error("WithVerbose(false) should leave verbose as false")
	}
}

func TestDetector_Detect_Vulnerable(t *testing.T) {
	// Server that reflects input without sanitization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("name")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Hello, %s! Welcome to our site.", input)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?name=test", "name", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	// Verify finding properties
	if result.Vulnerable {
		finding := result.Findings[0]
		if finding.Severity != core.SeverityMedium {
			t.Errorf("Severity = %v, want %v", finding.Severity, core.SeverityMedium)
		}
		if finding.Tool != "csvinj-detector" {
			t.Errorf("Tool = %q, want %q", finding.Tool, "csvinj-detector")
		}
		if len(finding.WSTG) == 0 {
			t.Error("Expected WSTG mappings")
		}
		if len(finding.CWE) == 0 {
			t.Error("Expected CWE mappings")
		}
		if finding.Remediation == "" {
			t.Error("Expected non-empty Remediation")
		}
	}
}

func TestDetector_Detect_SafeServer(t *testing.T) {
	// Server that does NOT reflect input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Static safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?name=test", "name", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result.Findings))
	}
}

func TestDetector_Detect_SanitizedReflection(t *testing.T) {
	// Server that sanitizes formula characters by stripping them
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("name")
		// Sanitize by removing formula chars entirely
		if len(input) > 0 {
			first := input[0]
			if first == '=' || first == '+' || first == '-' || first == '@' {
				input = input[1:]
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Data: %s", input)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?name=test", "name", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when input is sanitized")
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := detector.Detect(ctx, server.URL+"?name=test", "name", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	// Either baseline fails or context cancellation
	if err == nil {
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
	}
}

func TestDetector_Detect_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), serverURL+"?name=test", "name", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when server is down")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "failed to get baseline") {
		t.Errorf("Expected baseline error, got: %v", err)
	}
}

func TestDetector_Detect_PayloadLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?name=test", "name", "GET", DetectOptions{
		MaxPayloads: 2,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads > 2 {
		t.Errorf("Expected at most 2 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_MultipleFindings(t *testing.T) {
	// Server that reflects all input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("comment")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Your comment: %s", input)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?comment=test", "comment", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected")
	}

	// Should find multiple vulnerable payloads since all are reflected
	if len(result.Findings) < 2 {
		t.Errorf("Expected multiple findings, got %d", len(result.Findings))
	}
}

func TestDetector_isReflectedUnescaped(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		baseline string
		payload  string
		expected bool
	}{
		{
			name:     "equals formula reflected",
			body:     "Data: =CMD()",
			baseline: "Data: baseline_test_value",
			payload:  "=CMD()",
			expected: true,
		},
		{
			name:     "plus formula reflected",
			body:     `Data: +CMD("calc")`,
			baseline: "Data: baseline_test_value",
			payload:  `+CMD("calc")`,
			expected: true,
		},
		{
			name:     "minus formula reflected",
			body:     "Data: -1+1",
			baseline: "Data: baseline_test_value",
			payload:  "-1+1",
			expected: true,
		},
		{
			name:     "at formula reflected",
			body:     "Data: @SUM(1+1)",
			baseline: "Data: baseline_test_value",
			payload:  "@SUM(1+1)",
			expected: true,
		},
		{
			name:     "payload not in body",
			body:     "Data: safe value",
			baseline: "Data: baseline_test_value",
			payload:  "=CMD()",
			expected: false,
		},
		{
			name:     "payload in baseline too",
			body:     "Data: =CMD()",
			baseline: "Data: =CMD()",
			payload:  "=CMD()",
			expected: false,
		},
		{
			name:     "non-formula payload",
			body:     "Data: hello",
			baseline: "Data: baseline_test_value",
			payload:  "hello",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isReflectedUnescaped(tt.body, tt.baseline, tt.payload)
			if got != tt.expected {
				t.Errorf("isReflectedUnescaped() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payload := formulaPayload{
		Value:       "=CMD()",
		Description: "Excel CMD formula",
	}

	resp := &internalhttp.Response{
		StatusCode: 200,
		Body:       "Data: =CMD()",
	}

	finding := detector.createFinding("http://example.com/export", "name", payload, resp)

	if finding == nil {
		t.Fatal("createFinding() returned nil")
	}
	if finding.Severity != core.SeverityMedium {
		t.Errorf("Severity = %v, want %v", finding.Severity, core.SeverityMedium)
	}
	if finding.Tool != "csvinj-detector" {
		t.Errorf("Tool = %q, want %q", finding.Tool, "csvinj-detector")
	}
	if finding.URL != "http://example.com/export" {
		t.Errorf("URL = %q, want %q", finding.URL, "http://example.com/export")
	}
	if finding.Parameter != "name" {
		t.Errorf("Parameter = %q, want %q", finding.Parameter, "name")
	}
	if finding.Description == "" {
		t.Error("Expected non-empty Description")
	}
	if finding.Evidence == "" {
		t.Error("Expected non-empty Evidence")
	}
	if finding.Remediation == "" {
		t.Error("Expected non-empty Remediation")
	}
	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-15" {
		t.Error("Expected WSTG-INPV-15 mapping")
	}
	if len(finding.Top10) == 0 || finding.Top10[0] != "A03:2021" {
		t.Error("Expected A03:2021 mapping")
	}
	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-1236" {
		t.Error("Expected CWE-1236 mapping")
	}
}

func TestDetector_createFinding_LongBody(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payload := formulaPayload{
		Value:       "=CMD()",
		Description: "Excel CMD formula",
	}

	resp := &internalhttp.Response{
		StatusCode: 200,
		Body:       strings.Repeat("A", 600),
	}

	finding := detector.createFinding("http://example.com/export", "name", payload, resp)

	if finding == nil {
		t.Fatal("createFinding() returned nil")
	}
	if !strings.Contains(finding.Evidence, "...") {
		t.Error("Expected truncation indicator for long body")
	}
}

func TestDetector_Detect_HTTPErrorDuringPayload(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// Baseline succeeds
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("baseline"))
			return
		}
		// Subsequent requests: close connection
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?name=test", "name", "GET", DetectOptions{
		MaxPayloads: 3,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should handle errors gracefully
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}
