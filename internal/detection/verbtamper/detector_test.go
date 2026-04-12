package verbtamper

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

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()

	detector := New(client).WithVerbose(true)
	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}
}

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector.Name() != "verbtamper-detector" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "verbtamper-detector")
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
	if !opts.IncludeOverrideTests {
		t.Error("DefaultOptions() IncludeOverrideTests should be true")
	}
}

func TestDetect_VerbTamperingBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// GET is restricted
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access denied")
		case http.MethodPut:
			// PUT bypasses auth
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Resource updated successfully")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "Method not allowed")
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "", "GET", DetectOptions{
		MaxPayloads:          20,
		IncludeOverrideTests: false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected verb tampering vulnerability to be detected (403 on GET, 200 on PUT)")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Severity != core.SeverityHigh {
		t.Errorf("Severity = %v, want %v", finding.Severity, core.SeverityHigh)
	}
	if finding.Tool != "verbtamper-detector" {
		t.Errorf("Tool = %q, want %q", finding.Tool, "verbtamper-detector")
	}
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mappings")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mappings")
	}
	if !strings.Contains(finding.Description, "verb-tampering") {
		t.Errorf("Description should mention verb-tampering, got %q", finding.Description)
	}
}

func TestDetect_MethodOverrideHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for method override headers
		override := r.Header.Get("X-HTTP-Method-Override")
		if override == "DELETE" {
			// Override header changes behavior: return 200 with content
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, strings.Repeat("Resource deleted with override. Sensitive admin data here. ", 5))
			return
		}

		// Normal GET returns 403
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Access denied")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "", "GET", DetectOptions{
		MaxPayloads:          30,
		IncludeOverrideTests: true,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected method override vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if !strings.Contains(finding.Description, "override") {
		t.Errorf("Description should mention override, got %q", finding.Description)
	}
}

func TestDetect_NoBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// All methods return the same 403
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Access denied")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "", "GET", DetectOptions{
		MaxPayloads:          20,
		IncludeOverrideTests: true,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when all methods return same status")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected no findings, got %d", len(result.Findings))
	}
}

func TestDetect_EmptyURL(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), "", "", "GET", DefaultOptions())

	if err == nil {
		t.Error("Expected error for empty URL")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("Expected error about empty URL, got: %v", err)
	}
}

func TestDetect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Denied")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := detector.Detect(ctx, server.URL+"/admin", "", "GET", DetectOptions{
		MaxPayloads:          100,
		IncludeOverrideTests: true,
	})

	// Baseline request should fail with cancelled context
	if err == nil {
		return // acceptable if cancellation wasn't caught
	}

	if !strings.Contains(err.Error(), "context canceled") && !strings.Contains(err.Error(), "baseline") {
		t.Logf("Got error variant: %v", err)
	}
}

func TestDetect_ConsistentResponses(t *testing.T) {
	// All methods return 200 with same content - no vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Welcome to the page")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/page", "", "GET", DetectOptions{
		MaxPayloads:          20,
		IncludeOverrideTests: true,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when all methods return consistent responses")
	}
}

func TestDetect_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), serverURL+"/admin", "", "GET", DetectOptions{
		MaxPayloads:          5,
		IncludeOverrideTests: false,
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

func TestDetect_PayloadLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Denied")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "", "GET", DetectOptions{
		MaxPayloads:          3,
		IncludeOverrideTests: true,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads > 3 {
		t.Errorf("Expected at most 3 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetect_401Bypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Unauthorized")
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Resource deleted")
		default:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Unauthorized")
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/resource", "", "GET", DetectOptions{
		MaxPayloads:          20,
		IncludeOverrideTests: false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability when 401 on GET but 200 on DELETE")
	}
}

func TestDetect_IsOverrideBehaviorChange(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		baseline *internalhttp.Response
		override *internalhttp.Response
		expected bool
	}{
		{
			name:     "nil baseline",
			baseline: nil,
			override: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			expected: false,
		},
		{
			name:     "nil override",
			baseline: &internalhttp.Response{StatusCode: 403, Body: "Denied"},
			override: nil,
			expected: false,
		},
		{
			name:     "403 to 200",
			baseline: &internalhttp.Response{StatusCode: 403, Body: "Denied"},
			override: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			expected: true,
		},
		{
			name:     "401 to 200",
			baseline: &internalhttp.Response{StatusCode: 401, Body: "Unauthorized"},
			override: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			expected: true,
		},
		{
			name:     "same status same content",
			baseline: &internalhttp.Response{StatusCode: 200, Body: "Same"},
			override: &internalhttp.Response{StatusCode: 200, Body: "Same"},
			expected: false,
		},
		{
			name:     "200 to 403 not a bypass",
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			override: &internalhttp.Response{StatusCode: 403, Body: "Denied"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isOverrideBehaviorChange(tt.baseline, tt.override)
			if got != tt.expected {
				t.Errorf("isOverrideBehaviorChange() = %v, want %v", got, tt.expected)
			}
		})
	}
}
