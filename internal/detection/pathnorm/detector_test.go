package pathnorm

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

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector.Name() != "pathnorm" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "pathnorm")
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

func TestDetector_Detect_BypassFound(t *testing.T) {
	// Server that returns 403 for /admin but 200 for bypass paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden"))
			return
		}

		// Any other path (bypass attempts) returns 200
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Admin Panel Content"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
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
		if finding.Tool != "pathnorm-detector" {
			t.Errorf("Tool = %q, want %q", finding.Tool, "pathnorm-detector")
		}
		if len(finding.WSTG) == 0 {
			t.Error("Expected WSTG mappings")
		}
		if len(finding.Top10) == 0 {
			t.Error("Expected Top10 mappings")
		}
		if len(finding.CWE) == 0 {
			t.Error("Expected CWE mappings")
		}
		if finding.Remediation == "" {
			t.Error("Expected non-empty Remediation")
		}
	}
}

func TestDetector_Detect_NoBypass(t *testing.T) {
	// Server that returns 403 for all paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when all paths return 403")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result.Findings))
	}
}

func TestDetector_Detect_OriginalReturns200(t *testing.T) {
	// Server that returns 200 for everything - no bypass needed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when original returns 200")
	}

	// Should not even test payloads since original is 200
	if result.TestedPayloads != 0 {
		t.Errorf("Expected 0 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := detector.Detect(ctx, server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	// Either the original request fails or context cancellation is returned
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

	result, err := detector.Detect(context.Background(), serverURL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when server is down")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "failed to get original response") {
		t.Errorf("Expected original response error, got: %v", err)
	}
}

func TestDetector_Detect_PayloadLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 2,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads > 2 {
		t.Errorf("Expected at most 2 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_401Unauthorized(t *testing.T) {
	// Server that returns 401 for /admin but 200 for bypass paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("401 Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Admin Panel"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected for 401 bypass")
	}
}

func TestDetector_Detect_EmptyParam(t *testing.T) {
	// When param is empty, the detector should use the path from the URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Bypassed"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected with empty param")
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payload := bypassPayload{
		Template:    "..;/%s",
		Description: "Semicolon path traversal",
	}

	originalResp := &internalhttp.Response{StatusCode: 403, Body: "Forbidden"}
	bypassResp := &internalhttp.Response{StatusCode: 200, Body: "Admin Panel"}

	finding := detector.createFinding("http://example.com/admin", "http://example.com/..;/admin", payload, originalResp, bypassResp)

	if finding == nil {
		t.Fatal("createFinding() returned nil")
	}
	if finding.Tool != "pathnorm-detector" {
		t.Errorf("Tool = %q, want %q", finding.Tool, "pathnorm-detector")
	}
	if finding.URL != "http://example.com/admin" {
		t.Errorf("URL = %q, want %q", finding.URL, "http://example.com/admin")
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
	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-ATHZ-02" {
		t.Error("Expected WSTG-ATHZ-02 mapping")
	}
	if len(finding.Top10) == 0 || finding.Top10[0] != "A01:2021" {
		t.Error("Expected A01:2021 mapping")
	}
	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-22" {
		t.Error("Expected CWE-22 mapping")
	}
}
