package cssinj

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	if detector.Name() != "cssinj" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "cssinj")
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

func TestDetector_DetectVulnerable(t *testing.T) {
	// Server that reflects CSS input in a style context without sanitization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		color := r.URL.Query().Get("color")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><style>body { color: ` + color + `; }</style></head></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 10,
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

func TestDetector_DetectSafe(t *testing.T) {
	// Server that strips CSS injection payloads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		color := r.URL.Query().Get("color")
		// Strip all non-alphanumeric characters except # (for hex colors)
		safe := ""
		for _, c := range color {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '#' {
				safe += string(c)
			}
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><style>body { color: ` + safe + `; }</style></head></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_EmptyParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
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

	if result == nil {
		t.Error("Result should not be nil")
	}

	if result.Vulnerable {
		t.Error("Empty parameter should not yield vulnerability")
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(ctx, server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 100,
	})

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_MaxPayloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 3,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.TestedPayloads > 3 {
		t.Errorf("TestedPayloads = %d, should be <= 3", result.TestedPayloads)
	}
}

func TestDetector_WithWAFBypass(t *testing.T) {
	// Server that blocks standard CSS payloads but allows comment-based bypass
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("color")
		if strings.Contains(input, "expression(") || strings.Contains(input, "@import") ||
			strings.Contains(input, "url(") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("blocked"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<style>body{color:` + input + `}</style>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads:      20,
		IncludeWAFBypass: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected WAF bypass to detect vulnerability")
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("color")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<style>body{color:` + input + `}</style>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-CLNT-05" {
		t.Errorf("Expected WSTG-CLNT-05 mapping, got %v", finding.WSTG)
	}

	if len(finding.Top10) == 0 || finding.Top10[0] != "A03:2021" {
		t.Errorf("Expected A03:2021 mapping, got %v", finding.Top10)
	}

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-1236" {
		t.Errorf("Expected CWE-1236 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("color")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<style>body{color:` + input + `}</style>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding validation")
	}

	finding := result.Findings[0]

	if finding.Type != "CSS Injection" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "CSS Injection")
	}
	if finding.Tool != "cssinj-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "cssinj-detector")
	}
	if finding.Parameter != "color" {
		t.Errorf("Finding.Parameter = %q, want %q", finding.Parameter, "color")
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

func TestDetector_BaselineError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when baseline request fails")
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

	if opts.MaxPayloads != 20 {
		t.Errorf("DefaultOptions().MaxPayloads = %d, want 20", opts.MaxPayloads)
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
		TestedPayloads: 7,
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.TestedPayloads != 7 {
		t.Errorf("TestedPayloads = %d, want 7", result.TestedPayloads)
	}
}

func TestDetector_RequestError(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("baseline"))
			return
		}
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

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "GET", DetectOptions{
		MaxPayloads: 3,
	})

	if err != nil {
		t.Logf("Detect returned error (expected for connection issues): %v", err)
	}

	if result != nil && result.TestedPayloads == 0 {
		t.Error("Expected some payloads to be tested")
	}
}

func TestDetector_POSTMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		color := r.FormValue("color")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<style>body{color:` + color + `}</style>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?color=red", "color", "POST", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability via POST method")
	}
}
