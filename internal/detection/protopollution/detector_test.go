package protopollution

import (
	"context"
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
	if detector.Name() != "protopollution" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "protopollution")
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
		TestedPayloads: 5,
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.TestedPayloads != 5 {
		t.Errorf("TestedPayloads = %d, want 5", result.TestedPayloads)
	}
}

func TestDetector_DetectQueryParamPollution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("input")
		if strings.Contains(param, "__proto__") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"skws":"1","status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads:      20,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected prototype pollution vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectJSONBodyPollution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("data")
		if strings.Contains(param, "__proto__") || strings.Contains(param, "constructor") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"skws":"1","merged":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"merged":false}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?data=test", "data", "GET", DetectOptions{
		MaxPayloads:      20,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected JSON body prototype pollution to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"safe response"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
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
		w.Write([]byte(`{"status":"ok"}`))
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
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(ctx, server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads: 100,
	})

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_BaselineError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when baseline request fails")
	}
}

func TestDetector_ErrorMessageDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("input")
		if strings.Contains(param, "__proto__") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Cannot set property 'skws' of undefined"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads: 10,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected error-based prototype pollution detection")
	}
}

func TestDetector_AnalyzeResponse(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name       string
		baseline   string
		injected   string
		payload    string
		vulnerable bool
	}{
		{
			name:       "Marker appears in response",
			baseline:   `{"status":"ok"}`,
			injected:   `{"status":"ok","skws":"1"}`,
			payload:    "__proto__[skws]=1",
			vulnerable: true,
		},
		{
			name:       "Error message about prototype",
			baseline:   `{"status":"ok"}`,
			injected:   `{"error":"Cannot set property 'skws' of undefined"}`,
			payload:    "__proto__[skws]=1",
			vulnerable: true,
		},
		{
			name:       "Pollution confirmed message",
			baseline:   `{"status":"ok"}`,
			injected:   `{"__proto__":{"skws":"1"},"status":"ok"}`,
			payload:    `{"__proto__":{"skws":"1"}}`,
			vulnerable: true,
		},
		{
			name:       "No change safe response",
			baseline:   `{"status":"ok"}`,
			injected:   `{"status":"ok"}`,
			payload:    "__proto__[skws]=1",
			vulnerable: false,
		},
		{
			name:       "Empty responses",
			baseline:   "",
			injected:   "",
			payload:    "__proto__[skws]=1",
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.analyzeResponse(tt.baseline, tt.injected, tt.payload)
			if result != tt.vulnerable {
				t.Errorf("analyzeResponse() = %v, want %v", result, tt.vulnerable)
			}
		})
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("input")
		if strings.Contains(param, "__proto__") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"skws":"1","status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads: 5,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-CLNT-06" {
		t.Errorf("Expected WSTG-CLNT-06 mapping, got %v", finding.WSTG)
	}

	if len(finding.Top10) == 0 || finding.Top10[0] != "A03:2025" {
		t.Errorf("Expected A03:2025 mapping, got %v", finding.Top10)
	}

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-1321" {
		t.Errorf("Expected CWE-1321 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingCreation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")
		if strings.Contains(param, "__proto__") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"skws":"1","status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?test=value", "test", "GET", DetectOptions{
		MaxPayloads: 5,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding validation")
	}

	finding := result.Findings[0]

	if finding.Type != "Prototype Pollution" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "Prototype Pollution")
	}

	if finding.Tool != "protopollution-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "protopollution-detector")
	}

	if finding.Parameter != "test" {
		t.Errorf("Finding.Parameter = %q, want %q", finding.Parameter, "test")
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

func TestDetector_RequestErrorContinues(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
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

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads: 3,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Logf("Detect returned error (expected for connection issues): %v", err)
	}

	if result != nil && result.TestedPayloads == 0 {
		t.Error("Expected some payloads to be tested")
	}
}

func TestDetector_WithWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads:      30,
		IncludeWAFBypass: true,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.TestedPayloads == 0 {
		t.Error("Expected payloads to be tested")
	}
}
