package domclobber

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
	if detector.Name() != "domclobber" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "domclobber")
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
		TestedPayloads: 7,
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.TestedPayloads != 7 {
		t.Errorf("TestedPayloads = %d, want 7", result.TestedPayloads)
	}
}

func TestDetector_DetectFormClobbering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("input")
		if strings.Contains(param, "<form") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><form id=x>reflected</form></body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>safe</body></html>`))
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
		t.Error("Expected DOM clobbering vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectImgClobbering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("data")
		if strings.Contains(param, "<img") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><img name=x>reflected</body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>safe</body></html>`))
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
		t.Error("Expected img-based DOM clobbering to be detected")
	}
}

func TestDetector_DetectAnchorClobbering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		if strings.Contains(param, "<a") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><a id=x name=x>reflected</a></body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>safe</body></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      20,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected anchor-based DOM clobbering to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>safe response</body></html>`))
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
		w.Write([]byte(`<html><body>ok</body></html>`))
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
		w.Write([]byte(`<html><body>ok</body></html>`))
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
		w.Write([]byte(`ok`))
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
			name:       "Form element reflected",
			baseline:   `<html><body>safe</body></html>`,
			injected:   `<html><body><form id=x>reflected</form></body></html>`,
			payload:    `<form id=x>`,
			vulnerable: true,
		},
		{
			name:       "Img element reflected",
			baseline:   `<html><body>safe</body></html>`,
			injected:   `<html><body><img name=x>reflected</body></html>`,
			payload:    `<img name=x>`,
			vulnerable: true,
		},
		{
			name:       "Anchor element reflected",
			baseline:   `<html><body>safe</body></html>`,
			injected:   `<html><body><a id=x name=x>reflected</a></body></html>`,
			payload:    `<a id=x name=x>`,
			vulnerable: true,
		},
		{
			name:       "Payload not reflected",
			baseline:   `<html><body>safe</body></html>`,
			injected:   `<html><body>safe</body></html>`,
			payload:    `<form id=x>`,
			vulnerable: false,
		},
		{
			name:       "Payload encoded and not effective",
			baseline:   `<html><body>safe</body></html>`,
			injected:   `<html><body>&lt;form id=x&gt;</body></html>`,
			payload:    `<form id=x>`,
			vulnerable: false,
		},
		{
			name:       "Empty responses",
			baseline:   "",
			injected:   "",
			payload:    `<form id=x>`,
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
		if strings.Contains(param, "<form") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><form id=x></form></body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>safe</body></html>`))
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

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-79" {
		t.Errorf("Expected CWE-79 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingCreation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")
		if strings.Contains(param, "<form") || strings.Contains(param, "<img") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><form id=x></form></body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>safe</body></html>`))
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

	if finding.Type != "DOM Clobbering" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "DOM Clobbering")
	}

	if finding.Tool != "domclobber-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "domclobber-detector")
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
			w.Write([]byte(`<html><body>ok</body></html>`))
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
		w.Write([]byte(`<html><body>safe</body></html>`))
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

func TestDetector_HTMLEncodedNotVulnerable(t *testing.T) {
	// Server HTML-encodes input, so DOM clobbering should not be detected
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("input")
		// HTML-encode the output
		encoded := strings.ReplaceAll(param, "<", "&lt;")
		encoded = strings.ReplaceAll(encoded, ">", "&gt;")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` + encoded + `</body></html>`))
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

	if result.Vulnerable {
		t.Error("Expected no vulnerability when server HTML-encodes output")
	}
}
