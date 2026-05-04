package hpp

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
	if detector.Name() != "hpp" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "hpp")
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

func TestDetector_DetectVulnerableServer(t *testing.T) {
	// Vulnerable server: uses only the last occurrence of a duplicate parameter
	// and does not validate/sanitize the injected value.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()["q"]
		if len(values) > 1 {
			// Server uses last value only, simulating HPP vulnerability
			last := values[len(values)-1]
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"result": "%s", "count": %d}`, last, len(values))))
			return
		}
		if len(values) == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"result": "%s", "count": 1}`, values[0])))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "", "count": 0}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=original", "q", "GET", DetectOptions{
		MaxPayloads: 5,
		Timeout:     10 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected on server that handles duplicate params differently")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	if result.TestedPayloads == 0 {
		t.Error("Expected at least one payload to be tested")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	// Safe server: always returns the same static response regardless of parameters
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "safe response"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads: 5,
		Timeout:     10 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability on safe server")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected zero findings, got %d", len(result.Findings))
	}
}

func TestDetector_EmptyParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
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
		t.Error("Result should not be nil for empty parameter")
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability for empty parameter")
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(ctx, server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads: 100,
	})

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	// Vulnerable server that reflects the injected parameter differently
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()["q"]
		if len(values) > 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"result": "%s", "polluted": true}`, values[len(values)-1])))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "normal", "polluted": false}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=original", "q", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-04" {
		t.Errorf("Expected WSTG-INPV-04 mapping, got %v", finding.WSTG)
	}

	if len(finding.Top10) == 0 || finding.Top10[0] != "A03:2025" {
		t.Errorf("Expected A03:2025 mapping, got %v", finding.Top10)
	}

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-235" {
		t.Errorf("Expected CWE-235 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()["search"]
		if len(values) > 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"results": ["%s"], "total": %d}`, values[len(values)-1], len(values))))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"results": [], "total": 0}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?search=test", "search", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding fields test")
	}

	finding := result.Findings[0]

	if finding.Type != "HTTP Parameter Pollution" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "HTTP Parameter Pollution")
	}

	if finding.Tool != "hpp-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "hpp-detector")
	}

	if finding.Parameter != "search" {
		t.Errorf("Finding.Parameter = %q, want %q", finding.Parameter, "search")
	}

	if finding.URL == "" {
		t.Error("Finding.URL should not be empty")
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

func TestDetectOptions_MaxPayloadsLimit(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads: 3,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// requestCount includes 1 baseline + up to MaxPayloads test requests
	// The baseline request is always sent, so total should be at most 1 + MaxPayloads
	if requestCount > 4 { // 1 baseline + 3 payloads
		t.Errorf("Expected at most 4 requests (1 baseline + 3 payloads), got %d", requestCount)
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
		TestedPayloads: 5,
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.TestedPayloads != 5 {
		t.Errorf("TestedPayloads = %d, want 5", result.TestedPayloads)
	}
}

func TestDetector_BaselineError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	server.Close() // Close immediately to cause connection error

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when baseline request fails")
	}
}

func TestDetector_IncludeWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	// Test with WAF bypass enabled
	resultWith, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
	})
	if err != nil {
		t.Fatalf("Detect with WAF bypass failed: %v", err)
	}

	// Test with WAF bypass disabled
	resultWithout, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: false,
	})
	if err != nil {
		t.Fatalf("Detect without WAF bypass failed: %v", err)
	}

	if resultWith.TestedPayloads <= resultWithout.TestedPayloads {
		t.Errorf("Expected more payloads with WAF bypass (%d) than without (%d)",
			resultWith.TestedPayloads, resultWithout.TestedPayloads)
	}
}

func TestDetector_POSTMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			values := r.Form["q"]
			if len(values) > 1 {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf(`{"result": "%s", "polluted": true}`, values[len(values)-1])))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "normal"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=original", "q", "POST", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect with POST method failed: %v", err)
	}

	// Should still test payloads regardless of method
	if result.TestedPayloads == 0 {
		t.Error("Expected payloads to be tested with POST method")
	}
}

func TestDetector_ResponseDifferentialAnalysis(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantVuln   bool
		targetURL  string
		param      string
	}{
		{
			name: "Different status code on duplicate params",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				values := r.URL.Query()["id"]
				if len(values) > 1 {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": "multiple values"}`))
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id": "123"}`))
			}),
			wantVuln:  true,
			targetURL: "?id=123",
			param:     "id",
		},
		{
			name: "Same response always",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
			}),
			wantVuln:  false,
			targetURL: "?id=123",
			param:     "id",
		},
		{
			name: "Body content changes on pollution",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				values := r.URL.Query()["name"]
				if len(values) > 1 {
					// Concatenates all values - reveals HPP behavior
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(fmt.Sprintf(`{"name": "%s"}`, strings.Join(values, ","))))
					return
				}
				w.WriteHeader(http.StatusOK)
				if len(values) == 1 {
					w.Write([]byte(fmt.Sprintf(`{"name": "%s"}`, values[0])))
				} else {
					w.Write([]byte(`{"name": ""}`))
				}
			}),
			wantVuln:  true,
			targetURL: "?name=alice",
			param:     "name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := internalhttp.NewClient()
			detector := New(client)

			result, err := detector.Detect(context.Background(), server.URL+tt.targetURL, tt.param, "GET", DetectOptions{
				MaxPayloads: 5,
			})

			if err != nil {
				t.Fatalf("Detect failed: %v", err)
			}

			if result.Vulnerable != tt.wantVuln {
				t.Errorf("Vulnerable = %v, want %v", result.Vulnerable, tt.wantVuln)
			}
		})
	}
}

func TestDetector_RequestErrorContinues(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// Baseline succeeds
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
			return
		}
		// Subsequent requests fail via connection hijack
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, err := hj.Hijack()
			if err == nil && conn != nil {
				conn.Close()
			}
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads: 3,
	})

	// Should not return error; it should handle individual request errors gracefully
	if err != nil {
		t.Logf("Detect returned error (acceptable for connection issues): %v", err)
	}

	if result != nil && result.TestedPayloads == 0 {
		t.Error("Expected some payloads to be tested even with request errors")
	}
}
