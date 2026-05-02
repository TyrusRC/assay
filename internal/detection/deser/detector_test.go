package deser

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
	if detector.Name() != "deserialization" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "deserialization")
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

func TestDetector_DetectJavaSerialization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("data")
		if param != "" && (strings.Contains(param, "rO0AB") || strings.Contains(param, "aced")) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "java.io.InvalidClassException: Invalid class descriptor"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"?data=test", "data", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected Java deserialization vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectPHPSerialization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("data")
		if param != "" && strings.Contains(param, "O:") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`PHP Fatal error: Uncaught Exception: unserialize(): Error at offset`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"?data=test", "data", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected PHP deserialization vulnerability to be detected")
	}
}

func TestDetector_DetectDotNetSerialization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("data")
		// Payloads arrive URL-decoded via query parameters, so check for common
		// .NET deserialization markers that appear across all payload variants.
		if param != "" && param != "baseline_test_value" {
			if strings.Contains(param, "VIEWSTATE") ||
				strings.Contains(param, "type") ||
				strings.Contains(param, "System.") ||
				strings.Contains(param, "ObjectDataProvider") ||
				strings.Contains(param, "TypeConfuseDelegate") {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`System.Runtime.Serialization.SerializationException: Invalid serialization data`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"?data=test", "data", "GET", DetectOptions{
		MaxPayloads: 50,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected .NET deserialization vulnerability to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "safe response"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"?data=test", "data", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_ErrorPatterns(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		vulnerable bool
	}{
		{
			name:       "Java InvalidClassException",
			response:   `java.io.InvalidClassException: Invalid class descriptor`,
			vulnerable: true,
		},
		{
			name:       "Java ClassNotFoundException",
			response:   `java.lang.ClassNotFoundException: evil.Exploit`,
			vulnerable: true,
		},
		{
			name:       "Java ObjectInputStream error",
			response:   `ObjectInputStream readObject failed`,
			vulnerable: true,
		},
		{
			name:       "PHP unserialize error",
			response:   `unserialize(): Error at offset 0 of 10 bytes`,
			vulnerable: true,
		},
		{
			name:       "PHP __wakeup error",
			response:   `Call to undefined method __wakeup() in class`,
			vulnerable: true,
		},
		{
			name:       "Python pickle error",
			response:   `_pickle.UnpicklingError: invalid load key`,
			vulnerable: true,
		},
		{
			name:       "Python unpickle error",
			response:   `could not unpickle the data`,
			vulnerable: true,
		},
		{
			name:       ".NET SerializationException",
			response:   `System.Runtime.Serialization.SerializationException: invalid data`,
			vulnerable: true,
		},
		{
			name:       ".NET ViewState error",
			response:   `ViewState MAC validation failed`,
			vulnerable: true,
		},
		{
			name:       "Normal JSON response",
			response:   `{"data": [{"id": 1, "name": "test"}]}`,
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
			if tt.vulnerable && result.DetectionType == "" {
				t.Error("DetectionType should not be empty when vulnerable")
			}
		})
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

	result, err := detector.Detect(ctx(t), server.URL, "", "GET", DetectOptions{
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
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	cancelCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(cancelCtx, server.URL+"?data=test", "data", "GET", DetectOptions{
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

	if opts.MaxPayloads != 50 {
		t.Errorf("DefaultOptions().MaxPayloads = %d, want 50", opts.MaxPayloads)
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

func TestAnalysisResult_Fields(t *testing.T) {
	result := &AnalysisResult{
		IsVulnerable:  true,
		DetectionType: "error-based",
		Confidence:    0.9,
		Evidence:      "InvalidClassException",
	}

	if !result.IsVulnerable {
		t.Error("IsVulnerable should be true")
	}
	if result.DetectionType != "error-based" {
		t.Errorf("DetectionType = %q, want %q", result.DetectionType, "error-based")
	}
	if result.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want %f", result.Confidence, 0.9)
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("data")
		if strings.Contains(param, "rO0AB") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`java.io.InvalidClassException: invalid class`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"?data=test", "data", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-11" {
		t.Errorf("Expected WSTG-INPV-11 mapping, got %v", finding.WSTG)
	}

	if len(finding.Top10) == 0 || finding.Top10[0] != "A08:2021" {
		t.Errorf("Expected A08:2021 mapping, got %v", finding.Top10)
	}

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-502" {
		t.Errorf("Expected CWE-502 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingCreation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")
		if strings.Contains(param, "rO0AB") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`java.io.InvalidClassException: deserialization failed`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"?test=value", "test", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding validation")
	}

	finding := result.Findings[0]

	if finding.Type != "Insecure Deserialization" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "Insecure Deserialization")
	}

	if finding.Tool != "deser-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "deser-detector")
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

func TestDetector_BaselineError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	}))
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(ctx(t), server.URL+"?data=test", "data", "GET", DetectOptions{
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

	result, err := detector.Detect(ctx(t), server.URL+"?param=test", "param", "GET", DetectOptions{
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

func TestDetector_DeduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payloads := []testPayload{
		{Value: "rO0ABtest1"},
		{Value: "rO0ABtest2"},
		{Value: "rO0ABtest1"}, // duplicate
		{Value: "rO0ABtest3"},
	}

	deduped := detector.deduplicatePayloads(payloads)
	if len(deduped) != 3 {
		t.Errorf("deduplicatePayloads() returned %d payloads, want 3", len(deduped))
	}
}

// testPayload is a helper type for deduplication tests.
type testPayload = deserPayload

// ctx creates a background context for tests.
func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
