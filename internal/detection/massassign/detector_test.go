package massassign

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	if detector.Name() != "mass-assignment" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "mass-assignment")
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

func TestDetector_DetectPrivilegeEscalation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				// Not JSON, just accept
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
				return
			}

			// Vulnerable: accepts and reflects isAdmin field
			if _, ok := data["isAdmin"]; ok {
				w.WriteHeader(http.StatusOK)
				resp, _ := json.Marshal(data)
				w.Write(resp)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name": "test", "email": "test@test.com"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/user", "body", "POST", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected mass assignment vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectRoleEscalation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
				return
			}

			// Vulnerable: accepts role field
			if _, ok := data["role"]; ok {
				w.WriteHeader(http.StatusOK)
				resp, _ := json.Marshal(data)
				w.Write(resp)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name": "test"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/user", "body", "PUT", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected mass assignment role escalation to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe server: strips unknown fields
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name": "test", "email": "test@test.com"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/user", "body", "POST", DetectOptions{
		MaxPayloads: 5,
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
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL, "", "POST", DetectOptions{
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

	_, err := detector.Detect(cancelCtx, server.URL+"/api/user", "body", "POST", DetectOptions{
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

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			defer r.Body.Close()

			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err == nil {
				if _, ok := data["isAdmin"]; ok {
					w.WriteHeader(http.StatusOK)
					resp, _ := json.Marshal(data)
					w.Write(resp)
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name": "test"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/user", "body", "POST", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-20" {
		t.Errorf("Expected WSTG-INPV-20 mapping, got %v", finding.WSTG)
	}

	if len(finding.Top10) == 0 || finding.Top10[0] != "A01:2023-API" {
		t.Errorf("Expected A01:2023-API mapping, got %v", finding.Top10)
	}

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-915" {
		t.Errorf("Expected CWE-915 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingCreation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			defer r.Body.Close()

			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err == nil {
				if _, ok := data["isAdmin"]; ok {
					w.WriteHeader(http.StatusOK)
					resp, _ := json.Marshal(data)
					w.Write(resp)
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name": "test"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/user", "body", "POST", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding validation")
	}

	finding := result.Findings[0]

	if finding.Type != "Mass Assignment" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "Mass Assignment")
	}

	if finding.Tool != "massassign-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "massassign-detector")
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

	_, err := detector.Detect(ctx(t), server.URL+"/api/user", "body", "POST", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when baseline request fails")
	}
}

func TestDetector_WithNoWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name": "test"}`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/api/user", "body", "POST", DetectOptions{
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
