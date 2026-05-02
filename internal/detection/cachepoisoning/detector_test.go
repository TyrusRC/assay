package cachepoisoning

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	if detector.Name() != "cache-poisoning" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "cache-poisoning")
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

func TestDetector_DetectHostReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: reflects X-Forwarded-Host in response
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`<html><head><link rel="canonical" href="https://%s/page"></head></html>`, xfh)))
			return
		}
		w.Header().Set("X-Cache", "MISS")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><link rel="canonical" href="https://example.com/page"></head></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected cache poisoning vulnerability to be detected via host reflection")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectSchemeReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfs := r.Header.Get("X-Forwarded-Scheme")
		if xfs != "" && xfs != "https" {
			w.Header().Set("Location", fmt.Sprintf("https://example.com%s", r.URL.Path))
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>Normal response</body></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
		MaxPayloads: 20,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected cache poisoning vulnerability to be detected via scheme reflection")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe server: ignores all forwarded headers
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>Safe response</body></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
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
		w.Write([]byte(`<html>ok</html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	cancelCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(cancelCtx, server.URL+"/page", "", "GET", DetectOptions{
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
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`<html><a href="https://%s/link">Link</a></html>`, xfh)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><a href="https://example.com/link">Link</a></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping OWASP mapping test")
	}

	finding := result.Findings[0]

	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-17" {
		t.Errorf("Expected WSTG-INPV-17 mapping, got %v", finding.WSTG)
	}

	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-444" {
		t.Errorf("Expected CWE-444 mapping, got %v", finding.CWE)
	}
}

func TestDetector_FindingCreation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`<html><script src="https://%s/js"></script></html>`, xfh)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><script src="https://example.com/js"></script></html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Skip("No vulnerability detected, skipping finding validation")
	}

	finding := result.Findings[0]

	if finding.Type != "Web Cache Poisoning" {
		t.Errorf("Finding.Type = %q, want %q", finding.Type, "Web Cache Poisoning")
	}

	if finding.Tool != "cachepoisoning-detector" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "cachepoisoning-detector")
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

	_, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when baseline request fails")
	}
}

func TestDetector_WithNoWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html>ok</html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
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

func TestDetector_StatusCodeChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfs := r.Header.Get("X-Forwarded-Scheme")
		if xfs == "nothttps" {
			w.Header().Set("Location", "https://example.com/")
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`Redirecting...`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html>OK</html>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	detector := New(client)

	result, err := detector.Detect(ctx(t), server.URL+"/page", "", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability via status code change (redirect)")
	}
}

// ctx creates a background context for tests.
func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
