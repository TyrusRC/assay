package secheaders

import (
	"context"
	"net/http"
	"net/http/httptest"
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
		t.Error("client not set correctly")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose() did not set verbose flag")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
	if !opts.CheckRequired {
		t.Error("CheckRequired should be true by default")
	}
}

func TestDetector_SecureServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Secure server should have no high severity findings
	for _, finding := range result.Findings {
		if finding.Severity == core.SeverityHigh || finding.Severity == core.SeverityCritical {
			t.Errorf("Secure server should not have high severity findings, got: %s - %s",
				finding.Type, finding.Description)
		}
	}
}

func TestDetector_MissingAllHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		CheckRequired: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerabilities when all headers are missing")
	}

	// Should have findings for missing required headers
	if len(result.MissingHeaders) == 0 {
		t.Error("Expected missing headers to be reported")
	}
}

func TestDetector_MissingXFrameOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Check if X-Frame-Options is in missing headers
	found := false
	for _, h := range result.MissingHeaders {
		if h == "X-Frame-Options" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected X-Frame-Options to be in missing headers")
	}
}

func TestDetector_MissingCSP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Check if CSP is in missing headers
	found := false
	for _, h := range result.MissingHeaders {
		if h == "Content-Security-Policy" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected Content-Security-Policy to be in missing headers")
	}

	// Should have a high severity finding for missing CSP
	hasHighSeverity := false
	for _, finding := range result.Findings {
		if finding.Severity == core.SeverityHigh && finding.Parameter == "Content-Security-Policy" {
			hasHighSeverity = true
			break
		}
	}

	if !hasHighSeverity {
		t.Error("Expected high severity finding for missing CSP")
	}
}

func TestDetector_InsecureCSPUnsafeInline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should have a finding for unsafe-inline in CSP
	found := false
	for _, h := range result.InsecureHeaders {
		if h == "Content-Security-Policy" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected Content-Security-Policy to be flagged as insecure due to unsafe-inline")
	}
}

func TestDetector_InformationDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		CheckInfoDisclosure: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should find information disclosure headers
	if len(result.InfoDisclosureHeaders) == 0 {
		t.Error("Expected information disclosure headers to be reported")
	}

	// Check for specific headers
	foundServer := false
	foundPoweredBy := false
	for _, h := range result.InfoDisclosureHeaders {
		if h == "Server" {
			foundServer = true
		}
		if h == "X-Powered-By" {
			foundPoweredBy = true
		}
	}

	if !foundServer {
		t.Error("Expected Server header to be flagged")
	}
	if !foundPoweredBy {
		t.Error("Expected X-Powered-By header to be flagged")
	}
}

func TestDetector_MissingHSTS(t *testing.T) {
	// Use HTTPS server for HSTS test
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithInsecure(true)
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should find missing HSTS
	found := false
	for _, h := range result.MissingHeaders {
		if h == "Strict-Transport-Security" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected Strict-Transport-Security to be in missing headers for HTTPS site")
	}
}

func TestDetector_WeakHSTSMaxAge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=86400") // Only 1 day
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		CheckRequired: true,
		MinHSTSMaxAge: 31536000, // Require 1 year
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should find weak HSTS configuration
	found := false
	for _, h := range result.InsecureHeaders {
		if h == "Strict-Transport-Security" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected Strict-Transport-Security to be flagged as weak")
	}
}

func TestDetector_InvalidXFrameOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "ALLOW-FROM https://example.com") // Deprecated
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should find invalid X-Frame-Options
	found := false
	for _, h := range result.InsecureHeaders {
		if h == "X-Frame-Options" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected X-Frame-Options ALLOW-FROM to be flagged as insecure")
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := detector.Detect(ctx, server.URL, DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings")
	}

	for _, finding := range result.Findings {
		if len(finding.WSTG) == 0 {
			t.Errorf("Finding %s missing WSTG mapping", finding.Type)
		}
		if len(finding.Top10) == 0 {
			t.Errorf("Finding %s missing OWASP Top 10 mapping", finding.Type)
		}
		if len(finding.CWE) == 0 {
			t.Errorf("Finding %s missing CWE mapping", finding.Type)
		}
	}
}

func TestDetector_HeaderPresenceCheck(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		wantHeader string
		wantFound  bool
	}{
		{
			name:       "header present",
			headers:    map[string]string{"X-Frame-Options": "DENY"},
			wantHeader: "X-Frame-Options",
			wantFound:  true,
		},
		{
			name:       "header missing",
			headers:    map[string]string{},
			wantHeader: "X-Frame-Options",
			wantFound:  false,
		},
		{
			name:       "case insensitive",
			headers:    map[string]string{"x-frame-options": "DENY"},
			wantHeader: "X-Frame-Options",
			wantFound:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := internalhttp.NewClient()
			detector := New(client)

			_, found := detector.getHeader(tt.headers, tt.wantHeader)
			if found != tt.wantFound {
				t.Errorf("getHeader() found = %v, want %v", found, tt.wantFound)
			}
		})
	}
}
