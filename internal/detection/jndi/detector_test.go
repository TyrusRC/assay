package jndi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
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

	if opts.MaxPayloads <= 0 {
		t.Error("MaxPayloads should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
}

func TestDetector_DetectLog4ShellErrorBased(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check all headers for JNDI payloads
		for _, values := range r.Header {
			for _, v := range values {
				if strings.Contains(v, "${jndi:") || strings.Contains(v, "${${") {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Error: JNDI lookup failed: javax.naming.NamingException"))
					return
				}
			}
		}
		// Check query params
		for _, values := range r.URL.Query() {
			for _, v := range values {
				if strings.Contains(v, "${jndi:") || strings.Contains(v, "${${") {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Error: Lookup failed - com.sun.jndi.ldap.LdapCtx"))
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?input=test",
		DetectOptions{
			MaxPayloads:  10,
			CallbackHost: "attacker.example.com",
			TestHeaders:  true,
			TestParams:   true,
			Params:       []string{"input"},
		},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected Log4Shell vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectViaHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if strings.Contains(ua, "jndi") || strings.Contains(ua, "${") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("javax.naming.NamingException: JNDI lookup error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL,
		DetectOptions{
			MaxPayloads:  5,
			CallbackHost: "callback.example.com",
			TestHeaders:  true,
		},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected header-based Log4Shell to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?input=test",
		DetectOptions{
			MaxPayloads:  5,
			CallbackHost: "callback.example.com",
			TestHeaders:  true,
			TestParams:   true,
			Params:       []string{"input"},
		},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := detector.Detect(ctx, server.URL, DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_PayloadGeneration(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	callbackHost := "test.callback.com"
	payloads := detector.generatePayloads(callbackHost, DetectOptions{MaxPayloads: 50})

	if len(payloads) == 0 {
		t.Error("Expected payloads to be generated")
	}

	// Check that callback host is inserted
	for _, p := range payloads {
		if !strings.Contains(p, callbackHost) {
			t.Errorf("Payload doesn't contain callback host: %s", p)
		}
		// Should not contain template placeholder
		if strings.Contains(p, "{CALLBACK}") {
			t.Errorf("Payload still contains {CALLBACK} placeholder: %s", p)
		}
	}
}

func TestDetector_ErrorPatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{name: "NamingException", body: "javax.naming.NamingException: lookup failed", expected: true},
		{name: "JNDI lookup", body: "Error during JNDI lookup for resource", expected: true},
		{name: "LdapCtx", body: "com.sun.jndi.ldap.LdapCtx error", expected: true},
		{name: "Normal page", body: "Welcome to our website", expected: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasJNDIError(tt.body)
			if result != tt.expected {
				t.Errorf("hasJNDIError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range r.URL.Query()["input"] {
			if strings.Contains(v, "jndi") {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("javax.naming.NamingException"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?input=test",
		DetectOptions{
			MaxPayloads:  5,
			CallbackHost: "cb.example.com",
			TestParams:   true,
			Params:       []string{"input"},
		},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability")
	}

	finding := result.Findings[0]
	if finding.Type != "JNDI Injection (Log4Shell)" {
		t.Errorf("Expected type 'JNDI Injection (Log4Shell)', got %s", finding.Type)
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}
