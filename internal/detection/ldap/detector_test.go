package ldap

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
}

func TestDetector_DetectLDAPErrorBased(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if strings.Contains(user, "*") || strings.Contains(user, "(") || strings.Contains(user, ")") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("javax.naming.NamingException: Invalid filter expression"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User not found"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?user=admin",
		"user", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected LDAP injection to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectLDAPBoolBased(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		// Simulate LDAP filter injection - wildcard or filter bypass returns extra data
		if strings.Contains(user, "*") || strings.Contains(user, "(&") {
			// Wildcard/filter bypass returns many entries (large response)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uid=admin,dc=example,dc=com\nuid=root,dc=example,dc=com\nuid=john,dc=example,dc=com\nuid=jane,dc=example,dc=com\nuid=bob,dc=example,dc=com\nuid=alice,dc=example,dc=com\nuid=charlie,dc=example,dc=com\nuid=dave,dc=example,dc=com"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("uid=admin"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?user=admin",
		"user", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected LDAP bool-based injection to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?user=admin",
		"user", "GET",
		DetectOptions{MaxPayloads: 10},
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

	_, err := detector.Detect(ctx, server.URL+"?user=test", "user", "GET", DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_ErrorPatternDetection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{name: "NamingException", body: "javax.naming.NamingException: error", expected: true},
		{name: "LDAPException", body: "LDAPException occurred", expected: true},
		{name: "ldap_search", body: "Warning: ldap_search(): error", expected: true},
		{name: "Invalid DN", body: "Invalid DN syntax in filter", expected: true},
		{name: "Normal response", body: "User not found", expected: false},
		{name: "HTML page", body: "<html><body>Hello</body></html>", expected: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasLDAPError(tt.body)
			if result != tt.expected {
				t.Errorf("hasLDAPError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if strings.Contains(user, "*") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("LDAP error: invalid filter"))
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
		server.URL+"?user=admin",
		"user", "GET",
		DetectOptions{MaxPayloads: 5},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability")
	}

	finding := result.Findings[0]
	if finding.Type != "LDAP Injection" {
		t.Errorf("Expected type 'LDAP Injection', got %s", finding.Type)
	}
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}
