package redirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/redirect"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads <= 0 {
		t.Error("DefaultOptions() MaxPayloads should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
	if opts.EvilDomain == "" {
		t.Error("DefaultOptions() EvilDomain should not be empty")
	}
}

func TestDetector_DetectVulnerableRedirect(t *testing.T) {
	// Create a vulnerable server that redirects based on parameter
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("redirect")
		if redirectURL != "" {
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?redirect=http://example.com", "redirect", "GET", DetectOptions{
		MaxPayloads: 10,
		EvilDomain:  "evil.com",
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected Open Redirect vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectProtocolRelative(t *testing.T) {
	// Create a vulnerable server that handles protocol-relative URLs
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("url")
		if strings.HasPrefix(redirectURL, "//") {
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=//test.com", "url", "GET", DetectOptions{
		MaxPayloads:   10,
		EvilDomain:    "evil.com",
		IncludeBypass: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected protocol-relative redirect to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	// Create a safe server that doesn't redirect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=test", "url", "GET", DetectOptions{
		MaxPayloads: 5,
		EvilDomain:  "evil.com",
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_DetectWhitelistValidation(t *testing.T) {
	// Create a server that properly validates redirect URLs
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("redirect")
		if redirectURL != "" {
			// Proper validation: only allow relative paths starting with single /
			// and not containing external domain indicators
			if strings.HasPrefix(redirectURL, "/") &&
				!strings.HasPrefix(redirectURL, "//") &&
				!strings.Contains(redirectURL, "\\") &&
				!strings.Contains(redirectURL, "evil") &&
				!strings.Contains(redirectURL, "@") &&
				!strings.Contains(redirectURL, "%") &&
				len(redirectURL) < 100 {
				w.Header().Set("Location", redirectURL)
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		// No redirect for invalid URLs
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?redirect=/test", "redirect", "GET", DetectOptions{
		MaxPayloads: 10,
		EvilDomain:  "evil.com",
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability with proper validation")
	}
}

func TestDetector_isExternalRedirect(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name       string
		location   string
		evilDomain string
		expected   bool
	}{
		{
			name:       "direct evil domain",
			location:   "https://evil.com/path",
			evilDomain: "evil.com",
			expected:   true,
		},
		{
			name:       "subdomain of evil",
			location:   "https://sub.evil.com/path",
			evilDomain: "evil.com",
			expected:   true,
		},
		{
			name:       "protocol-relative evil",
			location:   "//evil.com/path",
			evilDomain: "evil.com",
			expected:   true,
		},
		{
			name:       "safe domain",
			location:   "https://safe.com/path",
			evilDomain: "evil.com",
			expected:   false,
		},
		{
			name:       "relative path",
			location:   "/internal/path",
			evilDomain: "evil.com",
			expected:   false,
		},
		{
			name:       "case insensitive",
			location:   "https://EVIL.COM/path",
			evilDomain: "evil.com",
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.isExternalRedirect(tt.location, tt.evilDomain)
			if result != tt.expected {
				t.Errorf("isExternalRedirect(%q, %q) = %v, want %v",
					tt.location, tt.evilDomain, result, tt.expected)
			}
		})
	}
}

func TestDetector_hasMetaRefreshToExternal(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name       string
		body       string
		evilDomain string
		expected   bool
	}{
		{
			name:       "meta refresh with evil domain",
			body:       `<meta http-equiv="refresh" content="0;url=https://evil.com">`,
			evilDomain: "evil.com",
			expected:   true,
		},
		{
			name:       "safe meta refresh",
			body:       `<meta http-equiv="refresh" content="0;url=/internal">`,
			evilDomain: "evil.com",
			expected:   false,
		},
		{
			name:       "no meta refresh",
			body:       `<html><body>Hello</body></html>`,
			evilDomain: "evil.com",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasMetaRefreshToExternal(tt.body, tt.evilDomain)
			if result != tt.expected {
				t.Errorf("hasMetaRefreshToExternal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_hasJSRedirectToExternal(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name       string
		body       string
		evilDomain string
		expected   bool
	}{
		{
			name:       "window.location to evil",
			body:       `<script>window.location = "https://evil.com";</script>`,
			evilDomain: "evil.com",
			expected:   true,
		},
		{
			name:       "location.href to evil",
			body:       `<script>location.href = "https://evil.com";</script>`,
			evilDomain: "evil.com",
			expected:   true,
		},
		{
			name:       "safe redirect",
			body:       `<script>window.location = "/internal";</script>`,
			evilDomain: "evil.com",
			expected:   false,
		},
		{
			name:       "no redirect",
			body:       `<script>console.log("hello");</script>`,
			evilDomain: "evil.com",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasJSRedirectToExternal(tt.body, tt.evilDomain)
			if result != tt.expected {
				t.Errorf("hasJSRedirectToExternal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_deduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payloads := []redirect.Payload{
		{Value: "https://evil.com"},
		{Value: "//evil.com"},
		{Value: "https://evil.com"}, // duplicate
		{Value: "https://other.com"},
		{Value: "//evil.com"}, // duplicate
	}

	unique := detector.deduplicatePayloads(payloads)
	if len(unique) != 3 {
		t.Errorf("deduplicatePayloads() returned %d payloads, want 3", len(unique))
	}
}

func TestDetector_DetectParams(t *testing.T) {
	// Create a server that responds to redirect parameters
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for known redirect parameters
		for _, param := range []string{"redirect", "url", "next", "return"} {
			if val := r.URL.Query().Get(param); val != "" {
				w.Header().Set("Location", val)
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	params, err := detector.DetectParams(context.Background(), server.URL, "GET")
	if err != nil {
		t.Fatalf("DetectParams failed: %v", err)
	}

	// Should find at least some of the common params
	if len(params) == 0 {
		t.Error("Expected to find redirect parameters")
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payload := redirect.Payload{
		Value:       "https://evil.com",
		BypassType:  redirect.BypassNone,
		Description: "Direct external URL",
	}

	resp := &internalhttp.Response{
		StatusCode: 302,
		Headers:    map[string]string{"Location": "https://evil.com"},
	}

	finding := detector.createFinding("https://target.com?url=x", "url", payload, resp, "evil.com")

	if finding == nil {
		t.Fatal("createFinding returned nil")
	}

	if finding.Type != "Open Redirect" {
		t.Errorf("Finding type = %q, want %q", finding.Type, "Open Redirect")
	}

	if finding.URL != "https://target.com?url=x" {
		t.Errorf("Finding URL = %q, want target URL", finding.URL)
	}

	if finding.Parameter != "url" {
		t.Errorf("Finding Parameter = %q, want %q", finding.Parameter, "url")
	}

	if len(finding.WSTG) == 0 {
		t.Error("Finding should have WSTG mapping")
	}

	if len(finding.CWE) == 0 {
		t.Error("Finding should have CWE mapping")
	}

	if finding.Remediation == "" {
		t.Error("Finding should have remediation")
	}
}

func TestDetector_BypassPayloads(t *testing.T) {
	// Create a server vulnerable to auth syntax bypass
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("url")
		if redirectURL != "" && strings.Contains(redirectURL, "trusted.com") {
			// Server incorrectly validates by checking if trusted.com is in URL
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:   20,
		EvilDomain:    "evil.com",
		TrustedDomain: "trusted.com",
		IncludeBypass: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// The server is vulnerable because it checks if trusted.com is in the URL
	// but doesn't properly validate it's the actual domain
	if result.Vulnerable && result.BypassUsed != redirect.BypassNone {
		t.Logf("Bypass technique used: %s", result.BypassUsed)
	}
}
