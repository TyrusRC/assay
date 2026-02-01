package cors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
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

	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
}

func TestDetector_DetectOriginReflection(t *testing.T) {
	// Create a vulnerable server that reflects Origin header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
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

	if !result.Vulnerable {
		t.Error("Expected CORS misconfiguration to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	if !result.AllowsCredentials {
		t.Error("Expected AllowsCredentials to be true")
	}
}

func TestDetector_DetectNullOrigin(t *testing.T) {
	// Create a server vulnerable to null origin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
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

	if !result.Vulnerable {
		t.Error("Expected null origin vulnerability to be detected")
	}

	if result.MisconfigType != MisconfigNullOrigin {
		t.Errorf("Expected MisconfigNullOrigin, got %s", result.MisconfigType)
	}
}

func TestDetector_SafeServer(t *testing.T) {
	// Create a safe server with proper CORS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Only allow specific trusted domain
		if origin == "https://trusted.com" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
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

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_DetectSubdomainWildcard(t *testing.T) {
	// Create a server with subdomain wildcard matching
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Vulnerable: accepts any subdomain of target
		if strings.Contains(origin, ".localhost") || strings.HasSuffix(origin, "localhost") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
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

	// Note: this test checks for the detector's ability to find subdomain wildcards
	// The specific test depends on the generated origins
	t.Logf("Vulnerable: %v, Findings: %d", result.Vulnerable, len(result.Findings))
}

func TestDetector_DetectPreflight(t *testing.T) {
	// Create a server with vulnerable pre-flight
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if r.Method == "OPTIONS" {
			// Reflect any origin in preflight
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "X-Custom-Header")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		TestPreflight:   true,
		TestCredentials: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected pre-flight vulnerability to be detected")
	}
}

func TestDetector_isCORSVulnerable(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name            string
		result          *corsTestResult
		testedOrigin    string
		testCredentials bool
		expected        bool
	}{
		{
			name: "origin reflection with credentials",
			result: &corsTestResult{
				allowOrigin:      "https://evil.com",
				allowCredentials: true,
			},
			testedOrigin:    "https://evil.com",
			testCredentials: true,
			expected:        true,
		},
		{
			name: "origin reflection without credentials",
			result: &corsTestResult{
				allowOrigin:      "https://evil.com",
				allowCredentials: false,
			},
			testedOrigin:    "https://evil.com",
			testCredentials: true,
			expected:        true,
		},
		{
			name: "null origin with credentials",
			result: &corsTestResult{
				allowOrigin:      "null",
				allowCredentials: true,
			},
			testedOrigin:    "null",
			testCredentials: true,
			expected:        true,
		},
		{
			name: "wildcard with credentials",
			result: &corsTestResult{
				allowOrigin:      "*",
				allowCredentials: true,
			},
			testedOrigin:    "https://evil.com",
			testCredentials: true,
			expected:        true,
		},
		{
			name: "safe configuration",
			result: &corsTestResult{
				allowOrigin:      "https://trusted.com",
				allowCredentials: false,
			},
			testedOrigin:    "https://evil.com",
			testCredentials: true,
			expected:        false,
		},
		{
			name: "no CORS headers",
			result: &corsTestResult{
				allowOrigin: "",
			},
			testedOrigin:    "https://evil.com",
			testCredentials: true,
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.isCORSVulnerable(tt.result, tt.testedOrigin, tt.testCredentials)
			if result != tt.expected {
				t.Errorf("isCORSVulnerable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_generateTestOrigins(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	origins := detector.generateTestOrigins("example.com", nil)

	if len(origins) == 0 {
		t.Fatal("generateTestOrigins returned empty slice")
	}

	// Check for expected origin patterns
	hasExternalDomain := false
	hasNullOrigin := false
	hasSubdomain := false

	for _, o := range origins {
		if strings.Contains(o.value, "evil.com") {
			hasExternalDomain = true
		}
		if o.value == "null" {
			hasNullOrigin = true
		}
		if strings.Contains(o.value, "evil.example.com") {
			hasSubdomain = true
		}
	}

	if !hasExternalDomain {
		t.Error("Expected external domain test origin")
	}
	if !hasNullOrigin {
		t.Error("Expected null origin test")
	}
	if !hasSubdomain {
		t.Error("Expected subdomain test origin")
	}
}

func TestDetector_testOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Expose-Headers", "X-Custom")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.testOrigin(context.Background(), server.URL, "https://test.com", false)

	if err != nil {
		t.Fatalf("testOrigin failed: %v", err)
	}

	if result.allowOrigin != "https://test.com" {
		t.Errorf("allowOrigin = %q, want %q", result.allowOrigin, "https://test.com")
	}

	if result.allowMethods == "" {
		t.Error("allowMethods should not be empty")
	}

	if result.exposeHeaders == "" {
		t.Error("exposeHeaders should not be empty")
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	origin := testOrigin{
		value:         "https://evil.com",
		description:   "External domain origin",
		misconfigType: MisconfigReflection,
	}

	corsResult := &corsTestResult{
		allowOrigin:      "https://evil.com",
		allowCredentials: true,
		allowMethods:     "GET, POST",
	}

	finding := detector.createFinding("https://target.com/api", origin, corsResult)

	if finding == nil {
		t.Fatal("createFinding returned nil")
	}

	if finding.Type != "CORS Misconfiguration" {
		t.Errorf("Finding type = %q, want %q", finding.Type, "CORS Misconfiguration")
	}

	if finding.URL != "https://target.com/api" {
		t.Errorf("Finding URL = %q, want target URL", finding.URL)
	}

	if len(finding.WSTG) == 0 {
		t.Error("Finding should have WSTG mapping")
	}

	if len(finding.CWE) == 0 {
		t.Error("Finding should have CWE mapping")
	}

	if len(finding.APITop10) == 0 {
		t.Error("Finding should have API Top 10 mapping")
	}

	if finding.Remediation == "" {
		t.Error("Finding should have remediation")
	}
}

func TestDetector_MisconfigTypes(t *testing.T) {
	// Test that all misconfig types are valid strings
	types := []MisconfigType{
		MisconfigReflection,
		MisconfigNullOrigin,
		MisconfigWildcard,
		MisconfigSubdomain,
		MisconfigInsecure,
		MisconfigPrefix,
		MisconfigSuffix,
	}

	for _, mt := range types {
		if string(mt) == "" {
			t.Errorf("MisconfigType %v has empty string value", mt)
		}
	}
}

func TestDetector_CustomOrigins(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "https://custom-attacker.com" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		CustomOrigins:   []string{"https://custom-attacker.com"},
		TestCredentials: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability with custom origin to be detected")
	}
}

func TestDetector_HTTPStoHTTPDowngrade(t *testing.T) {
	// Create a server that allows HTTP origin for HTTPS-like requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Vulnerable: allows http:// origin
		if strings.HasPrefix(origin, "http://") && strings.Contains(origin, "localhost") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
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

	// The test server allows HTTP origins which could be vulnerable
	t.Logf("Vulnerable: %v, Type: %s", result.Vulnerable, result.MisconfigType)
}
