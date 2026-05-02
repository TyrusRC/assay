package crlf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/crlf"
)

// TestIsVulnerable_RotatingSessionCookie_NoFP reproduces the real-world
// false positive seen against ginandjuice.shop: an AWS ALB in front of the
// target issues a fresh `Set-Cookie: AWSALB=<random>` on every request, so
// the test response's Set-Cookie differs from the baseline even when the
// CRLF payload did nothing. Before the fix, `hasInjectedHeader` flagged
// this as an injection (header name matches, value differs → "not in
// baseline"); after the fix, it must require the payload's specific
// injected marker ("crlf=injection") to appear in the header value.
func TestIsVulnerable_RotatingSessionCookie_NoFP(t *testing.T) {
	d := New(nil)
	payload := crlf.Payload{
		Value:          "%0d%0aSet-Cookie:crlf=injection",
		InjectionType:  crlf.InjectionHeader,
		EncodingType:   crlf.EncodingURL,
		InjectedHeader: "Set-Cookie",
	}
	baseline := &internalhttp.Response{
		Headers: map[string]string{"Set-Cookie": "AWSALB=aaaaaaaaaaaaaa; Path=/"},
	}
	rotated := &internalhttp.Response{
		// Same header name, different (rotated) value — NOT an injection.
		Headers: map[string]string{"Set-Cookie": "AWSALB=bbbbbbbbbbbbbb; Path=/"},
	}

	if d.isVulnerable(rotated, baseline, payload) {
		t.Errorf("FP: rotating AWS ALB cookie flagged as CRLF injection")
	}
}

// TestIsVulnerable_InjectedMarkerPresent_FlagsVuln verifies the positive
// case: when the payload's marker actually appears in a response header,
// the detector reports vulnerable.
func TestIsVulnerable_InjectedMarkerPresent_FlagsVuln(t *testing.T) {
	d := New(nil)
	payload := crlf.Payload{
		Value:          "%0d%0aSet-Cookie:crlf=injection",
		InjectionType:  crlf.InjectionHeader,
		EncodingType:   crlf.EncodingURL,
		InjectedHeader: "Set-Cookie",
	}
	baseline := &internalhttp.Response{
		Headers: map[string]string{"Set-Cookie": "AWSALB=aaaaaaaa; Path=/"},
	}
	injected := &internalhttp.Response{
		Headers: map[string]string{"Set-Cookie": "AWSALB=bbbbbbbb; Path=/, crlf=injection"},
	}

	if !d.isVulnerable(injected, baseline, payload) {
		t.Errorf("FN: response with injected marker not flagged as CRLF injection")
	}
}

// TestIsVulnerable_BodyReflectsPayloadHeaderName_NoFP ensures that pages
// that merely mention the header name (docs, echo-header responses) are
// NOT flagged. Only literal CR/LF + header + marker should count.
func TestIsVulnerable_BodyReflectsPayloadHeaderName_NoFP(t *testing.T) {
	d := New(nil)
	payload := crlf.Payload{
		Value:          "%0d%0aSet-Cookie:crlf=injection",
		InjectionType:  crlf.InjectionHeader,
		EncodingType:   crlf.EncodingURL,
		InjectedHeader: "Set-Cookie",
	}
	baseline := &internalhttp.Response{
		Headers: map[string]string{"Set-Cookie": "AWSALB=aaaaaaaa"},
	}
	// Body mentions "Set-Cookie:" but no CR/LF and no marker — likely docs
	// or an API that echoes the literal header name.
	echoed := &internalhttp.Response{
		Headers: map[string]string{"Set-Cookie": "AWSALB=bbbbbbbb"},
		Body:    `{"note": "the Set-Cookie: header is set by the server"}`,
	}
	if d.isVulnerable(echoed, baseline, payload) {
		t.Errorf("FP: response body merely echoing 'Set-Cookie:' flagged as CRLF injection")
	}
}

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
	if !opts.TestHeaderInjection {
		t.Error("DefaultOptions() should have TestHeaderInjection enabled")
	}
	if !opts.TestResponseSplit {
		t.Error("DefaultOptions() should have TestResponseSplit enabled")
	}
}

func TestDetector_DetectHeaderInjection(t *testing.T) {
	// Create a vulnerable server that includes user input in headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("redirect")
		if value != "" {
			// Vulnerable: directly using user input in Location header
			// Decode URL encoding to simulate vulnerable server
			decoded, err := url.QueryUnescape(value)
			if err == nil {
				// Check if decoded value contains CRLF
				if strings.Contains(decoded, "\r\n") {
					// Split on CRLF and add headers
					parts := strings.Split(decoded, "\r\n")
					for _, part := range parts {
						if strings.Contains(part, ":") {
							headerParts := strings.SplitN(part, ":", 2)
							if len(headerParts) == 2 {
								w.Header().Set(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
							}
						}
					}
				}
				w.Header().Set("Location", decoded)
			}
		}
		w.WriteHeader(http.StatusFound)
		w.Write([]byte("Redirecting..."))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?redirect=http://example.com", "redirect", "GET", DetectOptions{
		MaxPayloads:         10,
		TestHeaderInjection: true,
		TestResponseSplit:   false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// The test checks if detector can find CRLF injection
	t.Logf("Vulnerable: %v, TestedPayloads: %d", result.Vulnerable, result.TestedPayloads)
}

func TestDetector_DetectSetCookieInjection(t *testing.T) {
	// Create a server vulnerable to Set-Cookie injection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("input")
		if value != "" {
			decoded, err := url.QueryUnescape(value)
			if err == nil && strings.Contains(decoded, "\r\n") {
				// Parse and set injected headers
				lines := strings.Split(decoded, "\r\n")
				for _, line := range lines[1:] { // Skip first part
					if strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
						cookieValue := strings.TrimPrefix(line, "Set-Cookie:")
						cookieValue = strings.TrimPrefix(cookieValue, "set-cookie:")
						w.Header().Add("Set-Cookie", strings.TrimSpace(cookieValue))
					}
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DefaultOptions())

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	t.Logf("Vulnerable: %v, Findings: %d", result.Vulnerable, len(result.Findings))
}

func TestDetector_SafeServer(t *testing.T) {
	// Create a safe server that properly sanitizes input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("input")
		if value != "" {
			// Safe: sanitize CRLF characters
			safe := strings.ReplaceAll(value, "\r", "")
			safe = strings.ReplaceAll(safe, "\n", "")
			safe = strings.ReplaceAll(safe, "%0d", "")
			safe = strings.ReplaceAll(safe, "%0a", "")
			safe = strings.ReplaceAll(safe, "%0D", "")
			safe = strings.ReplaceAll(safe, "%0A", "")
			w.Header().Set("X-Input", safe)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_hasInjectedHeader(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	setCookiePayload := crlf.Payload{
		Value:          "%0d%0aSet-Cookie:crlf=injection",
		InjectionType:  crlf.InjectionHeader,
		EncodingType:   crlf.EncodingURL,
		InjectedHeader: "Set-Cookie",
	}
	xInjectedPayload := crlf.Payload{
		Value:          "%0d%0aX-Injected:header",
		InjectionType:  crlf.InjectionHeader,
		EncodingType:   crlf.EncodingURL,
		InjectedHeader: "X-Injected",
	}

	tests := []struct {
		name     string
		resp     *internalhttp.Response
		payload  crlf.Payload
		baseline *internalhttp.Response
		expected bool
	}{
		{
			name: "injected marker present in Set-Cookie",
			resp: &internalhttp.Response{
				Headers: map[string]string{"Set-Cookie": "crlf=injection"},
			},
			payload:  setCookiePayload,
			baseline: nil,
			expected: true,
		},
		{
			name: "X-Injected header with marker present and absent from baseline",
			resp: &internalhttp.Response{
				Headers: map[string]string{"X-Injected": "header"},
			},
			payload:  xInjectedPayload,
			baseline: &internalhttp.Response{Headers: map[string]string{}},
			expected: true,
		},
		{
			name: "same Content-Type in baseline (no injection)",
			resp: &internalhttp.Response{
				Headers: map[string]string{"Content-Type": "text/html"},
			},
			payload: crlf.Payload{
				Value:          "%0d%0aContent-Type:text/html",
				InjectedHeader: "Content-Type",
				InjectionType:  crlf.InjectionHeader,
			},
			baseline: &internalhttp.Response{
				Headers: map[string]string{"Content-Type": "text/html"},
			},
			expected: false,
		},
		{
			name: "marker only in a DIFFERENT header — not our injection",
			resp: &internalhttp.Response{
				Headers: map[string]string{"X-Custom": "crlf=injection"},
			},
			payload:  setCookiePayload, // targets Set-Cookie, not X-Custom
			baseline: nil,
			expected: false,
		},
		{
			name: "rotated session cookie (value differs from baseline, no marker) — FP case",
			resp: &internalhttp.Response{
				Headers: map[string]string{"Set-Cookie": "AWSALB=bbbbbbbb; Path=/"},
			},
			payload: setCookiePayload,
			baseline: &internalhttp.Response{
				Headers: map[string]string{"Set-Cookie": "AWSALB=aaaaaaaa; Path=/"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasInjectedHeader(tt.resp, tt.payload, tt.baseline)
			if result != tt.expected {
				t.Errorf("hasInjectedHeader() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_hasCustomInjectedHeader(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		resp     *internalhttp.Response
		expected bool
	}{
		{
			name:     "x-injected header",
			resp:     &internalhttp.Response{Headers: map[string]string{"X-Injected-Header": "value"}},
			expected: true,
		},
		{
			name:     "x-crlf header",
			resp:     &internalhttp.Response{Headers: map[string]string{"X-Crlf-Test": "anything"}},
			expected: true,
		},
		{
			name: "normal headers only",
			resp: &internalhttp.Response{
				Headers: map[string]string{
					"Content-Type": "text/html",
					"Date":         "Mon, 01 Jan 2024 00:00:00 GMT",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detector.hasCustomInjectedHeader(tt.resp); got != tt.expected {
				t.Errorf("hasCustomInjectedHeader() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_hasResponseSplitIndicators(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		resp     *internalhttp.Response
		expected bool
	}{
		{
			name: "HTTP version in body",
			resp: &internalhttp.Response{
				Body:        "Normal content HTTP/1.1 200 OK",
				ContentType: "text/plain",
			},
			expected: true,
		},
		{
			name: "script in non-HTML",
			resp: &internalhttp.Response{
				Body:        "<script>alert(1)</script>",
				ContentType: "application/json",
			},
			expected: true,
		},
		{
			name: "normal JSON response",
			resp: &internalhttp.Response{
				Body:        `{"status": "ok"}`,
				ContentType: "application/json",
			},
			expected: false,
		},
		{
			name: "normal HTML response",
			resp: &internalhttp.Response{
				Body:        "<html><body>Hello</body></html>",
				ContentType: "text/html",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasResponseSplitIndicators(tt.resp)
			if result != tt.expected {
				t.Errorf("hasResponseSplitIndicators() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_hasReflectedCRLFPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		payload  crlf.Payload
		expected bool
	}{
		{
			name: "CRLF + injected header + marker in body",
			body: "Some content\r\nSet-Cookie: crlf=injection",
			payload: crlf.Payload{
				Value:          "%0d%0aSet-Cookie:crlf=injection",
				InjectedHeader: "Set-Cookie",
			},
			expected: true,
		},
		{
			name: "LF + injected header + marker in body",
			body: "Some content\nSet-Cookie: crlf=injection",
			payload: crlf.Payload{
				Value:          "%0d%0aSet-Cookie:crlf=injection",
				InjectedHeader: "Set-Cookie",
			},
			expected: true,
		},
		{
			name: "CRLF + header but NO marker — FP case (docs/echo)",
			body: "Some content\r\nSet-Cookie: legitimate=value",
			payload: crlf.Payload{
				Value:          "%0d%0aSet-Cookie:crlf=injection",
				InjectedHeader: "Set-Cookie",
			},
			expected: false,
		},
		{
			name: "header name mentioned in prose (no CRLF)",
			body: "Content with X-Injected: header pattern",
			payload: crlf.Payload{
				Value:          "%0d%0aX-Injected:header",
				InjectedHeader: "X-Injected",
			},
			expected: false,
		},
		{
			name: "clean body",
			body: "Normal content without injection",
			payload: crlf.Payload{
				Value:          "%0d%0aSet-Cookie:crlf=injection",
				InjectedHeader: "Set-Cookie",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasReflectedCRLFPatterns(tt.body, tt.payload)
			if result != tt.expected {
				t.Errorf("hasReflectedCRLFPatterns() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_deduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payloads := []crlf.Payload{
		{Value: "%0d%0aSet-Cookie:test"},
		{Value: "%0d%0aX-Injected:header"},
		{Value: "%0d%0aSet-Cookie:test"}, // duplicate
		{Value: "%0aSet-Cookie:test"},
		{Value: "%0d%0aX-Injected:header"}, // duplicate
	}

	unique := detector.deduplicatePayloads(payloads)
	if len(unique) != 3 {
		t.Errorf("deduplicatePayloads() returned %d payloads, want 3", len(unique))
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payload := crlf.Payload{
		Value:          "%0d%0aSet-Cookie:crlf=injection",
		InjectionType:  crlf.InjectionHeader,
		EncodingType:   crlf.EncodingURL,
		Description:    "Set-Cookie injection",
		InjectedHeader: "Set-Cookie",
	}

	resp := &internalhttp.Response{
		StatusCode: 200,
		Headers: map[string]string{
			"Set-Cookie": "crlf=injection",
		},
	}

	finding := detector.createFinding("https://target.com?input=x", "input", payload, resp)

	if finding == nil {
		t.Fatal("createFinding returned nil")
	}

	if finding.Type != "CRLF Injection" {
		t.Errorf("Finding type = %q, want %q", finding.Type, "CRLF Injection")
	}

	if finding.URL != "https://target.com?input=x" {
		t.Errorf("Finding URL = %q, want target URL", finding.URL)
	}

	if finding.Parameter != "input" {
		t.Errorf("Finding Parameter = %q, want %q", finding.Parameter, "input")
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

func TestDetector_EncodingTypes(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	// Test with only URL encoding
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads:         10,
		IncludeAllEncodings: false,
		TestHeaderInjection: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Verify payloads were tested
	if result.TestedPayloads == 0 {
		t.Error("Expected some payloads to be tested")
	}
}

func TestDetector_InjectionTypes(t *testing.T) {
	// Test that injection types are correctly categorized
	headerPayloads := crlf.GetHeaderInjectionPayloads()
	responseSplitPayloads := crlf.GetResponseSplitPayloads()

	for _, p := range headerPayloads {
		if p.InjectionType != crlf.InjectionHeader && p.InjectionType != crlf.InjectionLogForging {
			t.Errorf("Header payload has wrong type: %s", p.InjectionType)
		}
	}

	for _, p := range responseSplitPayloads {
		if p.InjectionType != crlf.InjectionResponseSplit {
			t.Errorf("Response split payload has wrong type: %s", p.InjectionType)
		}
	}
}

func TestDetector_getCookieHeaders(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	resp := &internalhttp.Response{
		Headers: map[string]string{
			"Set-Cookie":   "session=abc123",
			"Content-Type": "text/html",
		},
	}

	cookies := detector.getCookieHeaders(resp)
	if len(cookies) != 1 {
		t.Errorf("getCookieHeaders() returned %d cookies, want 1", len(cookies))
	}
}

func TestDetector_ResponseSplitDetection(t *testing.T) {
	// Create a server vulnerable to response splitting
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("input")
		if value != "" {
			decoded, err := url.QueryUnescape(value)
			if err == nil {
				// Vulnerable: write user input to response body without sanitization
				if strings.Contains(decoded, "\r\n\r\n") {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(decoded))
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

	result, err := detector.Detect(context.Background(), server.URL+"?input=test", "input", "GET", DetectOptions{
		MaxPayloads:       10,
		TestResponseSplit: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	t.Logf("Vulnerable: %v, TestedPayloads: %d", result.Vulnerable, result.TestedPayloads)
}
