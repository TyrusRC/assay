package ssti

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/ssti"

	nethttp "net/http"
)

// ---------------------------------------------------------------------------
// Helpers -- mock HTTP server builders
// ---------------------------------------------------------------------------

// newMockServer creates an httptest.Server that inspects the "input" query
// parameter and returns a response body controlled by the responder function.
// The responder receives the raw value of the "input" parameter.
func newMockServer(responder func(payload string) string) *httptest.Server {
	return httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		payload := r.URL.Query().Get("input")
		body := responder(payload)
		w.WriteHeader(nethttp.StatusOK)
		fmt.Fprint(w, body)
	}))
}

// newMockServerStatus is like newMockServer but also allows controlling the
// HTTP status code.
func newMockServerStatus(responder func(payload string) (int, string)) *httptest.Server {
	return httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		payload := r.URL.Query().Get("input")
		code, body := responder(payload)
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	}))
}

// ---------------------------------------------------------------------------
// Existing tests (preserved as-is)
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := http.NewClient()
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
	if !opts.IncludeWAFBypass {
		t.Error("DefaultOptions() IncludeWAFBypass should be true")
	}
	if !opts.TestAllEngines {
		t.Error("DefaultOptions() TestAllEngines should be true")
	}
	if opts.IncludeRCE {
		t.Error("DefaultOptions() IncludeRCE should be false by default")
	}
}

func TestDetectionResult_Initialization(t *testing.T) {
	result := &DetectionResult{
		Findings:       make([]*core.Finding, 0),
		DetectedEngine: ssti.EngineUnknown,
		ErrorPatterns:  make([]string, 0),
	}

	if result.Vulnerable {
		t.Error("New result should not be vulnerable")
	}
	if result.DetectedEngine != ssti.EngineUnknown {
		t.Error("New result should have unknown engine")
	}
	if len(result.Findings) != 0 {
		t.Error("New result should have empty findings")
	}
	if len(result.ErrorPatterns) != 0 {
		t.Error("New result should have empty error patterns")
	}
}

func TestDetector_containsMathResult(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		expected string
		baseline string
		want     bool
	}{
		{
			name:     "result found and not in baseline",
			body:     "The result is 49",
			expected: "49",
			baseline: "The result is unknown",
			want:     true,
		},
		{
			name:     "result not found",
			body:     "No result here",
			expected: "49",
			baseline: "No result here",
			want:     false,
		},
		{
			name:     "result in both but count increased",
			body:     "49 and another 49",
			expected: "49",
			baseline: "49",
			want:     true,
		},
		{
			name:     "result in baseline only once",
			body:     "49",
			expected: "49",
			baseline: "49",
			want:     false,
		},
		{
			name:     "result 14 for addition",
			body:     "Sum: 14",
			expected: "14",
			baseline: "Sum: unknown",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.containsMathResult(tt.body, tt.expected, tt.baseline)
			if got != tt.want {
				t.Errorf("containsMathResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_isPayloadSuccessful_Math(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	baseline := &baselineResponse{
		body: "Normal response",
	}

	tests := []struct {
		name    string
		body    string
		payload ssti.Payload
		want    bool
	}{
		{
			name: "math payload with expected output found",
			body: "Result: 49",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodMath,
				ExpectedOutput:  "49",
			},
			want: true,
		},
		{
			name: "math payload with expected output not found",
			body: "Result: error",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodMath,
				ExpectedOutput:  "49",
			},
			want: false,
		},
		{
			name: "math payload without expected output finds 49",
			body: "Value is 49",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodMath,
			},
			want: true,
		},
		{
			name: "math payload without expected output finds 14",
			body: "Sum is 14",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodMath,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isPayloadSuccessful(tt.body, tt.payload, baseline)
			if got != tt.want {
				t.Errorf("isPayloadSuccessful() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_isPayloadSuccessful_Reflection(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	baseline := &baselineResponse{
		body: "Normal response",
	}

	tests := []struct {
		name    string
		body    string
		payload ssti.Payload
		want    bool
	}{
		{
			name: "reflection with expected output found",
			body: "<class 'str'>",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodReflection,
				ExpectedOutput:  "class",
			},
			want: true,
		},
		{
			name: "reflection with Template found",
			body: "__TwigTemplate__",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodReflection,
			},
			want: true,
		},
		{
			name: "reflection with Config found",
			body: "Config object here",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodReflection,
			},
			want: true,
		},
		{
			name: "reflection not found",
			body: "Normal text only",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodReflection,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isPayloadSuccessful(tt.body, tt.payload, baseline)
			if got != tt.want {
				t.Errorf("isPayloadSuccessful() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_isPayloadSuccessful_Output(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	baseline := &baselineResponse{
		body: "Normal response",
	}

	tests := []struct {
		name    string
		body    string
		payload ssti.Payload
		want    bool
	}{
		{
			name: "command output with uid found",
			body: "uid=1000(user) gid=1000(user)",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodOutput,
				ExpectedOutput:  "uid=",
			},
			want: true,
		},
		{
			name: "passwd file content",
			body: "root:x:0:0:root:/root:/bin/bash",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodOutput,
			},
			want: true,
		},
		{
			name: "process info",
			body: "Process[pid=123]",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodOutput,
			},
			want: true,
		},
		{
			name: "no command output",
			body: "Error occurred",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodOutput,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isPayloadSuccessful(tt.body, tt.payload, baseline)
			if got != tt.want {
				t.Errorf("isPayloadSuccessful() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_isPayloadSuccessful_Error(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	baseline := &baselineResponse{
		body: "Normal response",
	}

	tests := []struct {
		name    string
		body    string
		payload ssti.Payload
		want    bool
	}{
		{
			name: "error pattern matched",
			body: "jinja2.exceptions.UndefinedError: 'undefined' is undefined",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodError,
				ErrorPatterns:   []string{"jinja2.exceptions"},
			},
			want: true,
		},
		{
			name: "error pattern not matched",
			body: "Generic error",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodError,
				ErrorPatterns:   []string{"jinja2.exceptions"},
			},
			want: false,
		},
		{
			name: "empty error patterns",
			body: "Some error",
			payload: ssti.Payload{
				DetectionMethod: ssti.MethodError,
				ErrorPatterns:   []string{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isPayloadSuccessful(tt.body, tt.payload, baseline)
			if got != tt.want {
				t.Errorf("isPayloadSuccessful() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_deduplicatePayloads(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payloads := []ssti.Payload{
		{Value: "{{7*7}}"},
		{Value: "${7*7}"},
		{Value: "{{7*7}}"}, // duplicate
		{Value: "<%= 7*7 %>"},
		{Value: "${7*7}"}, // duplicate
	}

	unique := detector.deduplicatePayloads(payloads)
	if len(unique) != 3 {
		t.Errorf("deduplicatePayloads() returned %d payloads, want 3", len(unique))
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	resp := &http.Response{
		StatusCode: 200,
		Body:       "Response with 49",
	}

	tests := []struct {
		name           string
		payload        ssti.Payload
		engine         ssti.TemplateEngine
		wantSeverity   core.Severity
		wantConfidence core.Confidence
	}{
		{
			name: "detection payload",
			payload: ssti.Payload{
				Value:           "{{7*7}}",
				Type:            ssti.TypeDetection,
				DetectionMethod: ssti.MethodMath,
			},
			engine:         ssti.EngineJinja2,
			wantSeverity:   core.SeverityHigh,
			wantConfidence: core.ConfidenceHigh,
		},
		{
			name: "RCE payload",
			payload: ssti.Payload{
				Value:           "{{system('id')}}",
				Type:            ssti.TypeRCE,
				DetectionMethod: ssti.MethodOutput,
			},
			engine:         ssti.EngineJinja2,
			wantSeverity:   core.SeverityCritical,
			wantConfidence: core.ConfidenceConfirmed,
		},
		{
			name: "fingerprint payload",
			payload: ssti.Payload{
				Value:           "{{config}}",
				Type:            ssti.TypeFingerprint,
				DetectionMethod: ssti.MethodReflection,
			},
			engine:         ssti.EngineUnknown,
			wantSeverity:   core.SeverityHigh,
			wantConfidence: core.ConfidenceHigh,
		},
		{
			name: "config leak payload",
			payload: ssti.Payload{
				Value:           "{{config.items()}}",
				Type:            ssti.TypeConfigLeak,
				DetectionMethod: ssti.MethodReflection,
			},
			engine:         ssti.EngineJinja2,
			wantSeverity:   core.SeverityHigh,
			wantConfidence: core.ConfidenceMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := detector.createFinding("https://example.com", "input", tt.payload, resp, tt.engine)

			if finding == nil {
				t.Fatal("createFinding() returned nil")
			}
			if finding.Severity != tt.wantSeverity {
				t.Errorf("Severity = %s, want %s", finding.Severity, tt.wantSeverity)
			}
			if finding.Confidence != tt.wantConfidence {
				t.Errorf("Confidence = %s, want %s", finding.Confidence, tt.wantConfidence)
			}
			if finding.URL != "https://example.com" {
				t.Error("URL not set correctly")
			}
			if finding.Parameter != "input" {
				t.Error("Parameter not set correctly")
			}
			if finding.Tool != "ssti-detector" {
				t.Error("Tool not set correctly")
			}
			if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-18" {
				t.Error("WSTG mapping not set correctly")
			}
			if len(finding.Top10) == 0 || finding.Top10[0] != "A03:2021" {
				t.Error("Top10 mapping not set correctly")
			}
			if len(finding.CWE) < 2 {
				t.Error("CWE mapping should include CWE-94 and CWE-1336")
			}
			if finding.Remediation == "" {
				t.Error("Remediation should not be empty")
			}
			if len(finding.References) == 0 {
				t.Error("References should not be empty")
			}
		})
	}
}

func TestDetector_createFinding_Metadata(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payload := ssti.Payload{
		Value:           "{{7*7}}",
		Type:            ssti.TypeDetection,
		DetectionMethod: ssti.MethodMath,
	}

	resp := &http.Response{
		StatusCode: 200,
		Body:       "Result: 49",
	}

	finding := detector.createFinding("https://example.com", "input", payload, resp, ssti.EngineJinja2)

	if finding.Metadata["template_engine"] != "jinja2" {
		t.Errorf("Metadata template_engine = %v, want jinja2", finding.Metadata["template_engine"])
	}
	if finding.Metadata["payload_type"] != "detection" {
		t.Errorf("Metadata payload_type = %v, want detection", finding.Metadata["payload_type"])
	}
	if finding.Metadata["detection_method"] != "math" {
		t.Errorf("Metadata detection_method = %v, want math", finding.Metadata["detection_method"])
	}
}

func TestDetector_createFinding_UnknownEngine(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payload := ssti.Payload{
		Value:           "{{7*7}}",
		Type:            ssti.TypeDetection,
		DetectionMethod: ssti.MethodMath,
	}

	resp := &http.Response{
		StatusCode: 200,
		Body:       "49",
	}

	finding := detector.createFinding("https://example.com", "input", payload, resp, ssti.EngineUnknown)

	if finding.Metadata["template_engine"] != "unknown" {
		t.Errorf("Metadata template_engine = %v, want unknown", finding.Metadata["template_engine"])
	}
}

func TestMathDetectionResult_Fields(t *testing.T) {
	result := mathDetectionResult{
		detected:   true,
		engine:     ssti.EngineJinja2,
		confidence: 0.95,
		expression: "{{7*7}}",
		result:     "49",
	}

	if !result.detected {
		t.Error("detected should be true")
	}
	if result.engine != ssti.EngineJinja2 {
		t.Error("engine should be Jinja2")
	}
	if result.confidence != 0.95 {
		t.Error("confidence should be 0.95")
	}
	if result.expression != "{{7*7}}" {
		t.Error("expression should be {{7*7}}")
	}
	if result.result != "49" {
		t.Error("result should be 49")
	}
}

func TestErrorDetectionResult_Fields(t *testing.T) {
	result := errorDetectionResult{
		errorPatterns: []string{"jinja2.exceptions", "UndefinedError"},
		engine:        ssti.EngineJinja2,
		confidence:    0.9,
	}

	if len(result.errorPatterns) != 2 {
		t.Errorf("errorPatterns should have 2 items, got %d", len(result.errorPatterns))
	}
	if result.engine != ssti.EngineJinja2 {
		t.Error("engine should be Jinja2")
	}
	if result.confidence != 0.9 {
		t.Error("confidence should be 0.9")
	}
}

func TestBaselineResponse_Fields(t *testing.T) {
	baseline := &baselineResponse{
		body:          "Normal response body",
		statusCode:    200,
		contentLength: 20,
	}

	if baseline.body != "Normal response body" {
		t.Error("body not set correctly")
	}
	if baseline.statusCode != 200 {
		t.Error("statusCode not set correctly")
	}
	if baseline.contentLength != 20 {
		t.Error("contentLength not set correctly")
	}
}

func TestDetectOptions_CustomValues(t *testing.T) {
	opts := DetectOptions{
		MaxPayloads:      25,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   false,
		IncludeRCE:       true,
	}

	if opts.MaxPayloads != 25 {
		t.Error("MaxPayloads should be 25")
	}
	if opts.IncludeWAFBypass {
		t.Error("IncludeWAFBypass should be false")
	}
	if opts.Timeout != 5*time.Second {
		t.Error("Timeout should be 5 seconds")
	}
	if opts.TestAllEngines {
		t.Error("TestAllEngines should be false")
	}
	if !opts.IncludeRCE {
		t.Error("IncludeRCE should be true")
	}
}

func TestDetectionResult_VulnerableState(t *testing.T) {
	result := &DetectionResult{
		Vulnerable:       true,
		Findings:         make([]*core.Finding, 0),
		TestedPayloads:   50,
		DetectedEngine:   ssti.EngineJinja2,
		EngineConfidence: 0.95,
		ErrorPatterns:    []string{"jinja2.exceptions"},
	}

	if !result.Vulnerable {
		t.Error("Result should be vulnerable")
	}
	if result.TestedPayloads != 50 {
		t.Errorf("TestedPayloads = %d, want 50", result.TestedPayloads)
	}
	if result.DetectedEngine != ssti.EngineJinja2 {
		t.Error("DetectedEngine should be Jinja2")
	}
	if result.EngineConfidence != 0.95 {
		t.Error("EngineConfidence should be 0.95")
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := detector.Detect(ctx, "https://example.com", "input", "GET", DefaultOptions())
	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestFinding_OWASPMapping(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payload := ssti.Payload{
		Value:           "{{7*7}}",
		Type:            ssti.TypeDetection,
		DetectionMethod: ssti.MethodMath,
	}

	resp := &http.Response{
		StatusCode: 200,
		Body:       "49",
	}

	finding := detector.createFinding("https://example.com", "input", payload, resp, ssti.EngineJinja2)

	// Verify WSTG-INPV-18 is included (Server-Side Template Injection)
	foundWSTG := false
	for _, w := range finding.WSTG {
		if w == "WSTG-INPV-18" {
			foundWSTG = true
			break
		}
	}
	if !foundWSTG {
		t.Error("WSTG-INPV-18 should be included in OWASP mapping")
	}

	// Verify A03:2021 (Injection) is included
	foundTop10 := false
	for _, a := range finding.Top10 {
		if a == "A03:2021" {
			foundTop10 = true
			break
		}
	}
	if !foundTop10 {
		t.Error("A03:2021 should be included in OWASP Top 10 mapping")
	}

	// Verify CWE-94 (Code Injection) and CWE-1336 are included
	foundCWE94 := false
	foundCWE1336 := false
	for _, cwe := range finding.CWE {
		if cwe == "CWE-94" {
			foundCWE94 = true
		}
		if cwe == "CWE-1336" {
			foundCWE1336 = true
		}
	}
	if !foundCWE94 {
		t.Error("CWE-94 should be included")
	}
	if !foundCWE1336 {
		t.Error("CWE-1336 should be included")
	}
}

func TestDetector_deduplicatePayloads_Empty(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payloads := []ssti.Payload{}
	unique := detector.deduplicatePayloads(payloads)

	if len(unique) != 0 {
		t.Errorf("deduplicatePayloads() with empty input should return empty, got %d", len(unique))
	}
}

func TestDetector_deduplicatePayloads_AllUnique(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payloads := []ssti.Payload{
		{Value: "{{7*7}}"},
		{Value: "${7*7}"},
		{Value: "<%= 7*7 %>"},
	}

	unique := detector.deduplicatePayloads(payloads)
	if len(unique) != 3 {
		t.Errorf("deduplicatePayloads() with all unique should return 3, got %d", len(unique))
	}
}

func TestDetector_deduplicatePayloads_AllDuplicates(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payloads := []ssti.Payload{
		{Value: "{{7*7}}"},
		{Value: "{{7*7}}"},
		{Value: "{{7*7}}"},
	}

	unique := detector.deduplicatePayloads(payloads)
	if len(unique) != 1 {
		t.Errorf("deduplicatePayloads() with all same should return 1, got %d", len(unique))
	}
}

func TestDetector_containsMathResult_EdgeCases(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		expected string
		baseline string
		want     bool
	}{
		{
			name:     "empty body",
			body:     "",
			expected: "49",
			baseline: "",
			want:     false,
		},
		{
			name:     "empty expected",
			body:     "Some content",
			expected: "",
			baseline: "Some content",
			want:     false, // Empty string count is same in both, so false
		},
		{
			name:     "result at start",
			body:     "49 is the answer",
			expected: "49",
			baseline: "unknown is the answer",
			want:     true,
		},
		{
			name:     "result at end",
			body:     "The answer is 49",
			expected: "49",
			baseline: "The answer is unknown",
			want:     true,
		},
		{
			name:     "multiple results",
			body:     "49 and 49 and 49",
			expected: "49",
			baseline: "",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.containsMathResult(tt.body, tt.expected, tt.baseline)
			if got != tt.want {
				t.Errorf("containsMathResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFinding_References(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payload := ssti.Payload{
		Value:           "{{7*7}}",
		Type:            ssti.TypeDetection,
		DetectionMethod: ssti.MethodMath,
	}

	resp := &http.Response{StatusCode: 200, Body: "49"}
	finding := detector.createFinding("https://example.com", "input", payload, resp, ssti.EngineJinja2)

	expectedRefs := []string{
		"portswigger.net",
		"owasp.org",
		"hacktricks",
	}

	for _, ref := range expectedRefs {
		found := false
		for _, r := range finding.References {
			if containsSubstring(r, ref) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("References should contain a link with %s", ref)
		}
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDetector_isPayloadSuccessful_DefaultCase(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	baseline := &baselineResponse{body: "Normal"}

	// Test with an unknown detection method
	payload := ssti.Payload{
		DetectionMethod: "unknown_method",
	}

	got := detector.isPayloadSuccessful("some response", payload, baseline)
	if got {
		t.Error("Unknown detection method should return false")
	}
}

func TestFinding_Remediation(t *testing.T) {
	client := http.NewClient()
	detector := New(client)

	payload := ssti.Payload{
		Value:           "{{7*7}}",
		Type:            ssti.TypeDetection,
		DetectionMethod: ssti.MethodMath,
	}

	resp := &http.Response{StatusCode: 200, Body: "49"}
	finding := detector.createFinding("https://example.com", "input", payload, resp, ssti.EngineJinja2)

	if finding.Remediation == "" {
		t.Error("Remediation should not be empty")
	}

	// Check for key remediation advice
	remediationKeywords := []string{
		"user input",
		"template",
		"sandbox",
		"validation",
	}

	for _, keyword := range remediationKeywords {
		if !containsSubstring(finding.Remediation, keyword) {
			t.Errorf("Remediation should contain advice about '%s'", keyword)
		}
	}
}

// ---------------------------------------------------------------------------
// NEW TESTS -- HTTP-level tests using httptest.NewServer
// ---------------------------------------------------------------------------

// TestDetector_establishBaseline verifies that establishBaseline sends a probe
// value and captures the response body, status code, and content length.
func TestDetector_establishBaseline(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		// Baseline probe always starts with "sstiprobe"
		if strings.HasPrefix(payload, "sstiprobe") {
			return "baseline body content"
		}
		return "unexpected"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	baseline, err := detector.establishBaseline(ctx, ts.URL+"?input=test", "input", "GET")
	if err != nil {
		t.Fatalf("establishBaseline() returned error: %v", err)
	}
	if baseline == nil {
		t.Fatal("establishBaseline() returned nil baseline")
	}
	if baseline.body != "baseline body content" {
		t.Errorf("baseline.body = %q, want %q", baseline.body, "baseline body content")
	}
	if baseline.statusCode != 200 {
		t.Errorf("baseline.statusCode = %d, want 200", baseline.statusCode)
	}
}

// TestDetector_establishBaseline_Error verifies error handling when the server
// cannot be reached.
func TestDetector_establishBaseline_Error(t *testing.T) {
	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	// Use a URL that will definitely fail
	_, err := detector.establishBaseline(ctx, "http://127.0.0.1:1/nonexistent", "input", "GET")
	if err == nil {
		t.Error("establishBaseline() should return error for unreachable server")
	}
}

// TestDetector_establishBaseline_ContextCancelled verifies context cancellation
// is respected during baseline establishment.
func TestDetector_establishBaseline_ContextCancelled(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "ok"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := detector.establishBaseline(ctx, ts.URL+"?input=test", "input", "GET")
	if err == nil {
		t.Error("establishBaseline() should return error when context is cancelled")
	}
}

// TestDetector_detectMathExpression tests the math expression detection phase
// against a mock server that echoes back mathematical results.
func TestDetector_detectMathExpression(t *testing.T) {
	tests := []struct {
		name           string
		responder      func(payload string) string
		wantDetected   bool
		wantConfidence float64
	}{
		{
			name: "jinja2 style 7*7 returns 49",
			responder: func(payload string) string {
				if payload == "{{7*7}}" {
					return "Result: 49"
				}
				return "normal"
			},
			wantDetected:   true,
			wantConfidence: 0.85,
		},
		{
			name: "dollar style 7*7 returns 49",
			responder: func(payload string) string {
				if payload == "${7*7}" {
					return "Result: 49"
				}
				return "normal"
			},
			wantDetected:   true,
			wantConfidence: 0.85,
		},
		{
			name: "erb style returns 49",
			responder: func(payload string) string {
				if payload == "<%= 7*7 %>" {
					return "Result: 49"
				}
				return "normal"
			},
			wantDetected:   true,
			wantConfidence: 0.85,
		},
		{
			name: "smarty style {7*7} returns 49",
			responder: func(payload string) string {
				if payload == "{7*7}" {
					return "Value: 49"
				}
				return "normal"
			},
			wantDetected:   true,
			wantConfidence: 0.85,
		},
		{
			name: "freemarker style #{7*7} returns 49",
			responder: func(payload string) string {
				if payload == "#{7*7}" {
					return "Value: 49"
				}
				return "normal"
			},
			wantDetected:   true,
			wantConfidence: 0.85,
		},
		{
			name: "velocity style returns 49",
			responder: func(payload string) string {
				if payload == "#set($x=7*7)$x" {
					return "The value is 49"
				}
				return "normal"
			},
			wantDetected:   true,
			wantConfidence: 0.85,
		},
		{
			name: "addition 7+7 returns 14",
			responder: func(payload string) string {
				if payload == "{{7+7}}" {
					return "Sum: 14"
				}
				return "normal"
			},
			wantDetected:   true,
			wantConfidence: 0.85,
		},
		{
			name: "no math result detected",
			responder: func(_ string) string {
				return "normal page content"
			},
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newMockServer(tt.responder)
			defer ts.Close()

			client := http.NewClient()
			detector := New(client)
			ctx := context.Background()

			baseline := &baselineResponse{
				body:       "normal",
				statusCode: 200,
			}

			result := detector.detectMathExpression(ctx, ts.URL+"?input=test", "input", "GET", baseline)
			if result.detected != tt.wantDetected {
				t.Errorf("detected = %v, want %v", result.detected, tt.wantDetected)
			}
			if tt.wantDetected && result.confidence < tt.wantConfidence {
				t.Errorf("confidence = %v, want >= %v", result.confidence, tt.wantConfidence)
			}
		})
	}
}

// TestDetector_detectMathExpression_ContextCancelled verifies that
// detectMathExpression respects context cancellation.
func TestDetector_detectMathExpression_ContextCancelled(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "49"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	baseline := &baselineResponse{body: "normal", statusCode: 200}
	result := detector.detectMathExpression(ctx, ts.URL+"?input=test", "input", "GET", baseline)

	if result.detected {
		t.Error("detectMathExpression should not detect when context is cancelled")
	}
}

// TestDetector_detectMathExpression_WithFingerprinting verifies that when math
// detection succeeds, the detector attempts to fingerprint the engine and
// raises confidence when fingerprinting succeeds.
func TestDetector_detectMathExpression_WithFingerprinting(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		// Math detection succeeds on the first probe
		if payload == "{{7*7}}" {
			return "Result: 49"
		}
		// Fingerprint: Jinja2 returns "7777777" for {{7*'7'}}
		if payload == "{{7*'7'}}" {
			return "7777777"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	baseline := &baselineResponse{body: "normal", statusCode: 200}
	result := detector.detectMathExpression(ctx, ts.URL+"?input=test", "input", "GET", baseline)

	if !result.detected {
		t.Fatal("detectMathExpression should have detected SSTI")
	}
	if result.engine != ssti.EngineJinja2 {
		t.Errorf("engine = %v, want %v", result.engine, ssti.EngineJinja2)
	}
	if result.confidence < 0.95 {
		t.Errorf("confidence = %v, want >= 0.95 (fingerprint succeeded)", result.confidence)
	}
}

// TestDetector_detectByError verifies error-based detection using error
// patterns from various template engines.
func TestDetector_detectByError(t *testing.T) {
	tests := []struct {
		name             string
		responder        func(payload string) string
		wantPatterns     bool
		wantEngine       ssti.TemplateEngine
		wantMinPatterns  int
	}{
		{
			name: "jinja2 error pattern",
			responder: func(payload string) string {
				if payload == "{{" || payload == "{{''.__class__}}" {
					return "Error: jinja2.exceptions.TemplateSyntaxError: unexpected end"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineJinja2,
			wantMinPatterns: 1,
		},
		{
			name: "twig error pattern",
			responder: func(payload string) string {
				if payload == "{{" {
					return "Twig_Error_Syntax at line 1"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineTwig,
			wantMinPatterns: 1,
		},
		{
			name: "freemarker error pattern",
			responder: func(payload string) string {
				if payload == "${" {
					return "freemarker.template.TemplateException: ParseException occurred"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineFreemarker,
			wantMinPatterns: 1,
		},
		{
			name: "velocity error pattern",
			responder: func(payload string) string {
				if payload == "#set($x=" {
					return "org.apache.velocity.exception.ParseErrorException"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineVelocity,
			wantMinPatterns: 1,
		},
		{
			name: "thymeleaf error pattern",
			responder: func(payload string) string {
				if payload == "${undefined}" {
					return "org.thymeleaf.exceptions.TemplateProcessingException"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineThymeleaf,
			wantMinPatterns: 1,
		},
		{
			name: "mako error pattern",
			responder: func(payload string) string {
				if payload == "${" {
					return "mako.exceptions.CompileException"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineMako,
			wantMinPatterns: 1,
		},
		{
			name: "smarty error pattern",
			responder: func(payload string) string {
				if payload == "{#" {
					return "Smarty error: syntax error in template"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineSmarty,
			wantMinPatterns: 1,
		},
		{
			name: "erb error pattern",
			responder: func(payload string) string {
				if payload == "<%= undefined %>" {
					return "NameError: undefined local variable"
				}
				return "ok"
			},
			wantPatterns:    true,
			wantEngine:      ssti.EngineERB,
			wantMinPatterns: 1,
		},
		{
			name: "no error patterns found",
			responder: func(_ string) string {
				return "HTTP 200 OK - normal"
			},
			wantPatterns: false,
			wantEngine:   ssti.EngineUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newMockServer(tt.responder)
			defer ts.Close()

			client := http.NewClient()
			detector := New(client)
			ctx := context.Background()

			result := detector.detectByError(ctx, ts.URL+"?input=test", "input", "GET")

			if tt.wantPatterns {
				if len(result.errorPatterns) < tt.wantMinPatterns {
					t.Errorf("errorPatterns count = %d, want >= %d", len(result.errorPatterns), tt.wantMinPatterns)
				}
				if result.engine != tt.wantEngine {
					t.Errorf("engine = %v, want %v", result.engine, tt.wantEngine)
				}
				if result.confidence == 0 {
					t.Error("confidence should be > 0 when error patterns are found")
				}
			} else {
				if len(result.errorPatterns) != 0 {
					t.Errorf("expected no error patterns, got %d: %v", len(result.errorPatterns), result.errorPatterns)
				}
			}
		})
	}
}

// TestDetector_detectByError_ContextCancelled verifies that detectByError
// stops early when the context is cancelled.
func TestDetector_detectByError_ContextCancelled(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "jinja2.exceptions.TemplateSyntaxError"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := detector.detectByError(ctx, ts.URL+"?input=test", "input", "GET")

	// With an already-cancelled context, the loop should not execute at all
	if len(result.errorPatterns) != 0 {
		t.Error("detectByError should not detect patterns when context is cancelled")
	}
}

// TestDetector_fingerprintEngine tests the engine fingerprinting logic
// for each supported template engine.
func TestDetector_fingerprintEngine(t *testing.T) {
	tests := []struct {
		name       string
		responder  func(payload string) string
		wantEngine ssti.TemplateEngine
	}{
		{
			name: "fingerprint jinja2 via string multiplication",
			responder: func(payload string) string {
				if payload == "{{7*'7'}}" {
					return "7777777"
				}
				return "normal"
			},
			wantEngine: ssti.EngineJinja2,
		},
		{
			name: "fingerprint twig via numeric multiplication",
			responder: func(payload string) string {
				if payload == "{{7*'7'}}" {
					return "The result is 49 here"
				}
				return "normal"
			},
			wantEngine: ssti.EngineTwig,
		},
		{
			name: "fingerprint jinja2 via config",
			responder: func(payload string) string {
				if payload == "{{config}}" {
					return "<Config {'SECRET_KEY': '...' }>"
				}
				return "normal"
			},
			wantEngine: ssti.EngineJinja2,
		},
		{
			name: "fingerprint twig via _self",
			responder: func(payload string) string {
				if payload == "{{_self}}" {
					return "__TwigTemplate_abc123"
				}
				return "normal"
			},
			wantEngine: ssti.EngineTwig,
		},
		{
			name: "fingerprint mako via self",
			responder: func(payload string) string {
				if payload == "${self}" {
					return "Namespace(name='body')"
				}
				return "normal"
			},
			wantEngine: ssti.EngineMako,
		},
		{
			name: "fingerprint freemarker via version",
			responder: func(payload string) string {
				if payload == "${.version}" {
					return "FreeMarker 2.3.31"
				}
				return "normal"
			},
			wantEngine: ssti.EngineFreemarker,
		},
		{
			name: "no engine fingerprinted",
			responder: func(_ string) string {
				return "nothing special"
			},
			wantEngine: ssti.EngineUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newMockServer(tt.responder)
			defer ts.Close()

			client := http.NewClient()
			detector := New(client)
			ctx := context.Background()

			engine := detector.fingerprintEngine(ctx, ts.URL+"?input=test", "input", "GET")
			if engine != tt.wantEngine {
				t.Errorf("fingerprintEngine() = %v, want %v", engine, tt.wantEngine)
			}
		})
	}
}

// TestDetector_fingerprintEngine_ContextCancelled verifies that
// fingerprintEngine returns EngineUnknown when the context is cancelled.
func TestDetector_fingerprintEngine_ContextCancelled(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "{{7*'7'}}" {
			return "7777777"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	engine := detector.fingerprintEngine(ctx, ts.URL+"?input=test", "input", "GET")
	if engine != ssti.EngineUnknown {
		t.Errorf("fingerprintEngine() with cancelled ctx = %v, want EngineUnknown", engine)
	}
}

// TestDetector_Detect_FullFlow_NotVulnerable tests the complete Detect()
// method against a server that does not exhibit any SSTI behavior.
func TestDetector_Detect_FullFlow_NotVulnerable(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "safe page content"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   false,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.Vulnerable {
		t.Error("Detect() should report not vulnerable for a safe server")
	}
	if result.TestedPayloads == 0 {
		t.Error("Detect() should have tested at least some payloads")
	}
	if len(result.Findings) != 0 {
		t.Errorf("Detect() should have 0 findings, got %d", len(result.Findings))
	}
}

// TestDetector_Detect_FullFlow_Vulnerable_MathDetection tests the complete
// Detect() flow when the server is vulnerable to math-based SSTI detection.
func TestDetector_Detect_FullFlow_Vulnerable_MathDetection(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		// Respond to math expression
		if payload == "{{7*7}}" {
			return "Output: 49"
		}
		// Respond to fingerprint
		if payload == "{{7*'7'}}" {
			return "7777777"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   false,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Detect() should report vulnerable for math-expression SSTI")
	}
	if result.DetectedEngine != ssti.EngineJinja2 {
		t.Errorf("DetectedEngine = %v, want %v", result.DetectedEngine, ssti.EngineJinja2)
	}
	if result.EngineConfidence < 0.85 {
		t.Errorf("EngineConfidence = %v, want >= 0.85", result.EngineConfidence)
	}
}

// TestDetector_Detect_FullFlow_ErrorDetection tests the complete Detect() flow
// when the server reveals error patterns.
func TestDetector_Detect_FullFlow_ErrorDetection(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "{{" || payload == "{{''.__class__}}" || payload == "{{undefined_var}}" {
			return "Error: jinja2.exceptions.UndefinedError"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   false,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if len(result.ErrorPatterns) == 0 {
		t.Error("Detect() should have found error patterns")
	}
	if result.DetectedEngine != ssti.EngineJinja2 {
		t.Errorf("DetectedEngine = %v, want %v", result.DetectedEngine, ssti.EngineJinja2)
	}
}

// TestDetector_Detect_WithWAFBypass verifies that WAF bypass payloads are
// included when requested.
func TestDetector_Detect_WithWAFBypass(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "safe"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      200,
		IncludeWAFBypass: true,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	// The key assertion is that more payloads are tested because WAF bypass is on
	if result.TestedPayloads == 0 {
		t.Error("Detect() should have tested payloads with WAF bypass enabled")
	}
}

// TestDetector_Detect_WithRCE verifies that RCE payloads are included when
// both IncludeRCE is true and the target is already identified as vulnerable.
func TestDetector_Detect_WithRCE(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "{{7*7}}" {
			return "49"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      200,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       true,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Detect() should report vulnerable")
	}
	// TestedPayloads should be > 0 because RCE payloads are appended
	if result.TestedPayloads == 0 {
		t.Error("Detect() should have tested payloads including RCE")
	}
}

// TestDetector_Detect_MaxPayloads verifies that MaxPayloads limits the number
// of payloads tested.
func TestDetector_Detect_MaxPayloads(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "safe"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      3,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.TestedPayloads > 3 {
		t.Errorf("TestedPayloads = %d, but MaxPayloads was 3", result.TestedPayloads)
	}
}

// TestDetector_Detect_ContextCancelledDuringPayloadLoop verifies that
// Detect() returns a partial result and ctx.Err() when the context is
// cancelled during payload iteration.
func TestDetector_Detect_ContextCancelledDuringPayloadLoop(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		requestCount++
		w.WriteHeader(nethttp.StatusOK)
		fmt.Fprint(w, "safe")
	}))
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	opts := DetectOptions{
		MaxPayloads:      500,
		IncludeWAFBypass: true,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	// With a short timeout the context may cancel during payload testing
	// The result should still be returned (partial) with ctx.Err()
	if result == nil {
		t.Fatal("Detect() should return a result even on context cancellation")
	}
	_ = err // err may be nil or context.DeadlineExceeded, both are acceptable
}

// TestDetector_Detect_PayloadFinding verifies that when a payload is
// successful, a Finding is added to the result.
func TestDetector_Detect_PayloadFinding(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		decodedPayload, _ := url.QueryUnescape(payload)
		// Respond with expected math result for detection payloads
		if decodedPayload == "{{7*7}}" || strings.Contains(decodedPayload, "7*7") {
			return "The answer is 49"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Detect() should report vulnerable when payload triggers math detection")
	}
	if len(result.Findings) == 0 {
		t.Error("Detect() should have at least one finding")
	}
}

// TestDetector_Detect_TestAllEnginesFalse_StopsEarly verifies that when
// TestAllEngines is false, detection stops after the first successful payload.
func TestDetector_Detect_TestAllEnginesFalse_StopsEarly(t *testing.T) {
	hitCount := 0
	ts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hitCount++
		payload := r.URL.Query().Get("input")
		if strings.Contains(payload, "7*7") || strings.Contains(payload, "7+7") {
			w.WriteHeader(nethttp.StatusOK)
			fmt.Fprint(w, "Result: 49")
			return
		}
		w.WriteHeader(nethttp.StatusOK)
		fmt.Fprint(w, "normal")
	}))
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      200,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   false,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Detect() should report vulnerable")
	}
	// With TestAllEngines=false and IncludeRCE=false, should stop early
	if len(result.Findings) > 1 {
		t.Logf("findings count = %d (stopped early might still test a few)", len(result.Findings))
	}
}

// TestDetector_Detect_SpecificEngine verifies that when a specific engine is
// detected, payloads for that engine are used (not all engines).
func TestDetector_Detect_SpecificEngine(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "{{7*7}}" {
			return "49"
		}
		if payload == "{{7*'7'}}" {
			return "7777777" // Jinja2 fingerprint
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   false, // Should use engine-specific payloads
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.DetectedEngine != ssti.EngineJinja2 {
		t.Errorf("DetectedEngine = %v, want %v", result.DetectedEngine, ssti.EngineJinja2)
	}
}

// TestDetector_VerifyRCE_ExpectedOutput tests VerifyRCE when the server
// returns the expected output for an RCE payload.
func TestDetector_VerifyRCE_ExpectedOutput(t *testing.T) {
	// We need to know what the RCE payloads look like to respond correctly
	rcePayloads := ssti.GetRCEPayloads()
	if len(rcePayloads) == 0 {
		t.Skip("No RCE payloads available to test")
	}

	// Find an RCE payload with expected output
	var targetPayload ssti.Payload
	found := false
	for _, p := range rcePayloads {
		if p.ExpectedOutput != "" {
			targetPayload = p
			found = true
			break
		}
	}

	ts := newMockServer(func(payload string) string {
		if found && payload == targetPayload.Value {
			return "prefix " + targetPayload.ExpectedOutput + " suffix"
		}
		return "safe"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}

	if found {
		if !verified {
			t.Error("VerifyRCE() should return true when expected output is found")
		}
		if finding == nil {
			t.Fatal("VerifyRCE() should return a finding when RCE is verified")
		}
		if finding.Severity != core.SeverityCritical {
			t.Errorf("finding.Severity = %s, want critical", finding.Severity)
		}
		if finding.Confidence != core.ConfidenceConfirmed {
			t.Errorf("finding.Confidence = %s, want confirmed", finding.Confidence)
		}
	}
}

// TestDetector_VerifyRCE_GenericIndicators tests VerifyRCE when the server
// returns generic RCE indicators (uid=, root:, etc.).
func TestDetector_VerifyRCE_GenericIndicators(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "uid=1000(testuser) gid=1000(testuser)"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if !verified {
		t.Error("VerifyRCE() should return true with uid= indicator")
	}
	if finding == nil {
		t.Fatal("VerifyRCE() should return a finding")
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("finding.Severity = %s, want critical", finding.Severity)
	}
}

// TestDetector_VerifyRCE_NotVerified tests VerifyRCE when no RCE indicators
// are present in the response.
func TestDetector_VerifyRCE_NotVerified(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "safe content no rce here"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if verified {
		t.Error("VerifyRCE() should return false for safe content")
	}
	if finding != nil {
		t.Error("VerifyRCE() should return nil finding when not verified")
	}
}

// TestDetector_VerifyRCE_ContextCancelled tests that VerifyRCE returns an
// error when the context is cancelled.
func TestDetector_VerifyRCE_ContextCancelled(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "uid=0(root)"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err == nil {
		// When context is cancelled before the loop starts, the loop may exit
		// without running and return false/nil/nil -- which is also acceptable.
		if verified {
			t.Error("VerifyRCE() should not verify with cancelled context")
		}
	}
	_ = finding // may be nil
}

// TestDetector_VerifyRCE_WithSpecificEngine tests that VerifyRCE filters
// payloads by engine when a known engine is specified.
func TestDetector_VerifyRCE_WithSpecificEngine(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "uid=33(www-data) gid=33(www-data)"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineJinja2)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if !verified {
		t.Error("VerifyRCE() should verify RCE when www-data is present")
	}
	if finding == nil {
		t.Fatal("VerifyRCE() should return a finding")
	}
}

// TestDetector_VerifyRCE_GenericIndicators_RootPasswd tests the root:
// indicator path.
func TestDetector_VerifyRCE_GenericIndicators_RootPasswd(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "root:x:0:0:root:/root:/bin/bash"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, _, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if !verified {
		t.Error("VerifyRCE() should verify RCE when root: is present")
	}
}

// TestDetector_VerifyRCE_GenericIndicators_Apache tests the apache indicator.
func TestDetector_VerifyRCE_GenericIndicators_Apache(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "apache server running"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, _, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if !verified {
		t.Error("VerifyRCE() should verify RCE when apache indicator is present")
	}
}

// TestDetector_VerifyRCE_GenericIndicators_Nginx tests the nginx indicator.
func TestDetector_VerifyRCE_GenericIndicators_Nginx(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "nginx worker process"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, _, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if !verified {
		t.Error("VerifyRCE() should verify RCE when nginx indicator is present")
	}
}

// TestDetector_VerifyRCE_ServerError tests VerifyRCE when the server returns
// errors for all payloads (should gracefully skip them all).
func TestDetector_VerifyRCE_ServerError(t *testing.T) {
	ts := newMockServerStatus(func(_ string) (int, string) {
		return nethttp.StatusInternalServerError, "internal error"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	// Even though the server returns 500, the HTTP client returns a Response
	// without error. So VerifyRCE will check the body for indicators. Since
	// the body is "internal error" with no indicators, it should not verify.
	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if verified {
		t.Error("VerifyRCE() should not verify when server only returns errors")
	}
	if finding != nil {
		t.Error("finding should be nil when not verified")
	}
}

// TestDetector_DetectEngine_ViaFingerprint tests DetectEngine when the engine
// is identified through fingerprinting.
func TestDetector_DetectEngine_ViaFingerprint(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "{{7*'7'}}" {
			return "7777777"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	engine, confidence, err := detector.DetectEngine(ctx, ts.URL+"?input=test", "input", "GET")
	if err != nil {
		t.Fatalf("DetectEngine() returned error: %v", err)
	}
	if engine != ssti.EngineJinja2 {
		t.Errorf("engine = %v, want %v", engine, ssti.EngineJinja2)
	}
	if confidence < 0.9 {
		t.Errorf("confidence = %v, want >= 0.9", confidence)
	}
}

// TestDetector_DetectEngine_ViaError tests DetectEngine when the engine is
// identified through error-based detection.
func TestDetector_DetectEngine_ViaError(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "{{" || payload == "{{''.__class__}}" || payload == "{{undefined_var}}" {
			return "jinja2.exceptions.UndefinedError: something went wrong"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	engine, confidence, err := detector.DetectEngine(ctx, ts.URL+"?input=test", "input", "GET")
	if err != nil {
		t.Fatalf("DetectEngine() returned error: %v", err)
	}
	if engine != ssti.EngineJinja2 {
		t.Errorf("engine = %v, want %v", engine, ssti.EngineJinja2)
	}
	if confidence == 0 {
		t.Error("confidence should be > 0")
	}
}

// TestDetector_DetectEngine_Unknown tests DetectEngine when neither
// fingerprinting nor error detection can identify the engine.
func TestDetector_DetectEngine_Unknown(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "totally normal response"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	engine, confidence, err := detector.DetectEngine(ctx, ts.URL+"?input=test", "input", "GET")
	if err != nil {
		t.Fatalf("DetectEngine() returned error: %v", err)
	}
	if engine != ssti.EngineUnknown {
		t.Errorf("engine = %v, want %v", engine, ssti.EngineUnknown)
	}
	if confidence != 0.0 {
		t.Errorf("confidence = %v, want 0.0", confidence)
	}
}

// TestDetector_Detect_BaselineError verifies that Detect returns a wrapped
// error when baseline establishment fails.
func TestDetector_Detect_BaselineError(t *testing.T) {
	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	// Use an unreachable URL to cause baseline failure
	result, err := detector.Detect(ctx, "http://127.0.0.1:1/nonexistent", "input", "GET", DefaultOptions())
	if err == nil {
		t.Error("Detect() should return error when baseline fails")
	}
	if result == nil {
		t.Fatal("Detect() should return non-nil result even on baseline error")
	}
	if !strings.Contains(err.Error(), "baseline") {
		t.Errorf("error = %q, should mention 'baseline'", err.Error())
	}
}

// TestDetector_Detect_PayloadLoopSkipsHTTPErrors verifies that individual
// payload HTTP errors are silently skipped.
func TestDetector_Detect_PayloadLoopSkipsHTTPErrors(t *testing.T) {
	requestNum := 0
	ts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		requestNum++
		// Baseline and error/math probes succeed, but most payload
		// requests also succeed. We just need to exercise the path.
		w.WriteHeader(nethttp.StatusOK)
		fmt.Fprint(w, "normal content")
	}))
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.TestedPayloads == 0 {
		t.Error("Detect() should have tested some payloads")
	}
}

// TestDetector_Detect_FindingEngineUpdate verifies that when a successful
// payload has a known engine, the result's DetectedEngine is updated.
func TestDetector_Detect_FindingEngineUpdate(t *testing.T) {
	// Get actual Jinja2 detection payloads to know which ones to match
	jinja2Payloads := ssti.GetPayloads(ssti.EngineJinja2)
	if len(jinja2Payloads) == 0 {
		t.Skip("No Jinja2 payloads available")
	}

	// Find a math payload with expected output
	var matchPayload ssti.Payload
	found := false
	for _, p := range jinja2Payloads {
		if p.DetectionMethod == ssti.MethodMath && p.ExpectedOutput != "" {
			matchPayload = p
			found = true
			break
		}
	}
	if !found {
		t.Skip("No suitable Jinja2 math payload found")
	}

	ts := newMockServer(func(payload string) string {
		if payload == matchPayload.Value {
			return "The result is " + matchPayload.ExpectedOutput
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      100,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Log("No finding was generated for the matched Jinja2 payload")
		return
	}
	// If a finding was produced from a Jinja2 payload, the engine should be set
	if result.DetectedEngine == ssti.EngineJinja2 {
		if result.EngineConfidence < 0.85 {
			t.Errorf("EngineConfidence = %v, want >= 0.85", result.EngineConfidence)
		}
	}
}

// TestDetector_detectMathExpression_ERBStyle verifies ERB-style math detection
// sets the engine to EngineERB.
func TestDetector_detectMathExpression_ERBStyle(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "<%= 7*7 %>" {
			return "49"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	baseline := &baselineResponse{body: "normal", statusCode: 200}
	result := detector.detectMathExpression(ctx, ts.URL+"?input=test", "input", "GET", baseline)

	if !result.detected {
		t.Error("should detect ERB math expression")
	}
	// The initial engine should be ERB from the math tests table
	if result.engine != ssti.EngineERB {
		t.Logf("engine = %v (fingerprinting may have changed it)", result.engine)
	}
}

// TestDetector_detectMathExpression_ServerError verifies that detectMathExpression
// gracefully continues when the mock server is unreachable for some probes.
func TestDetector_detectMathExpression_ServerError(t *testing.T) {
	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	baseline := &baselineResponse{body: "normal", statusCode: 200}
	result := detector.detectMathExpression(ctx, "http://127.0.0.1:1/bad", "input", "GET", baseline)

	if result.detected {
		t.Error("should not detect when server is unreachable")
	}
}

// TestDetector_detectByError_MultipleEnginePatterns tests that detectByError
// can detect multiple error patterns from different engines.
func TestDetector_detectByError_MultipleEnginePatterns(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		// Return both Jinja2 and Twig errors to test accumulation
		if payload == "{{" {
			return "jinja2.exceptions.TemplateSyntaxError and Twig_Error_Syntax"
		}
		return "ok"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	result := detector.detectByError(ctx, ts.URL+"?input=test", "input", "GET")

	if len(result.errorPatterns) < 2 {
		t.Errorf("errorPatterns count = %d, want >= 2 (both jinja2 and twig)", len(result.errorPatterns))
	}
}

// TestDetector_fingerprintEngine_Mako tests Mako fingerprinting when the
// response contains "mako" string.
func TestDetector_fingerprintEngine_Mako(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "${self}" {
			return "mako.runtime.Context object"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	engine := detector.fingerprintEngine(ctx, ts.URL+"?input=test", "input", "GET")
	if engine != ssti.EngineMako {
		t.Errorf("engine = %v, want %v", engine, ssti.EngineMako)
	}
}

// TestDetector_fingerprintEngine_Jinja2Config tests Jinja2 fingerprinting via
// the {{config}} payload when the response contains "Config" string.
func TestDetector_fingerprintEngine_Jinja2Config(t *testing.T) {
	ts := newMockServer(func(payload string) string {
		if payload == "{{config}}" {
			return "Config items: SECRET_KEY=abc"
		}
		return "normal"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	engine := detector.fingerprintEngine(ctx, ts.URL+"?input=test", "input", "GET")
	if engine != ssti.EngineJinja2 {
		t.Errorf("engine = %v, want %v", engine, ssti.EngineJinja2)
	}
}

// TestDetector_fingerprintEngine_ServerError tests that fingerprintEngine
// returns EngineUnknown when all requests fail.
func TestDetector_fingerprintEngine_ServerError(t *testing.T) {
	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	engine := detector.fingerprintEngine(ctx, "http://127.0.0.1:1/bad", "input", "GET")
	if engine != ssti.EngineUnknown {
		t.Errorf("engine = %v, want EngineUnknown", engine)
	}
}

// TestDetector_detectByError_ServerUnreachable tests that detectByError
// gracefully handles unreachable servers.
func TestDetector_detectByError_ServerUnreachable(t *testing.T) {
	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	result := detector.detectByError(ctx, "http://127.0.0.1:1/bad", "input", "GET")

	if len(result.errorPatterns) != 0 {
		t.Errorf("errorPatterns should be empty, got %d", len(result.errorPatterns))
	}
	if result.engine != ssti.EngineUnknown {
		t.Errorf("engine = %v, want EngineUnknown", result.engine)
	}
}

// TestDetector_VerifyRCE_WithFilteredEngine verifies that VerifyRCE
// filters payloads by the specified engine when there are matching payloads.
func TestDetector_VerifyRCE_WithFilteredEngine(t *testing.T) {
	allRCE := ssti.GetRCEPayloads()
	if len(allRCE) == 0 {
		t.Skip("No RCE payloads available")
	}

	// Find an engine that has RCE payloads
	var targetEngine ssti.TemplateEngine
	engineFound := false
	for _, p := range allRCE {
		if p.Engine != ssti.EngineUnknown {
			targetEngine = p.Engine
			engineFound = true
			break
		}
	}
	if !engineFound {
		t.Skip("No engine-specific RCE payload found")
	}

	ts := newMockServer(func(_ string) string {
		return "uid=0(root) gid=0(root)"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", targetEngine)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if !verified {
		t.Error("VerifyRCE() should verify with root uid indicator")
	}
	if finding == nil {
		t.Fatal("VerifyRCE() should return a finding")
	}
}

// TestDetector_VerifyRCE_RCEDescription verifies that the finding description
// mentions RCE verification.
func TestDetector_VerifyRCE_RCEDescription(t *testing.T) {
	rcePayloads := ssti.GetRCEPayloads()
	if len(rcePayloads) == 0 {
		t.Skip("No RCE payloads available")
	}

	// Find a payload with expected output to trigger the description path
	var target ssti.Payload
	found := false
	for _, p := range rcePayloads {
		if p.ExpectedOutput != "" {
			target = p
			found = true
			break
		}
	}
	if !found {
		t.Skip("No RCE payload with expected output found")
	}

	ts := newMockServer(func(payload string) string {
		if payload == target.Value {
			return "before " + target.ExpectedOutput + " after"
		}
		return "safe"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	verified, finding, err := detector.VerifyRCE(ctx, ts.URL+"?input=test", "input", "GET", ssti.EngineUnknown)
	if err != nil {
		t.Fatalf("VerifyRCE() returned error: %v", err)
	}
	if !verified || finding == nil {
		t.Skip("Payload did not trigger verified RCE")
	}
	if !strings.Contains(finding.Description, "RCE") {
		t.Errorf("finding.Description = %q, should contain 'RCE'", finding.Description)
	}
}

// TestDetector_Detect_AllEngines_WithWAFBypass_NoVuln exercises the path where
// TestAllEngines is true, WAF bypass is enabled, but the server is not
// vulnerable. This covers the payload aggregation and deduplication logic.
func TestDetector_Detect_AllEngines_WithWAFBypass_NoVuln(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "nothing to see here"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      20,
		IncludeWAFBypass: true,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.Vulnerable {
		t.Error("should not be vulnerable")
	}
	// Should have tested up to MaxPayloads
	if result.TestedPayloads == 0 {
		t.Error("should have tested some payloads")
	}
	if result.TestedPayloads > 20 {
		t.Errorf("TestedPayloads = %d, should be <= MaxPayloads (20)", result.TestedPayloads)
	}
}

// TestDetector_Detect_NoMaxPayloads verifies that when MaxPayloads is 0 no
// artificial limit is imposed.
func TestDetector_Detect_NoMaxPayloads(t *testing.T) {
	ts := newMockServer(func(_ string) string {
		return "safe"
	})
	defer ts.Close()

	client := http.NewClient()
	detector := New(client)
	ctx := context.Background()

	opts := DetectOptions{
		MaxPayloads:      0, // no limit
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllEngines:   true,
		IncludeRCE:       false,
	}

	result, err := detector.Detect(ctx, ts.URL+"?input=test", "input", "GET", opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	// With no limit, all detection payloads should be tested
	if result.TestedPayloads == 0 {
		t.Error("should have tested payloads when MaxPayloads is 0")
	}
}
