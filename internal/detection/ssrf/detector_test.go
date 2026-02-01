package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/ssrf"
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

	if len(detector.responsePatterns) == 0 {
		t.Error("New() did not initialize responsePatterns")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()

	detector := New(client).WithVerbose(true)
	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}

	detector2 := New(client).WithVerbose(false)
	if detector2.verbose {
		t.Error("WithVerbose(false) should leave verbose as false")
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
	if len(opts.TargetTypes) == 0 {
		t.Error("DefaultOptions() TargetTypes should not be empty")
	}
	if len(opts.TestCloudTypes) == 0 {
		t.Error("DefaultOptions() TestCloudTypes should not be empty")
	}
}

func TestDetector_DetectCloudMetadata(t *testing.T) {
	// Create a vulnerable server that fetches URLs
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" && containsMetadataURL(urlParam) {
			// Simulate AWS metadata response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"ami-id": "ami-12345678",
				"instance-id": "i-1234567890abcdef0",
				"iam": {
					"security-credentials": {
						"role-name": "test-role"
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads: 10,
		TargetTypes: []ssrf.TargetType{ssrf.TargetCloud},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected SSRF vulnerability to be detected")
	}
}

func TestDetector_DetectInternal(t *testing.T) {
	// Create a vulnerable server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" && containsLocalhost(urlParam) {
			// Simulate Redis response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("redis_version:6.0.0\nconnected_clients:1"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads: 10,
		TargetTypes: []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected SSRF vulnerability to be detected")
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

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads: 5,
		TargetTypes: []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_CloudPatterns(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		cloudType string
		expected  bool
	}{
		{
			name:      "AWS metadata",
			body:      `ami-id: ami-12345678, instance-id: i-abc123`,
			cloudType: "aws",
			expected:  true,
		},
		{
			name:      "GCP metadata",
			body:      `computeMetadata project-id: my-project`,
			cloudType: "gcp",
			expected:  true,
		},
		{
			name:      "Normal response",
			body:      `Hello World`,
			cloudType: "aws",
			expected:  false,
		},
		{
			name:      "Azure metadata",
			body:      `subscriptionId: abc-123, resourceGroupName: my-rg`,
			cloudType: "azure",
			expected:  true,
		},
		{
			name:      "Unknown cloud type defaults to AWS",
			body:      `ami-id: ami-12345678, instance-id: i-abc123`,
			cloudType: "unknown",
			expected:  true,
		},
		{
			name:      "Unknown cloud type no match",
			body:      `Hello World`,
			cloudType: "unknown",
			expected:  false,
		},
		{
			name:      "AWS with only one indicator not enough",
			body:      `ami-id: ami-12345678`,
			cloudType: "aws",
			expected:  false,
		},
		{
			name:      "GCP service-accounts and project-id",
			body:      `service-accounts: default, project-id: test`,
			cloudType: "gcp",
			expected:  true,
		},
		{
			name:      "Azure vmId and subscriptionId",
			body:      `vmId: 123, subscriptionId: abc`,
			cloudType: "azure",
			expected:  true,
		},
		{
			name:      "AWS AccessKeyId and ec2.internal",
			body:      `AccessKeyId: AKIAIOSFODNN7EXAMPLE, ec2.internal`,
			cloudType: "aws",
			expected:  true,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.hasCloudMetadataIndicators(tt.body, tt.cloudType)
			if result != tt.expected {
				t.Errorf("hasCloudMetadataIndicators() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_containsInternalData(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "passwd and home directory",
			body:     "root:x:0:0:root:/root:/bin/bash\n/home/user",
			expected: true,
		},
		{
			name:     "internal IP ranges 192.168",
			body:     "Server at 192.168.1.100, redis_version:6.0.0",
			expected: true,
		},
		{
			name:     "internal IP ranges 10.0",
			body:     "Connected to 10.0.0.1, mysql_native_password",
			expected: true,
		},
		{
			name:     "internal IP ranges 172.16",
			body:     "Gateway 172.16.0.1, ami-id: ami-123",
			expected: true,
		},
		{
			name:     "localhost and computeMetadata",
			body:     "127.0.0.1 computeMetadata response",
			expected: true,
		},
		{
			name:     "bin bash and instance-id",
			body:     "/bin/bash shell, instance-id data",
			expected: true,
		},
		{
			name:     "only one indicator not enough",
			body:     "192.168.1.100 is the IP",
			expected: false,
		},
		{
			name:     "no indicators",
			body:     "Normal web page content without any indicators",
			expected: false,
		},
		{
			name:     "empty body",
			body:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.containsInternalData(tt.body)
			if got != tt.expected {
				t.Errorf("containsInternalData() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_hasSSRFErrorIndicators(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"connection refused", "Error: Connection refused to 10.0.0.1", true},
		{"connection timed out", "Connection timed out after 30s", true},
		{"no route to host", "No route to host 192.168.1.1", true},
		{"name not known", "Name or service not known for internal.host", true},
		{"getaddrinfo failed", "getaddrinfo failed: host not found", true},
		{"couldnt connect", "couldn't connect to host", true},
		{"failed to connect", "Failed to connect to internal server", true},
		{"could not resolve", "Could not resolve host: internal.example.com", true},
		{"no error indicators", "Normal successful response", false},
		{"empty body", "", false},
		{"partial match not enough", "connection was successful", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.hasSSRFErrorIndicators(tt.body)
			if got != tt.expected {
				t.Errorf("hasSSRFErrorIndicators() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_deduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		payloads []ssrf.Payload
		want     int
	}{
		{
			name: "with duplicates",
			payloads: []ssrf.Payload{
				{Value: "a"},
				{Value: "b"},
				{Value: "a"},
				{Value: "c"},
				{Value: "b"},
			},
			want: 3,
		},
		{
			name: "no duplicates",
			payloads: []ssrf.Payload{
				{Value: "a"},
				{Value: "b"},
				{Value: "c"},
			},
			want: 3,
		},
		{
			name:     "empty slice",
			payloads: []ssrf.Payload{},
			want:     0,
		},
		{
			name: "all same",
			payloads: []ssrf.Payload{
				{Value: "same"},
				{Value: "same"},
			},
			want: 1,
		},
		{
			name: "single payload",
			payloads: []ssrf.Payload{
				{Value: "only"},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unique := detector.deduplicatePayloads(tt.payloads)
			if len(unique) != tt.want {
				t.Errorf("deduplicatePayloads() returned %d, want %d", len(unique), tt.want)
			}
		})
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name         string
		target       string
		param        string
		payload      ssrf.Payload
		resp         *internalhttp.Response
		wantSeverity core.Severity
		wantTool     string
	}{
		{
			name:   "cloud target critical severity",
			target: "http://example.com/fetch",
			param:  "url",
			payload: ssrf.Payload{
				Value:       "http://169.254.169.254/latest/meta-data/",
				Target:      ssrf.TargetCloud,
				Protocol:    ssrf.ProtocolHTTP,
				Description: "AWS metadata",
				CloudType:   "aws",
			},
			resp:         &internalhttp.Response{StatusCode: 200, Body: "ami-id: ami-123"},
			wantSeverity: core.SeverityCritical,
			wantTool:     "ssrf-detector",
		},
		{
			name:   "internal target high severity",
			target: "http://example.com/proxy",
			param:  "target",
			payload: ssrf.Payload{
				Value:       "http://127.0.0.1:6379",
				Target:      ssrf.TargetInternal,
				Protocol:    ssrf.ProtocolHTTP,
				Description: "Localhost Redis",
			},
			resp:         &internalhttp.Response{StatusCode: 200, Body: "redis_version:6.0"},
			wantSeverity: core.SeverityHigh,
			wantTool:     "ssrf-detector",
		},
		{
			name:   "local file target high severity",
			target: "http://example.com/read",
			param:  "file",
			payload: ssrf.Payload{
				Value:       "file:///etc/passwd",
				Target:      ssrf.TargetLocalFile,
				Protocol:    ssrf.ProtocolFile,
				Description: "Linux passwd",
			},
			resp:         &internalhttp.Response{StatusCode: 200, Body: "root:x:0:0:"},
			wantSeverity: core.SeverityHigh,
			wantTool:     "ssrf-detector",
		},
		{
			name:   "cloud target with nil response",
			target: "http://example.com/fetch",
			param:  "url",
			payload: ssrf.Payload{
				Value:       "http://169.254.169.254/",
				Target:      ssrf.TargetCloud,
				Protocol:    ssrf.ProtocolHTTP,
				Description: "Metadata",
				CloudType:   "gcp",
			},
			resp:         nil,
			wantSeverity: core.SeverityCritical,
			wantTool:     "ssrf-detector",
		},
		{
			name:   "with long response body truncation",
			target: "http://example.com/fetch",
			param:  "url",
			payload: ssrf.Payload{
				Value:       "http://127.0.0.1",
				Target:      ssrf.TargetInternal,
				Protocol:    ssrf.ProtocolHTTP,
				Description: "localhost",
			},
			resp:         &internalhttp.Response{StatusCode: 200, Body: strings.Repeat("B", 600)},
			wantSeverity: core.SeverityHigh,
			wantTool:     "ssrf-detector",
		},
		{
			name:   "with empty response body",
			target: "http://example.com/fetch",
			param:  "url",
			payload: ssrf.Payload{
				Value:       "http://127.0.0.1",
				Target:      ssrf.TargetInternal,
				Protocol:    ssrf.ProtocolHTTP,
				Description: "localhost",
			},
			resp:         &internalhttp.Response{StatusCode: 200, Body: ""},
			wantSeverity: core.SeverityHigh,
			wantTool:     "ssrf-detector",
		},
		{
			name:   "cloud target without cloud type in description",
			target: "http://example.com/fetch",
			param:  "url",
			payload: ssrf.Payload{
				Value:       "http://127.0.0.1",
				Target:      ssrf.TargetInternal,
				Protocol:    ssrf.ProtocolHTTP,
				Description: "Internal service",
				CloudType:   "",
			},
			resp:         &internalhttp.Response{StatusCode: 200, Body: "test"},
			wantSeverity: core.SeverityHigh,
			wantTool:     "ssrf-detector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := detector.createFinding(tt.target, tt.param, tt.payload, tt.resp)

			if finding == nil {
				t.Fatal("createFinding() returned nil")
			}
			if finding.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", finding.Severity, tt.wantSeverity)
			}
			if finding.Tool != tt.wantTool {
				t.Errorf("Tool = %q, want %q", finding.Tool, tt.wantTool)
			}
			if finding.URL != tt.target {
				t.Errorf("URL = %q, want %q", finding.URL, tt.target)
			}
			if finding.Parameter != tt.param {
				t.Errorf("Parameter = %q, want %q", finding.Parameter, tt.param)
			}
			if finding.Evidence == "" {
				t.Error("Expected non-empty Evidence")
			}
			if finding.Remediation == "" {
				t.Error("Expected non-empty Remediation")
			}
			if finding.Description == "" {
				t.Error("Expected non-empty Description")
			}
			if len(finding.WSTG) == 0 {
				t.Error("Expected WSTG mappings")
			}
			if len(finding.Top10) == 0 {
				t.Error("Expected Top10 mappings")
			}
			if len(finding.CWE) == 0 {
				t.Error("Expected CWE mappings")
			}

			// Verify cloud type is mentioned in description when present
			if tt.payload.CloudType != "" {
				if !strings.Contains(finding.Description, tt.payload.CloudType) {
					t.Errorf("Description should mention cloud type %q", tt.payload.CloudType)
				}
			}

			// Check truncation for long body
			if tt.resp != nil && len(tt.resp.Body) > 500 {
				if !strings.Contains(finding.Evidence, "...") {
					t.Error("Expected truncation indicator for long body")
				}
			}
		})
	}
}

func TestDetector_isSSRFSuccess(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		resp     *internalhttp.Response
		baseline *internalhttp.Response
		payload  ssrf.Payload
		expected bool
	}{
		{
			name:     "nil response",
			resp:     nil,
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: false,
		},
		{
			name:     "internal pattern match redis",
			resp:     &internalhttp.Response{StatusCode: 200, Body: "redis_version:6.0.0\nconnected_clients:1"},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: true,
		},
		{
			name:     "internal pattern match in baseline too",
			resp:     &internalhttp.Response{StatusCode: 200, Body: "redis_version:6.0.0"},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "redis_version:6.0.0"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: false,
		},
		{
			name:     "cloud pattern match AWS",
			resp:     &internalhttp.Response{StatusCode: 200, Body: `ami-12345678 instance-id i-abc123`},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetCloud, CloudType: "aws"},
			expected: true,
		},
		{
			name: "response much larger with internal data",
			resp: &internalhttp.Response{
				StatusCode: 200,
				Body:       "root:x:0:0:root:/root:/bin/bash\n" + strings.Repeat("data ", 200),
			},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: true,
		},
		{
			name: "response much larger but no internal data",
			resp: &internalhttp.Response{
				StatusCode: 200,
				Body:       strings.Repeat("normal content ", 100),
			},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: false,
		},
		{
			name: "different status code with internal data",
			resp: &internalhttp.Response{
				StatusCode: 200,
				Body:       "root:x:0:0: /home/user /bin/bash",
			},
			baseline: &internalhttp.Response{StatusCode: 403, Body: "Forbidden"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: true,
		},
		{
			name: "different status code but no internal data",
			resp: &internalhttp.Response{
				StatusCode: 200,
				Body:       "Normal page content",
			},
			baseline: &internalhttp.Response{StatusCode: 403, Body: "Forbidden"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: false,
		},
		{
			name:     "error indicators in response not in baseline",
			resp:     &internalhttp.Response{StatusCode: 500, Body: "Connection refused to 10.0.0.1"},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: true,
		},
		{
			name:     "error indicators in both response and baseline",
			resp:     &internalhttp.Response{StatusCode: 500, Body: "Connection refused"},
			baseline: &internalhttp.Response{StatusCode: 500, Body: "Connection refused"},
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: false,
		},
		{
			name:     "cloud target no pattern match falls through to cloud metadata check",
			resp:     &internalhttp.Response{StatusCode: 200, Body: "ami-id data, instance-id data, AccessKeyId data"},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetCloud, CloudType: "aws"},
			expected: true,
		},
		{
			name:     "nil baseline with matching pattern",
			resp:     &internalhttp.Response{StatusCode: 200, Body: "redis_version:6.0.0"},
			baseline: nil,
			payload:  ssrf.Payload{Target: ssrf.TargetInternal},
			expected: true,
		},
		{
			name:     "local file pattern match",
			resp:     &internalhttp.Response{StatusCode: 200, Body: "root:x:0:0:root:/root:/bin/bash"},
			baseline: &internalhttp.Response{StatusCode: 200, Body: "OK"},
			payload:  ssrf.Payload{Target: ssrf.TargetLocalFile},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isSSRFSuccess(tt.resp, tt.baseline, tt.payload)
			if got != tt.expected {
				t.Errorf("isSSRFSuccess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := detector.Detect(ctx, server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads: 100,
		TargetTypes: []ssrf.TargetType{ssrf.TargetInternal},
	})

	// Either the baseline request fails or context cancellation is returned
	if err == nil {
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
	}
}

func TestDetector_Detect_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), serverURL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads: 5,
		TargetTypes: []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err == nil {
		t.Error("Expected error when server is down")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "failed to get baseline") {
		t.Errorf("Expected baseline error, got: %v", err)
	}
}

func TestDetector_Detect_PayloadLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:      3,
		IncludeWAFBypass: false,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads > 3 {
		t.Errorf("Expected at most 3 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_WithWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: true,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_HTTPErrorDuringPayload(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// Baseline request succeeds
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("baseline"))
			return
		}
		// Subsequent requests cause connection reset
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads: 3,
		TargetTypes: []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_MaxPayloadsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:      0,
		IncludeWAFBypass: false,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_InvalidURL(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), "://invalid-url", "url", "GET", DetectOptions{
		MaxPayloads: 5,
		TargetTypes: []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}
}

func TestDetector_Detect_MultipleTargetTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: false,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetCloud, ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_ErrorIndicatorsFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" && containsLocalhost(urlParam) {
			// Simulate connection refused error
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Error: Connection refused to internal server"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected SSRF vulnerability detected via error indicators")
	}
}

func TestDetector_Detect_LimitFindings(t *testing.T) {
	// Server that returns vulnerable responses for all internal URLs
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" && urlParam != "https://example.com" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("redis_version:7.0.0\nredis_git_sha1:abc123\nconnected_clients:5"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: false,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability")
	}

	// SSRF detector limits to 3 findings
	if len(result.Findings) > 3 {
		t.Errorf("Expected at most 3 findings, got %d", len(result.Findings))
	}
}

func TestDetector_Detect_ContextCancellationDuringPayloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	result, err := detector.Detect(ctx, server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads: 1000,
		TargetTypes: []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil && err != context.Canceled {
		if !strings.Contains(err.Error(), "context canceled") {
			t.Logf("Got expected error variant: %v", err)
		}
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_DifferentStatusCodeWithInternalData(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		urlParam := r.URL.Query().Get("url")
		if requestCount == 1 {
			// Baseline returns 403
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		if urlParam != "" && containsLocalhost(urlParam) {
			// SSRF returns 200 with internal data
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n/home/user/.ssh")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?url=http://example.com", "url", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetInternal},
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected SSRF vulnerability to be detected via status code difference")
	}
}

func TestDetector_initResponsePatterns(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	// Verify all expected pattern categories exist
	if _, ok := detector.responsePatterns[ssrf.TargetCloud]; !ok {
		t.Error("Expected Cloud patterns to be initialized")
	}
	if _, ok := detector.responsePatterns[ssrf.TargetInternal]; !ok {
		t.Error("Expected Internal patterns to be initialized")
	}
	if _, ok := detector.responsePatterns[ssrf.TargetLocalFile]; !ok {
		t.Error("Expected LocalFile patterns to be initialized")
	}

	// Verify cloud patterns match expected strings
	cloudPatterns := detector.responsePatterns[ssrf.TargetCloud]
	if len(cloudPatterns) == 0 {
		t.Error("Expected non-empty Cloud patterns")
	}

	// Verify internal patterns match expected strings
	internalPatterns := detector.responsePatterns[ssrf.TargetInternal]
	if len(internalPatterns) == 0 {
		t.Error("Expected non-empty Internal patterns")
	}

	// Verify file patterns match expected strings
	filePatterns := detector.responsePatterns[ssrf.TargetLocalFile]
	if len(filePatterns) == 0 {
		t.Error("Expected non-empty LocalFile patterns")
	}
}

func containsMetadataURL(url string) bool {
	return strings.Contains(url, "169.254.169.254") || strings.Contains(url, "metadata")
}

func containsLocalhost(url string) bool {
	return strings.Contains(url, "127.0.0.1") || strings.Contains(url, "localhost")
}
