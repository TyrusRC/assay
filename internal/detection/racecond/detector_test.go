package racecond

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector.Name() != "racecond" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "racecond")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.ConcurrentRequests <= 0 {
		t.Error("DefaultOptions() ConcurrentRequests should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
	if opts.BodyLengthVariance <= 0 {
		t.Error("DefaultOptions() BodyLengthVariance should be positive")
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

func TestDetector_Detect_InconsistentStatusCodes(t *testing.T) {
	// Server that returns different status codes for concurrent requests
	var counter int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		if n%2 == 0 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		} else {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("Conflict"))
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?action=transfer", "action", "POST", DetectOptions{
		ConcurrentRequests: 10,
		BodyLengthVariance: 0.1,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected with inconsistent status codes")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	if result.Vulnerable {
		finding := result.Findings[0]
		if finding.Tool != "racecond-detector" {
			t.Errorf("Tool = %q, want %q", finding.Tool, "racecond-detector")
		}
		if len(finding.WSTG) == 0 {
			t.Error("Expected WSTG mappings")
		}
		if len(finding.CWE) == 0 {
			t.Error("Expected CWE mappings")
		}
		if finding.Remediation == "" {
			t.Error("Expected non-empty Remediation")
		}
	}
}

func TestDetector_Detect_ConsistentResponses(t *testing.T) {
	// Server that returns consistent responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Consistent response body"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?action=test", "action", "POST", DetectOptions{
		ConcurrentRequests: 5,
		BodyLengthVariance: 0.1,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability with consistent responses")
	}
}

func TestDetector_Detect_InconsistentBodyLengths(t *testing.T) {
	// Server that returns different body lengths
	var counter int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		w.WriteHeader(http.StatusOK)
		if n%3 == 0 {
			// Much longer response (significant variance)
			w.Write([]byte("This is a much longer response body that indicates something different happened during processing of this particular request"))
		} else {
			w.Write([]byte("Short"))
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?amount=100", "amount", "POST", DetectOptions{
		ConcurrentRequests: 9,
		BodyLengthVariance: 0.1,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected with inconsistent body lengths")
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

	result, err := detector.Detect(context.Background(), serverURL+"?action=test", "action", "POST", DetectOptions{
		ConcurrentRequests: 5,
		BodyLengthVariance: 0.1,
	})

	if err == nil {
		t.Error("Expected error when server is down")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
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

	result, err := detector.Detect(ctx, server.URL+"?action=test", "action", "POST", DetectOptions{
		ConcurrentRequests: 5,
		BodyLengthVariance: 0.1,
	})

	// All requests may fail due to cancelled context
	if err == nil {
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
	}
}

func TestDetector_analyzeResponses(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name      string
		responses []concurrentResponse
		variance  float64
		expected  bool
	}{
		{
			name: "different status codes",
			responses: []concurrentResponse{
				{StatusCode: 200, ContentLength: 10},
				{StatusCode: 200, ContentLength: 10},
				{StatusCode: 409, ContentLength: 10},
			},
			variance: 0.1,
			expected: true,
		},
		{
			name: "consistent responses",
			responses: []concurrentResponse{
				{StatusCode: 200, ContentLength: 100},
				{StatusCode: 200, ContentLength: 100},
				{StatusCode: 200, ContentLength: 100},
			},
			variance: 0.1,
			expected: false,
		},
		{
			name: "significant body length variance",
			responses: []concurrentResponse{
				{StatusCode: 200, ContentLength: 100},
				{StatusCode: 200, ContentLength: 100},
				{StatusCode: 200, ContentLength: 500},
			},
			variance: 0.1,
			expected: true,
		},
		{
			name:      "single response",
			responses: []concurrentResponse{{StatusCode: 200, ContentLength: 100}},
			variance:  0.1,
			expected:  false,
		},
		{
			name:      "empty responses",
			responses: []concurrentResponse{},
			variance:  0.1,
			expected:  false,
		},
		{
			name: "zero body lengths",
			responses: []concurrentResponse{
				{StatusCode: 200, ContentLength: 0},
				{StatusCode: 200, ContentLength: 0},
			},
			variance: 0.1,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.analyzeResponses(tt.responses, tt.variance)
			if got != tt.expected {
				t.Errorf("analyzeResponses() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	responses := []concurrentResponse{
		{StatusCode: 200, ContentLength: 100},
		{StatusCode: 200, ContentLength: 100},
		{StatusCode: 409, ContentLength: 50},
	}

	finding := detector.createFinding("http://example.com/transfer", "amount", "POST", responses)

	if finding == nil {
		t.Fatal("createFinding() returned nil")
	}
	if finding.Tool != "racecond-detector" {
		t.Errorf("Tool = %q, want %q", finding.Tool, "racecond-detector")
	}
	if finding.URL != "http://example.com/transfer" {
		t.Errorf("URL = %q, want %q", finding.URL, "http://example.com/transfer")
	}
	if finding.Parameter != "amount" {
		t.Errorf("Parameter = %q, want %q", finding.Parameter, "amount")
	}
	if finding.Description == "" {
		t.Error("Expected non-empty Description")
	}
	if finding.Evidence == "" {
		t.Error("Expected non-empty Evidence")
	}
	if finding.Remediation == "" {
		t.Error("Expected non-empty Remediation")
	}
	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-BUSL-07" {
		t.Error("Expected WSTG-BUSL-07 mapping")
	}
	if len(finding.Top10) == 0 || finding.Top10[0] != "A04:2021" {
		t.Error("Expected A04:2021 mapping")
	}
	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-362" {
		t.Error("Expected CWE-362 mapping")
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("averageInt", func(t *testing.T) {
		tests := []struct {
			input    []int
			expected int
		}{
			{[]int{10, 20, 30}, 20},
			{[]int{5}, 5},
			{[]int{}, 0},
			{[]int{0, 0, 0}, 0},
		}
		for _, tt := range tests {
			got := averageInt(tt.input)
			if got != tt.expected {
				t.Errorf("averageInt(%v) = %d, want %d", tt.input, got, tt.expected)
			}
		}
	})

	t.Run("minInt", func(t *testing.T) {
		tests := []struct {
			input    []int
			expected int
		}{
			{[]int{10, 5, 20}, 5},
			{[]int{5}, 5},
			{[]int{}, 0},
		}
		for _, tt := range tests {
			got := minInt(tt.input)
			if got != tt.expected {
				t.Errorf("minInt(%v) = %d, want %d", tt.input, got, tt.expected)
			}
		}
	})

	t.Run("maxInt", func(t *testing.T) {
		tests := []struct {
			input    []int
			expected int
		}{
			{[]int{10, 5, 20}, 20},
			{[]int{5}, 5},
			{[]int{}, 0},
		}
		for _, tt := range tests {
			got := maxInt(tt.input)
			if got != tt.expected {
				t.Errorf("maxInt(%v) = %d, want %d", tt.input, got, tt.expected)
			}
		}
	})
}

func TestDetector_Detect_DefaultConcurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	// Use 0 for ConcurrentRequests to trigger default
	result, err := detector.Detect(context.Background(), server.URL+"?a=1", "a", "POST", DetectOptions{
		ConcurrentRequests: 0,
		BodyLengthVariance: 0.1,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads != DefaultOptions().ConcurrentRequests {
		t.Errorf("Expected %d tested payloads with default concurrency, got %d",
			DefaultOptions().ConcurrentRequests, result.TestedPayloads)
	}
}

func TestDetector_Detect_MultipleSuccessDetection(t *testing.T) {
	// Simulate a coupon redemption: all requests succeed when only one should
	var counter int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		w.WriteHeader(http.StatusOK)
		// Each response has slightly different content length based on counter
		fmt.Fprintf(w, "Coupon redeemed successfully! Order #%d", n)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?coupon=SAVE50", "coupon", "POST", DetectOptions{
		ConcurrentRequests: 5,
		BodyLengthVariance: 0.01, // Very tight variance to detect small differences
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// The result depends on the variance of order numbers in the response
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}
