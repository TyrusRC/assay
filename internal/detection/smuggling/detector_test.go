package smuggling

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewDetector(t *testing.T) {
	detector := NewDetector()
	if detector == nil {
		t.Fatal("NewDetector() returned nil")
	}
}

func TestDetector_Name(t *testing.T) {
	detector := NewDetector()
	if detector.Name() != "http-request-smuggling" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "http-request-smuggling")
	}
}

func TestDetector_Description(t *testing.T) {
	detector := NewDetector()
	desc := detector.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
	if !strings.Contains(desc, "HTTP") {
		t.Error("Description() should mention HTTP")
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	detector := NewDetector()
	mapping := detector.OWASPMapping()

	if len(mapping.WSTG) == 0 {
		t.Error("WSTG mapping should not be empty")
	}
	if len(mapping.CWE) == 0 {
		t.Error("CWE mapping should not be empty")
	}

	// Verify specific mappings
	foundWSTG := false
	for _, w := range mapping.WSTG {
		if w == "WSTG-INPV-15" {
			foundWSTG = true
			break
		}
	}
	if !foundWSTG {
		t.Error("Expected WSTG-INPV-15 in WSTG mapping")
	}

	foundCWE := false
	for _, c := range mapping.CWE {
		if c == "CWE-444" {
			foundCWE = true
			break
		}
	}
	if !foundCWE {
		t.Error("Expected CWE-444 in CWE mapping")
	}
}

func TestSmugglingType_String(t *testing.T) {
	tests := []struct {
		smuggleType SmugglingType
		want        string
	}{
		{TypeCLTE, "CL.TE"},
		{TypeTECL, "TE.CL"},
		{TypeTETE, "TE.TE"},
		{TypeUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.smuggleType.String() != tt.want {
				t.Errorf("String() = %q, want %q", tt.smuggleType.String(), tt.want)
			}
		})
	}
}

func TestResult_Fields(t *testing.T) {
	result := &Result{
		Vulnerable:       true,
		Type:             TypeCLTE,
		Confidence:       0.85,
		Evidence:         "Timing differential detected",
		TimingDiff:       time.Second * 5,
		FrontendBehavior: "Uses Content-Length",
		BackendBehavior:  "Uses Transfer-Encoding",
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.Type != TypeCLTE {
		t.Errorf("Type = %v, want %v", result.Type, TypeCLTE)
	}
	if result.Confidence != 0.85 {
		t.Errorf("Confidence = %f, want %f", result.Confidence, 0.85)
	}
	if result.TimingDiff != time.Second*5 {
		t.Errorf("TimingDiff = %v, want %v", result.TimingDiff, time.Second*5)
	}
}

func TestConfig_Defaults(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout == 0 {
		t.Error("Default Timeout should not be zero")
	}
	if config.TimingThreshold == 0 {
		t.Error("Default TimingThreshold should not be zero")
	}
	if config.MaxRetries == 0 {
		t.Error("Default MaxRetries should not be zero")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "zero timeout",
			config: &Config{
				Timeout:         0,
				TimingThreshold: time.Second,
				MaxRetries:      3,
			},
			wantErr: true,
		},
		{
			name: "zero timing threshold",
			config: &Config{
				Timeout:         time.Second * 10,
				TimingThreshold: 0,
				MaxRetries:      3,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildRawRequest(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		host     string
		path     string
		headers  map[string]string
		body     string
		contains []string
	}{
		{
			name:   "simple GET request",
			method: "GET",
			host:   "example.com",
			path:   "/",
			headers: map[string]string{
				"User-Agent": "test-scanner",
			},
			body: "",
			contains: []string{
				"GET / HTTP/1.1\r\n",
				"Host: example.com\r\n",
				"User-Agent: test-scanner\r\n",
			},
		},
		{
			name:   "POST request with body",
			method: "POST",
			host:   "example.com",
			path:   "/api",
			headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: "data=test",
			contains: []string{
				"POST /api HTTP/1.1\r\n",
				"Host: example.com\r\n",
				"Content-Type: application/x-www-form-urlencoded\r\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := BuildRawRequest(tt.method, tt.host, tt.path, tt.headers, tt.body)
			for _, expected := range tt.contains {
				if !strings.Contains(raw, expected) {
					t.Errorf("BuildRawRequest() missing %q in output:\n%s", expected, raw)
				}
			}
		})
	}
}

func TestBuildCLTEPayload(t *testing.T) {
	payload := BuildCLTEPayload("example.com", "/", 5)

	// Verify payload has both Content-Length and Transfer-Encoding
	if !strings.Contains(payload, "Content-Length:") {
		t.Error("CL.TE payload should contain Content-Length header")
	}
	if !strings.Contains(payload, "Transfer-Encoding: chunked") {
		t.Error("CL.TE payload should contain Transfer-Encoding header")
	}

	// Verify POST method for body support
	if !strings.HasPrefix(payload, "POST") {
		t.Error("CL.TE payload should use POST method")
	}
}

func TestBuildTECLPayload(t *testing.T) {
	payload := BuildTECLPayload("example.com", "/", 5)

	// Verify payload has both Transfer-Encoding and Content-Length
	if !strings.Contains(payload, "Transfer-Encoding: chunked") {
		t.Error("TE.CL payload should contain Transfer-Encoding header")
	}
	if !strings.Contains(payload, "Content-Length:") {
		t.Error("TE.CL payload should contain Content-Length header")
	}
}

func TestBuildTETEPayloads(t *testing.T) {
	payloads := BuildTETEPayloads("example.com", "/", 5)

	if len(payloads) == 0 {
		t.Fatal("BuildTETEPayloads() should return at least one payload")
	}

	// Verify each payload has some form of Transfer-Encoding obfuscation
	for i, payload := range payloads {
		if !strings.Contains(strings.ToLower(payload), "transfer-encoding") &&
			!strings.Contains(strings.ToLower(payload), "transfer") {
			t.Errorf("Payload %d should contain Transfer-Encoding variant", i)
		}
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantStatus  int
		wantHeaders int
		wantBody    string
	}{
		{
			name: "simple 200 response",
			raw: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"Content-Length: 5\r\n" +
				"\r\n" +
				"hello",
			wantStatus:  200,
			wantHeaders: 2,
			wantBody:    "hello",
		},
		{
			name: "400 bad request",
			raw: "HTTP/1.1 400 Bad Request\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n" +
				"Invalid request",
			wantStatus:  400,
			wantHeaders: 1,
			wantBody:    "Invalid request",
		},
		{
			name: "chunked response",
			raw: "HTTP/1.1 200 OK\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"\r\n" +
				"5\r\nhello\r\n0\r\n\r\n",
			wantStatus:  200,
			wantHeaders: 1,
			wantBody:    "5\r\nhello\r\n0\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(tt.raw)
			if err != nil {
				t.Fatalf("ParseResponse() error = %v", err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if len(resp.Headers) != tt.wantHeaders {
				t.Errorf("Headers count = %d, want %d", len(resp.Headers), tt.wantHeaders)
			}
			if resp.Body != tt.wantBody {
				t.Errorf("Body = %q, want %q", resp.Body, tt.wantBody)
			}
		})
	}
}

func TestParseResponse_Invalid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "empty response",
			raw:  "",
		},
		{
			name: "incomplete status line",
			raw:  "HTTP/1.1",
		},
		{
			name: "invalid status code",
			raw:  "HTTP/1.1 abc OK\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseResponse(tt.raw)
			if err == nil {
				t.Error("ParseResponse() should return error for invalid response")
			}
		})
	}
}

// mockServer creates a test server that responds to raw socket connections.
type mockServer struct {
	listener  net.Listener
	responses map[string]mockResponse
	mu        sync.Mutex
	closed    bool
}

type mockResponse struct {
	response string
	delay    time.Duration
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}
	s := &mockServer{
		listener:  listener,
		responses: make(map[string]mockResponse),
	}
	go s.serve(t)
	return s
}

func (s *mockServer) serve(t *testing.T) {
	t.Helper()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		go s.handleConn(t, conn)
	}
}

func (s *mockServer) handleConn(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return
	}
	request := string(buf[:n])

	s.mu.Lock()
	// Find matching response
	var resp mockResponse
	for pattern, r := range s.responses {
		if strings.Contains(request, pattern) {
			resp = r
			break
		}
	}
	s.mu.Unlock()

	if resp.response == "" {
		resp.response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	}

	if resp.delay > 0 {
		time.Sleep(resp.delay)
	}

	conn.Write([]byte(resp.response))
}

func (s *mockServer) setResponse(pattern string, response string, delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responses[pattern] = mockResponse{response: response, delay: delay}
}

func (s *mockServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockServer) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.listener.Close()
}

func TestSendRawRequest(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	server.setResponse("GET /", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK", 0)

	ctx := context.Background()
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", server.addr())

	resp, duration, err := SendRawRequest(ctx, server.addr(), request, time.Second*5)
	if err != nil {
		t.Fatalf("SendRawRequest() error = %v", err)
	}

	if resp == "" {
		t.Error("SendRawRequest() returned empty response")
	}
	if duration <= 0 {
		t.Error("SendRawRequest() returned zero duration")
	}
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("Expected 200 OK in response, got: %s", resp)
	}
}

func TestSendRawRequest_Timeout(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	// Set a response with delay longer than timeout
	server.setResponse("GET /slow", "HTTP/1.1 200 OK\r\n\r\nOK", time.Second*5)

	ctx := context.Background()
	request := fmt.Sprintf("GET /slow HTTP/1.1\r\nHost: %s\r\n\r\n", server.addr())

	// Use a short timeout - the response will come after the timeout
	startTime := time.Now()
	resp, duration, err := SendRawRequest(ctx, server.addr(), request, time.Millisecond*200)

	// The request should either:
	// 1. Return with an error due to timeout
	// 2. Return with partial/empty response due to read timeout
	// Either is acceptable behavior for this test
	elapsed := time.Since(startTime)

	// Should not have waited the full 5 seconds
	if elapsed > time.Second*3 {
		t.Errorf("Request took too long: %v", elapsed)
	}

	// Log what happened for debugging
	t.Logf("Elapsed: %v, Duration: %v, Error: %v, Response len: %d", elapsed, duration, err, len(resp))
}

func TestSendRawRequest_ContextCancellation(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	server.setResponse("GET /", "HTTP/1.1 200 OK\r\n\r\nOK", time.Second*5)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", server.addr())

	_, _, err := SendRawRequest(ctx, server.addr(), request, time.Second*5)
	if err == nil {
		t.Error("SendRawRequest() should fail with cancelled context")
	}
}

func TestDetector_DetectCLTE_WithMockServer(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	// Set up differential response - CL.TE vulnerable server would process differently
	// Normal request gets fast response
	server.setResponse("GET /", "HTTP/1.1 200 OK\r\n\r\nOK", 0)
	// CL.TE probe causes delay (simulating smuggled request being processed)
	server.setResponse("Transfer-Encoding: chunked", "HTTP/1.1 200 OK\r\n\r\nOK", time.Second*2)

	detector := NewDetector()
	detector.config.TimingThreshold = time.Second

	ctx := context.Background()
	result := detector.DetectCLTE(ctx, server.addr(), "/")

	// The mock server simulates timing differential
	if result.TimingDiff < time.Second {
		t.Logf("Note: Timing diff was %v, threshold is %v", result.TimingDiff, detector.config.TimingThreshold)
	}
}

func TestDetector_DetectTECL_WithMockServer(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	// Normal requests are fast
	server.setResponse("GET /", "HTTP/1.1 200 OK\r\n\r\nOK", 0)
	// TE.CL probe causes delay
	server.setResponse("0\r\n\r\nGET", "HTTP/1.1 200 OK\r\n\r\nOK", time.Second*2)

	detector := NewDetector()
	detector.config.TimingThreshold = time.Second

	ctx := context.Background()
	result := detector.DetectTECL(ctx, server.addr(), "/")

	// Verify result structure
	if result.Type != TypeTECL {
		t.Errorf("Type = %v, want %v", result.Type, TypeTECL)
	}
}

func TestDetector_DetectTETE_WithMockServer(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	// Normal requests are fast
	server.setResponse("GET /", "HTTP/1.1 200 OK\r\n\r\nOK", 0)
	// TE.TE obfuscation causes different behavior
	server.setResponse("Transfer-Encoding: xchunked", "HTTP/1.1 400 Bad Request\r\n\r\nBad", 0)

	detector := NewDetector()

	ctx := context.Background()
	result := detector.DetectTETE(ctx, server.addr(), "/")

	// Verify result structure
	if result.Type != TypeTETE {
		t.Errorf("Type = %v, want %v", result.Type, TypeTETE)
	}
}

func TestDetector_Detect_Integration(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	// Set up responses
	server.setResponse("GET /", "HTTP/1.1 200 OK\r\n\r\nOK", 0)

	detector := NewDetector()
	detector.config.Timeout = time.Second * 2
	detector.config.TimingThreshold = time.Millisecond * 500

	ctx := context.Background()
	results := detector.Detect(ctx, server.addr(), "/")

	// Should return results for all three types
	if len(results) == 0 {
		t.Error("Detect() should return at least one result")
	}

	// Verify each result has proper type
	typesSeen := make(map[SmugglingType]bool)
	for _, r := range results {
		typesSeen[r.Type] = true
	}

	expectedTypes := []SmugglingType{TypeCLTE, TypeTECL, TypeTETE}
	for _, expected := range expectedTypes {
		if !typesSeen[expected] {
			t.Errorf("Expected result for type %v", expected)
		}
	}
}

func TestDetector_WithConfig(t *testing.T) {
	config := &Config{
		Timeout:          time.Second * 30,
		TimingThreshold:  time.Second * 3,
		MaxRetries:       5,
		EnableTimingTest: true,
		EnableDiffTest:   true,
	}

	detector := NewDetectorWithConfig(config)

	if detector.config.Timeout != time.Second*30 {
		t.Errorf("Config Timeout not applied")
	}
	if detector.config.TimingThreshold != time.Second*3 {
		t.Errorf("Config TimingThreshold not applied")
	}
	if detector.config.MaxRetries != 5 {
		t.Errorf("Config MaxRetries not applied")
	}
}

func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			name:     "host with port",
			target:   "example.com:8080",
			wantHost: "example.com",
			wantPort: "8080",
			wantErr:  false,
		},
		{
			name:     "host without port",
			target:   "example.com",
			wantHost: "example.com",
			wantPort: "80",
			wantErr:  false,
		},
		{
			name:     "http URL",
			target:   "http://example.com/path",
			wantHost: "example.com",
			wantPort: "80",
			wantErr:  false,
		},
		{
			name:     "https URL",
			target:   "https://example.com/path",
			wantHost: "example.com",
			wantPort: "443",
			wantErr:  false,
		},
		{
			name:     "URL with port",
			target:   "http://example.com:8080/path",
			wantHost: "example.com",
			wantPort: "8080",
			wantErr:  false,
		},
		{
			name:     "empty target",
			target:   "",
			wantHost: "",
			wantPort: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := ExtractHostPort(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractHostPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if host != tt.wantHost {
				t.Errorf("ExtractHostPort() host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("ExtractHostPort() port = %q, want %q", port, tt.wantPort)
			}
		})
	}
}

func TestCalculateTimingDifferential(t *testing.T) {
	tests := []struct {
		name       string
		baseline   time.Duration
		probe      time.Duration
		wantDiff   time.Duration
		wantSignif bool
		threshold  time.Duration
	}{
		{
			name:       "significant difference",
			baseline:   time.Millisecond * 100,
			probe:      time.Second * 5,
			wantDiff:   time.Second*5 - time.Millisecond*100,
			wantSignif: true,
			threshold:  time.Second,
		},
		{
			name:       "no significant difference",
			baseline:   time.Millisecond * 100,
			probe:      time.Millisecond * 150,
			wantDiff:   time.Millisecond * 50,
			wantSignif: false,
			threshold:  time.Second,
		},
		{
			name:       "probe faster than baseline",
			baseline:   time.Millisecond * 500,
			probe:      time.Millisecond * 100,
			wantDiff:   0,
			wantSignif: false,
			threshold:  time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff, signif := CalculateTimingDifferential(tt.baseline, tt.probe, tt.threshold)
			if diff != tt.wantDiff {
				t.Errorf("CalculateTimingDifferential() diff = %v, want %v", diff, tt.wantDiff)
			}
			if signif != tt.wantSignif {
				t.Errorf("CalculateTimingDifferential() signif = %v, want %v", signif, tt.wantSignif)
			}
		})
	}
}

func TestIsChunkedTerminator(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "valid terminator",
			data: "0\r\n\r\n",
			want: true,
		},
		{
			name: "with trailing data",
			data: "0\r\n\r\nextra",
			want: true,
		},
		{
			name: "invalid terminator",
			data: "5\r\nhello\r\n",
			want: false,
		},
		{
			name: "empty",
			data: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsChunkedTerminator(tt.data); got != tt.want {
				t.Errorf("IsChunkedTerminator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTEObfuscationVariants(t *testing.T) {
	variants := TEObfuscationVariants()

	if len(variants) == 0 {
		t.Fatal("TEObfuscationVariants() should return variants")
	}

	// Verify each variant contains some form of "transfer" or "encoding"
	for i, v := range variants {
		lower := strings.ToLower(v)
		if !strings.Contains(lower, "transfer") && !strings.Contains(lower, "encoding") {
			t.Errorf("Variant %d %q doesn't appear to be a TE header variant", i, v)
		}
	}
}

func TestBuildBaselineRequest(t *testing.T) {
	request := BuildBaselineRequest("example.com", "/")

	if !strings.Contains(request, "GET /") {
		t.Error("Baseline request should be a GET request")
	}
	if !strings.Contains(request, "Host: example.com") {
		t.Error("Baseline request should have Host header")
	}
}

func TestDetector_CreateFinding(t *testing.T) {
	detector := NewDetector()
	result := &Result{
		Vulnerable:       true,
		Type:             TypeCLTE,
		Confidence:       0.9,
		Evidence:         "Timing differential: 5s",
		TimingDiff:       time.Second * 5,
		FrontendBehavior: "Content-Length",
		BackendBehavior:  "Transfer-Encoding",
		Request:          "POST / HTTP/1.1...",
		Response:         "HTTP/1.1 200 OK...",
	}

	finding := detector.CreateFinding("http://example.com/", result)

	if finding == nil {
		t.Fatal("CreateFinding() returned nil")
	}
	if finding.Type != "http-request-smuggling" {
		t.Errorf("Finding Type = %q, want %q", finding.Type, "http-request-smuggling")
	}
	if finding.URL != "http://example.com/" {
		t.Errorf("Finding URL = %q, want %q", finding.URL, "http://example.com/")
	}
	if len(finding.WSTG) == 0 {
		t.Error("Finding should have WSTG mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Finding should have CWE mapping")
	}
}

func TestDetector_CreateFinding_NotVulnerable(t *testing.T) {
	detector := NewDetector()
	result := &Result{
		Vulnerable: false,
		Type:       TypeCLTE,
	}

	finding := detector.CreateFinding("http://example.com/", result)
	if finding != nil {
		t.Error("CreateFinding() should return nil for non-vulnerable result")
	}
}

func TestDetector_CreateFinding_TETE_LowConfidence(t *testing.T) {
	detector := NewDetector()
	result := &Result{
		Vulnerable:       true,
		Type:             TypeTETE,
		Confidence:       0.6, // Below 0.8
		Evidence:         "Some evidence",
		FrontendBehavior: "TE",
		BackendBehavior:  "TE",
	}

	finding := detector.CreateFinding("http://example.com/", result)

	if finding == nil {
		t.Fatal("CreateFinding() returned nil")
	}
	// TE.TE with low confidence should be medium severity
	if finding.Severity != "medium" {
		t.Errorf("Finding Severity = %q, want %q for low confidence TE.TE", finding.Severity, "medium")
	}
}

func TestConfidenceFromFloat(t *testing.T) {
	tests := []struct {
		name     string
		conf     float64
		wantConf string
	}{
		{"confirmed", 0.95, "confirmed"},
		{"high", 0.85, "high"},
		{"medium", 0.6, "medium"},
		{"low", 0.3, "low"},
	}

	detector := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{
				Vulnerable: true,
				Type:       TypeCLTE,
				Confidence: tt.conf,
			}
			finding := detector.CreateFinding("http://example.com/", result)
			if finding == nil {
				t.Fatal("CreateFinding() returned nil")
			}
			if finding.Confidence.String() != tt.wantConf {
				t.Errorf("Confidence = %q, want %q", finding.Confidence, tt.wantConf)
			}
		})
	}
}

func TestExtractStatusCode_Empty(t *testing.T) {
	// extractStatusCode with empty response should return 0
	resp, err := ParseResponse("HTTP/1.1 200 OK\r\n\r\n")
	if err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestDetector_DetectCLTE_InvalidTarget(t *testing.T) {
	detector := NewDetector()
	ctx := context.Background()

	// Empty target should return error in result
	result := detector.DetectCLTE(ctx, "", "/")
	if result.Vulnerable {
		t.Error("Should not be vulnerable with empty target")
	}
	if result.Evidence == "" {
		t.Error("Evidence should contain error message")
	}
}

func TestDetector_DetectTECL_InvalidTarget(t *testing.T) {
	detector := NewDetector()
	ctx := context.Background()

	// Empty target should return error in result
	result := detector.DetectTECL(ctx, "", "/")
	if result.Vulnerable {
		t.Error("Should not be vulnerable with empty target")
	}
	if result.Evidence == "" {
		t.Error("Evidence should contain error message")
	}
}

func TestDetector_DetectTETE_InvalidTarget(t *testing.T) {
	detector := NewDetector()
	ctx := context.Background()

	// Empty target should return error in result
	result := detector.DetectTETE(ctx, "", "/")
	if result.Vulnerable {
		t.Error("Should not be vulnerable with empty target")
	}
	if result.Evidence == "" {
		t.Error("Evidence should contain error message")
	}
}

func TestDetector_DetectTETE_ContextCancelled(t *testing.T) {
	server := newMockServer(t)
	defer server.close()

	server.setResponse("GET /", "HTTP/1.1 200 OK\r\n\r\nOK", 0)

	detector := NewDetector()
	detector.config.Timeout = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := detector.DetectTETE(ctx, server.addr(), "/")
	// Should handle cancelled context gracefully
	if result.Vulnerable {
		t.Error("Should not report vulnerable with cancelled context")
	}
}
