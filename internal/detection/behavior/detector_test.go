package behavior

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("Expected non-nil detector")
	}
	if detector.client == nil {
		t.Error("Expected client to be set")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("Expected verbose to be true")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", opts.Timeout)
	}
	if opts.TimingThreshold != 3*time.Second {
		t.Errorf("Expected timing threshold 3s, got %v", opts.TimingThreshold)
	}
	if opts.ContentDiffThreshold != 0.3 {
		t.Errorf("Expected content diff threshold 0.3, got %v", opts.ContentDiffThreshold)
	}
}

func TestDetector_EstablishBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal response content"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	baseline, err := detector.EstablishBaseline(context.Background(), server.URL+"?param=test", "param", "GET")

	if err != nil {
		t.Fatalf("EstablishBaseline failed: %v", err)
	}
	if baseline == nil {
		t.Fatal("Expected non-nil baseline")
	}
	if baseline.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", baseline.StatusCode)
	}
	if baseline.ContentLength == 0 {
		t.Error("Expected non-zero content length")
	}
	if baseline.ContentHash == "" {
		t.Error("Expected non-empty content hash")
	}
}

func TestDetector_checkStatusAnomaly(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name           string
		respStatus     int
		baselineStatus int
		expectAnomaly  bool
	}{
		{"same status", 200, 200, false},
		{"different status", 500, 200, true},
		{"forbidden", 403, 200, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{StatusCode: tt.respStatus}
			baseline := &Baseline{StatusCode: tt.baselineStatus}

			anomaly := detector.checkStatusAnomaly(resp, baseline)

			if tt.expectAnomaly && anomaly == nil {
				t.Error("Expected anomaly but got nil")
			}
			if !tt.expectAnomaly && anomaly != nil {
				t.Errorf("Expected no anomaly but got: %v", anomaly)
			}
		})
	}
}

func TestDetector_checkTimingAnomaly(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()

	tests := []struct {
		name          string
		respDuration  time.Duration
		baseDuration  time.Duration
		expectAnomaly bool
	}{
		{"normal timing", 100 * time.Millisecond, 100 * time.Millisecond, false},
		{"slight delay", 500 * time.Millisecond, 100 * time.Millisecond, false},
		{"significant delay", 5 * time.Second, 100 * time.Millisecond, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{Duration: tt.respDuration}
			baseline := &Baseline{ResponseTime: tt.baseDuration}

			anomaly := detector.checkTimingAnomaly(resp, baseline, opts)

			if tt.expectAnomaly && anomaly == nil {
				t.Error("Expected anomaly but got nil")
			}
			if !tt.expectAnomaly && anomaly != nil {
				t.Errorf("Expected no anomaly but got: %v", anomaly)
			}
		})
	}
}

func TestDetector_checkErrorDisclosure(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name          string
		body          string
		expectAnomaly bool
	}{
		{"no error", "Normal page content", false},
		{"stack trace", "Error: Stack trace follows...", true},
		{"php warning", "Warning: mysqli_connect()", true},
		{"python traceback", "Traceback (most recent call last):", true},
		{"file path", "Error in /var/www/html/index.php", true},
		{"java exception", "Exception in thread at Main.java:42", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{Body: tt.body}
			baseline := &Baseline{ErrorPatterns: []string{}}

			anomaly := detector.checkErrorDisclosure(resp, baseline)

			if tt.expectAnomaly && anomaly == nil {
				t.Error("Expected anomaly but got nil")
			}
			if !tt.expectAnomaly && anomaly != nil {
				t.Errorf("Expected no anomaly but got: %v", anomaly)
			}
		})
	}
}

func TestDetector_checkReflection(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name          string
		body          string
		payload       string
		expectAnomaly bool
	}{
		{"no reflection", "Normal content", "test", false},
		{"exact reflection", "Hello <script>alert(1)</script> world", "<script>alert(1)</script>", true},
		{"dangerous chars", "Value: <test>", "<test", true},
		{"short payload", "ab", "ab", false}, // Too short to detect
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{Body: tt.body}

			anomaly := detector.checkReflection(resp, tt.payload)

			if tt.expectAnomaly && anomaly == nil {
				t.Error("Expected anomaly but got nil")
			}
			if !tt.expectAnomaly && anomaly != nil {
				t.Errorf("Expected no anomaly but got: %v", anomaly)
			}
		})
	}
}

func TestDetector_checkContentAnomaly(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()

	tests := []struct {
		name          string
		respBody      string
		baselineLen   int
		expectAnomaly bool
	}{
		{"same content", "Same content", 12, false},
		{"much larger", "This is a much much much longer response", 5, true},
		{"much smaller", "Hi", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{Body: tt.respBody}
			baseline := &Baseline{
				ContentLength: tt.baselineLen,
				ContentHash:   detector.hashContent("different"),
			}

			anomaly := detector.checkContentAnomaly(resp, baseline, opts)

			if tt.expectAnomaly && anomaly == nil {
				t.Error("Expected anomaly but got nil")
			}
			if !tt.expectAnomaly && anomaly != nil {
				t.Errorf("Expected no anomaly but got: %v", anomaly)
			}
		})
	}
}

func TestDetector_CreateFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	anomaly := &Anomaly{
		Type:        BehaviorErrorDisclosure,
		Description: "Stack trace disclosed",
		Confidence:  core.ConfidenceHigh,
		Evidence:    "at Main.java:42",
		Payload:     "test'",
	}

	finding := detector.CreateFinding("http://example.com", "param", anomaly)

	if finding == nil {
		t.Fatal("Expected non-nil finding")
	}
	if finding.URL != "http://example.com" {
		t.Errorf("Expected URL 'http://example.com', got '%s'", finding.URL)
	}
	if finding.Parameter != "param" {
		t.Errorf("Expected parameter 'param', got '%s'", finding.Parameter)
	}
	if finding.Tool != "behavior-detector" {
		t.Errorf("Expected tool 'behavior-detector', got '%s'", finding.Tool)
	}
}

func TestBehaviorType_Values(t *testing.T) {
	types := []BehaviorType{
		BehaviorTimingAnomaly,
		BehaviorContentAnomaly,
		BehaviorStatusAnomaly,
		BehaviorErrorDisclosure,
		BehaviorReflection,
		BehaviorRedirectAnomaly,
		BehaviorHeaderAnomaly,
	}

	for _, bt := range types {
		if bt == "" {
			t.Error("Behavior type should not be empty")
		}
	}
}

func TestDetector_AnalyzeResponse(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	opts := DefaultOptions()

	baseline := &Baseline{
		StatusCode:    200,
		ContentLength: 100,
		ContentHash:   detector.hashContent("baseline content"),
		ResponseTime:  100 * time.Millisecond,
		Headers:       map[string]string{},
		ErrorPatterns: []string{},
	}

	resp := &internalhttp.Response{
		StatusCode: 500,
		Body:       "Fatal error: Stack trace follows...",
		Duration:   100 * time.Millisecond,
		Headers:    map[string]string{},
	}

	anomalies := detector.AnalyzeResponse(resp, baseline, "test'", opts)

	if len(anomalies) == 0 {
		t.Error("Expected at least one anomaly")
	}

	// Should detect status anomaly and error disclosure
	hasStatusAnomaly := false
	hasErrorDisclosure := false
	for _, a := range anomalies {
		if a.Type == BehaviorStatusAnomaly {
			hasStatusAnomaly = true
		}
		if a.Type == BehaviorErrorDisclosure {
			hasErrorDisclosure = true
		}
	}

	if !hasStatusAnomaly {
		t.Error("Expected status anomaly to be detected")
	}
	if !hasErrorDisclosure {
		t.Error("Expected error disclosure to be detected")
	}
}
