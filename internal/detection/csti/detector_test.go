package csti

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
		t.Error("client not set correctly")
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

func TestDetector_DetectAngularCSTI(t *testing.T) {
	// Simulate Angular app that evaluates template expressions IN PLACE —
	// a real engine replaces the `{{expr}}` syntax inside the surrounding
	// text, so the detector's sentinel wrapper ends up bracketing the
	// evaluated result.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		rendered := input
		for expr, val := range map[string]string{"7*7": "49", "9999*9999": "99980001"} {
			rendered = strings.ReplaceAll(rendered, "{{"+expr+"}}", val)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<div>Search result: " + rendered + "</div>"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?q=test",
		"q", "GET",
		DetectOptions{MaxPayloads: 30},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected CSTI vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectTemplateLiteral(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("name")
		rendered := input
		for expr, val := range map[string]string{"9999+1": "10000", "7*7": "49"} {
			rendered = strings.ReplaceAll(rendered, "${"+expr+"}", val)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<p>Hello " + rendered + "</p>"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?name=user",
		"name", "GET",
		DetectOptions{MaxPayloads: 30},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected template literal CSTI to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe response - no template evaluation"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?q=test",
		"q", "GET",
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
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := detector.Detect(ctx, server.URL+"?q=test", "q", "GET", DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		// In-place evaluation for common CSTI expressions so the sentinel
		// wrapper ends up bracketing the result.
		rendered := input
		for _, expr := range []string{"{{7*7}}", "${7*7}", "#{7*7}"} {
			rendered = strings.ReplaceAll(rendered, expr, "49")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Result: " + rendered))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?q=test",
		"q", "GET",
		DetectOptions{MaxPayloads: 10},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability to be detected")
	}

	finding := result.Findings[0]
	if finding.Type != "Client-Side Template Injection" {
		t.Errorf("Expected type 'Client-Side Template Injection', got %s", finding.Type)
	}
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}

func TestDetector_ExpressionEvaluation(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
		match    bool
	}{
		{name: "49 in body", body: "result: 49", expected: "49", match: true},
		{name: "99980001 in body", body: "got 99980001 items", expected: "99980001", match: true},
		{name: "no match", body: "nothing here", expected: "49", match: false},
		{name: "payload reflected literally", body: "{{7*7}}", expected: "49", match: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.containsExpected(tt.body, tt.expected)
			if result != tt.match {
				t.Errorf("containsExpected() = %v, want %v", result, tt.match)
			}
		})
	}
}
