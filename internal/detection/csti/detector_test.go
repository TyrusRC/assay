package csti

import (
	"context"
	"fmt"
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
	// Simulate Angular app that evaluates template expressions
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		if strings.Contains(input, "{{") && strings.Contains(input, "}}") {
			// Simulate template evaluation
			if strings.Contains(input, "7*7") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf("<div>Search result: 49</div>")))
				return
			}
			if strings.Contains(input, "9999*9999") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf("<div>Search result: 99980001</div>")))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("<div>Search result: %s</div>", input)))
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
		if strings.Contains(input, "${") {
			if strings.Contains(input, "9999+1") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<p>Hello 10000</p>"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("<p>Hello %s</p>", input)))
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
		if strings.Contains(input, "7*7") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Result: 49"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal"))
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
