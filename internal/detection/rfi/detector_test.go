package rfi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
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

func TestDetector_DetectRFI(t *testing.T) {
	// Create a server that simulates RFI vulnerability by including remote content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page != "" && strings.Contains(page, "httpbin.org") {
			// Simulate fetching remote content
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("RFITEST"))
			return
		}
		if page != "" && strings.Contains(page, "data://") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("RFITEST"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal page content"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?page=index.php",
		"page", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected RFI vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe response - no inclusion"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?page=index.php",
		"page", "GET",
		DetectOptions{MaxPayloads: 5},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_DetectDataURI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("file")
		if strings.HasPrefix(page, "data:") || strings.HasPrefix(page, "data://") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("RFITEST"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal page"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(
		context.Background(),
		server.URL+"?file=test.txt",
		"file", "GET",
		DetectOptions{MaxPayloads: 20},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected data URI RFI to be detected")
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

	_, err := detector.Detect(ctx, server.URL+"?page=test", "page", "GET", DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_FindingType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if strings.Contains(page, "http") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("RFITEST"))
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
		server.URL+"?page=index",
		"page", "GET",
		DetectOptions{MaxPayloads: 5},
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability to be detected")
	}

	finding := result.Findings[0]
	if finding.Type != "Remote File Inclusion" {
		t.Errorf("Expected type 'Remote File Inclusion', got %s", finding.Type)
	}

	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
}

func TestDetector_DeduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payloads := []rfiPayload{
		{Value: "http://test.com", Description: "test1"},
		{Value: "http://test.com", Description: "test2"},
		{Value: "http://other.com", Description: "test3"},
	}

	deduped := detector.deduplicatePayloads(payloads)

	if len(deduped) != 2 {
		t.Errorf("Expected 2 unique payloads, got %d", len(deduped))
	}
}
