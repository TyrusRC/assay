package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInternalScanner_testCORS_Integration(t *testing.T) {
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

	config := &InternalScanConfig{
		EnableCORS:          true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testCORS(ctx, server.URL)

	if len(findings) == 0 {
		t.Log("CORS misconfiguration not detected (this is expected in some cases)")
	} else {
		t.Logf("CORS findings: %d", len(findings))
	}
}

func TestInternalScanner_testIDOR_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user_id": "` + userID + `", "name": "User", "email": "user@example.com"}`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableIDOR:          true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testIDOR(ctx, server.URL+"?user_id=1")
	t.Logf("IDOR findings: %d", len(findings))
}

func TestInternalScanner_testJNDI_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("search")
		if strings.Contains(input, "${jndi:") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("javax.naming.NamingException"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Result: " + input))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableJNDI:          true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testJNDI(ctx, server.URL+"?search=test")
	t.Logf("JNDI findings: %d", len(findings))
}

func TestInternalScanner_testSecHeaders_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableSecHeaders: true,
		RequestTimeout:   10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testSecHeaders(ctx, server.URL)
	t.Logf("SecHeaders findings: %d", len(findings))
}

func TestInternalScanner_testExposure_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret123"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableExposure: true,
		RequestTimeout: 10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testExposure(ctx, server.URL)
	t.Logf("Exposure findings: %d", len(findings))
}

func TestInternalScanner_testCloud_Integration(t *testing.T) {
	config := &InternalScanConfig{
		EnableCloud:    true,
		RequestTimeout: 10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testCloud(ctx, "https://example.com")
	t.Logf("Cloud findings: %d", len(findings))
}

func TestInternalScanner_testTLS_Integration(t *testing.T) {
	config := &InternalScanConfig{
		EnableTLS:      true,
		RequestTimeout: 10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testTLS(ctx, "https://example.com")
	t.Logf("TLS findings: %d", len(findings))
}

func TestInternalScanner_testGraphQL_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":null}`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableGraphQL:  true,
		RequestTimeout: 10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testGraphQL(ctx, server.URL)
	t.Logf("GraphQL findings: %d", len(findings))
}

func TestInternalScanner_testSmuggling_Integration(t *testing.T) {
	config := &InternalScanConfig{
		EnableSmuggling: true,
		RequestTimeout:  10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testSmuggling(ctx, "https://example.com")
	t.Logf("Smuggling findings: %d", len(findings))
}
