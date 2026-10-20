package injection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	assayhttp "github.com/TyrusRC/assay/internal/http"
)

func TestDetectDifferential_QuoteBreaksResponse(t *testing.T) {
	// Simulate a backend that concatenates the param into SQL:
	//   SELECT * FROM users WHERE name = '<val>'
	// A bare single-quote produces a syntax error (500). A balanced
	// injection like ' AND '1'='1 is valid SQL and returns normally.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("username")
		if val == "" {
			_ = r.ParseForm()
			val = r.FormValue("username")
		}
		w.Header().Set("Content-Type", "application/json")

		// Count unescaped single-quotes — odd count = syntax error.
		quoteCount := strings.Count(val, "'")
		if quoteCount%2 != 0 {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":{"message":"internal error"}}`))
			return
		}

		// Even-quote injections: simulate boolean control.
		if strings.Contains(val, "1'='2") || strings.Contains(val, "1=2") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}

		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"results":[{"id":1,"name":"alice"}]}`))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := assayhttp.NewClient()
	detector := NewSQLiDetector()

	res, err := detector.DetectDifferential(context.Background(), client, server.URL+"?username=test", "username", "GET")
	if err != nil {
		t.Fatalf("DetectDifferential() error = %v", err)
	}
	if !res.IsVulnerable {
		t.Fatal("DetectDifferential() should detect SQLi — quote changes response shape")
	}
	if res.DetectionType != "response-differential" {
		t.Errorf("DetectionType = %q, want %q", res.DetectionType, "response-differential")
	}
	if res.Confidence <= 0 {
		t.Errorf("Confidence = %f, want > 0", res.Confidence)
	}
}

func TestDetectDifferential_NoSQLi(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := assayhttp.NewClient()
	detector := NewSQLiDetector()

	res, err := detector.DetectDifferential(context.Background(), client, server.URL+"?q=hello", "q", "GET")
	if err != nil {
		t.Fatalf("DetectDifferential() error = %v", err)
	}
	if res.IsVulnerable {
		t.Fatal("DetectDifferential() should not detect SQLi — response is static")
	}
}

func TestDetectDifferential_UnstableBaseline(t *testing.T) {
	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		// Every response is completely different — unstable baseline.
		_, _ = w.Write([]byte(`{"counter":` + strings.Repeat("x", callCount*100) + `}`))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := assayhttp.NewClient()
	detector := NewSQLiDetector()

	res, err := detector.DetectDifferential(context.Background(), client, server.URL+"?x=1", "x", "GET")
	if err != nil {
		t.Fatalf("DetectDifferential() error = %v", err)
	}
	if res.IsVulnerable {
		t.Fatal("DetectDifferential() should not fire on an unstable baseline")
	}
}

func TestDetectDifferential_NilClient(t *testing.T) {
	detector := NewSQLiDetector()
	res, err := detector.DetectDifferential(context.Background(), nil, "http://example.com", "x", "GET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsVulnerable {
		t.Fatal("should not be vulnerable with nil client")
	}
}
