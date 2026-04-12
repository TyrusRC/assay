package analysis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	skwshttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNewBooleanDifferential(t *testing.T) {
	bd := NewBooleanDifferential()
	if bd == nil {
		t.Fatal("NewBooleanDifferential() returned nil")
	}
	if bd.similarityThreshold <= 0 || bd.similarityThreshold > 1.0 {
		t.Errorf("similarityThreshold = %f, want a value in (0, 1]", bd.similarityThreshold)
	}
}

func TestBooleanDifferential_Analyze_TrueDifferential(t *testing.T) {
	// Server returns different content for "true" payload, same for everything else.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		switch param {
		case "1' AND '1'='1":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Welcome admin! Here is your secret data panel with user details."))
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Invalid credentials. Please try again with valid input."))
		}
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	bd := NewBooleanDifferential()

	result := bd.Analyze(
		context.Background(),
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"1' AND '1'='1",
		"1' AND '1'='2",
	)

	if result == nil {
		t.Fatal("Analyze() returned nil")
	}
	if !result.IsDifferential {
		t.Error("IsDifferential should be true for boolean differential")
	}
	if result.Confidence <= 0 {
		t.Errorf("Confidence = %f, want > 0", result.Confidence)
	}
	if result.BaselineBody == "" {
		t.Error("BaselineBody should not be empty")
	}
	if result.TrueBody == "" {
		t.Error("TrueBody should not be empty")
	}
	if result.FalseBody == "" {
		t.Error("FalseBody should not be empty")
	}
}

func TestBooleanDifferential_Analyze_NoDifferential(t *testing.T) {
	// Server returns the same content for all payloads.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Static content that never changes regardless of input."))
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	bd := NewBooleanDifferential()

	result := bd.Analyze(
		context.Background(),
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"1' AND '1'='1",
		"1' AND '1'='2",
	)

	if result == nil {
		t.Fatal("Analyze() returned nil")
	}
	if result.IsDifferential {
		t.Error("IsDifferential should be false when all responses are the same")
	}
	if result.Confidence != 0 {
		t.Errorf("Confidence = %f, want 0", result.Confidence)
	}
}

func TestBooleanDifferential_Analyze_FalseDifferential(t *testing.T) {
	// Server returns different content for every single request (random-like).
	// This should NOT be detected as a differential since the baseline itself is unstable.
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		// Each response is completely different from others.
		switch callCount {
		case 1:
			w.Write([]byte("alpha bravo charlie delta echo foxtrot golf"))
		case 2:
			w.Write([]byte("hotel india juliet kilo lima mike november"))
		case 3:
			w.Write([]byte("oscar papa quebec romeo sierra tango uniform"))
		default:
			w.Write([]byte("victor whiskey xray yankee zulu one two three"))
		}
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	bd := NewBooleanDifferential()

	result := bd.Analyze(
		context.Background(),
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"1' AND '1'='1",
		"1' AND '1'='2",
	)

	if result == nil {
		t.Fatal("Analyze() returned nil")
	}
	if result.IsDifferential {
		t.Error("IsDifferential should be false for unstable/random responses")
	}
}

func TestBooleanDifferential_Analyze_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("content"))
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	bd := NewBooleanDifferential()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := bd.Analyze(
		ctx,
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"true_payload",
		"false_payload",
	)

	if result == nil {
		t.Fatal("Analyze() returned nil on cancelled context")
	}
	if result.IsDifferential {
		t.Error("IsDifferential should be false when context is cancelled")
	}
}

func TestDifferentialResult_Fields(t *testing.T) {
	result := &DifferentialResult{
		IsDifferential: true,
		Confidence:     0.95,
		BaselineBody:   "baseline",
		TrueBody:       "true body",
		FalseBody:      "false body",
	}

	if !result.IsDifferential {
		t.Error("IsDifferential should be true")
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", result.Confidence)
	}
	if result.BaselineBody != "baseline" {
		t.Errorf("BaselineBody = %q", result.BaselineBody)
	}
	if result.TrueBody != "true body" {
		t.Errorf("TrueBody = %q", result.TrueBody)
	}
	if result.FalseBody != "false body" {
		t.Errorf("FalseBody = %q", result.FalseBody)
	}
}
