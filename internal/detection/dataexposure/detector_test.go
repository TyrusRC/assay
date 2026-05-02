package dataexposure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": 1,
			"username": "alice",
			"password_hash": "$2b$12$abc...",
			"profile": {
				"email": "alice@x.test",
				"phone": "555-1234"
			}
		}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/users/1")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	keysFound := map[string]bool{}
	for _, f := range res.Findings {
		keysFound[f.Parameter] = true
	}
	if !keysFound["password_hash"] {
		t.Error("expected password_hash to be flagged")
	}
	if !keysFound["profile.phone"] {
		t.Error("expected profile.phone to be flagged (nested path)")
	}
}

func TestDetect_NoFlagsOnSafeJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": 1, "name": "Widget", "price": 9.99}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/products/1")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on safe JSON, got %d", len(res.Findings))
	}
}

func TestDetect_NonJSONIgnored(t *testing.T) {
	// HTML body with the literal string "password" — must not trigger.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Forgot password? Click here.</body></html>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/login")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on HTML, got %d", len(res.Findings))
	}
}

func TestDetect_FlagsArrayOfRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"id": 1, "name": "alice", "api_key": "ak_live_abc123"},
			{"id": 2, "name": "bob"}
		]`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/users")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected api_key in element 0 to be flagged")
	}
	if !strings.Contains(res.Findings[0].Parameter, "[0].api_key") {
		t.Errorf("expected path with [0].api_key, got %q", res.Findings[0].Parameter)
	}
	if res.Findings[0].Severity != core.SeverityCritical {
		t.Errorf("api_key severity = %v, want Critical", res.Findings[0].Severity)
	}
}

func TestDetect_ValueSnippetIsTruncated(t *testing.T) {
	// Confirm we never echo the full value into evidence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jwt_secret": "this-is-a-very-long-server-side-signing-key-please-do-not-leak-me"}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/config")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected jwt_secret to be flagged")
	}
	if strings.Contains(res.Findings[0].Evidence, "please-do-not-leak-me") {
		t.Errorf("evidence leaked the full secret value: %q", res.Findings[0].Evidence)
	}
}

func TestDetect_NilClientNoOp(t *testing.T) {
	det := &Detector{client: nil}
	res, err := det.Detect(context.Background(), "http://x.test/")
	if err != nil {
		t.Fatalf("nil-client should not error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("nil-client should produce 0 findings, got %d", len(res.Findings))
	}
}
