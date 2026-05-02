package apiversion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FindsLegacyAndV0Siblings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/users"):
			_, _ = w.Write([]byte(`{"version": "v1", "users": []}`))
		case strings.HasPrefix(r.URL.Path, "/api/v0/users"):
			_, _ = w.Write([]byte(`{"version": "v0", "deprecated": true, "users": [{"id": 1, "name": "alice"}]}`))
		case strings.HasPrefix(r.URL.Path, "/api/legacy/users"):
			_, _ = w.Write([]byte(`{"version": "legacy", "users": [{"id": 1}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Parameter] = true
	}
	if !got["v0"] {
		t.Errorf("expected v0 sibling found, got %v", got)
	}
	if !got["legacy"] {
		t.Errorf("expected legacy sibling found, got %v", got)
	}
}

func TestDetect_NoVersionSegmentNoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/users")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on URL without /vN/, got %d", len(res.Findings))
	}
}

func TestDetect_SuppressesIdenticalBodies(t *testing.T) {
	// All versions return the exact same body — likely a single handler.
	const body = `{"users":[{"id":1,"name":"alice"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when all sibling bodies match, got %d", len(res.Findings))
	}
}

func TestDetect_SuppressesAuthControlled(t *testing.T) {
	// Sibling versions return 401 — that's the gate working.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/users") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"v1"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on auth-controlled siblings, got %d", len(res.Findings))
	}
}
