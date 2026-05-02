package csrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsMissingOriginCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Server happily processes any POST regardless of Origin.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true, "id": 123}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/profile", "POST", `{"email":"x@y.test"}`)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 CSRF finding, got %d", len(res.Findings))
	}
}

func TestDetect_NoFindingWhenOriginRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server rejects requests with a foreign Origin.
		if origin := r.Header.Get("Origin"); origin != "" && !strings.Contains(origin, r.Host) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/transfer", "POST", `{"amount":1}`)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when Origin is enforced, got %d", len(res.Findings))
	}
}

func TestDetect_SkipsGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users", "GET", "")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings for GET method, got %d", len(res.Findings))
	}
}

func TestDetect_SkipsNonStateChangePathWithoutBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	// No body, path doesn't match state-change hints → skip silently.
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/products", "POST", "")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on non-state-change path with no body, got %d", len(res.Findings))
	}
}

func TestDetect_NilClientNoOp(t *testing.T) {
	det := &Detector{client: nil}
	res, err := det.Detect(context.Background(), "http://x.test/login", "POST", "")
	if err != nil {
		t.Fatalf("nil-client should not error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}
