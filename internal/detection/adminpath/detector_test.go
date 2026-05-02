package adminpath

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FindsExposedActuator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator/env":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"propertySources": [{"name": "applicationConfig"}]}`))
		case "/.env":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("DB_PASSWORD=hunter2"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}

	paths := map[string]bool{}
	for _, f := range res.Findings {
		paths[f.Parameter] = true
	}
	if !paths["/actuator/env"] {
		t.Errorf("expected /actuator/env in findings, got %v", paths)
	}
	if !paths["/.env"] {
		t.Errorf("expected /.env in findings, got %v", paths)
	}
}

func TestDetect_SuppressesSoft404(t *testing.T) {
	// Server returns 200 + same body for EVERY path. Baseline canary will
	// match every probe → no findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>404 Not Found</h1><p>Sorry, the page you requested could not be found.</p></body></html>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on soft-404 server, got %d (first: %v)",
			len(res.Findings), res.Findings[0].Parameter)
	}
}

func TestDetect_DoesNotFlag401Or403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/admin"):
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasPrefix(r.URL.Path, "/api/admin"):
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when admin paths return 401/403, got %d", len(res.Findings))
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
