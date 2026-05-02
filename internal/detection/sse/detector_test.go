package sse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsUnauthenticatedEventsStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/events":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: {\"id\":1,\"event\":\"order.placed\"}\n\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected finding for /api/v1/events")
	}
	if res.Findings[0].Parameter != "/api/v1/events" {
		t.Errorf("expected path /api/v1/events, got %q", res.Findings[0].Parameter)
	}
}

func TestDetect_NoFindingWhen401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/events") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on 401-protected SSE, got %d", len(res.Findings))
	}
}

func TestDetect_NoFindingOnNonSSE200(t *testing.T) {
	// /events exists but returns regular HTML.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Events page</body></html>"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on HTML 200, got %d", len(res.Findings))
	}
}

func TestDetect_FallsBackToBodyShape(t *testing.T) {
	// Server omits content-type but body is a valid SSE frame.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Error("expected body-shape detection to flag /stream even without content-type")
	}
}
