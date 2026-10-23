package sesstimeout

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ahttp "github.com/TyrusRC/assay/internal/http"
)

func TestDetect_SessionSurvives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "authenticated content")
	}))
	defer srv.Close()

	client := ahttp.NewClient()
	det := New(client)
	findings, err := det.Detect(context.Background(), srv.URL, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestDetect_Unauthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	client := ahttp.NewClient()
	det := New(client)
	findings, err := det.Detect(context.Background(), srv.URL, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Error("expected no finding for unauthenticated endpoint")
	}
}
