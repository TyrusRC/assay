package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_ServesIndex(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("index code = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("index body is empty")
	}
}

func TestHandler_SPAFallback(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	// An unknown client-side route must fall back to index.html (200), not 404.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scans/abc123", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Errorf("SPA fallback code = %d, want 200", rec.Code)
	}
}
