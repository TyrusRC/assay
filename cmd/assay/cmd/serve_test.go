package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/api"
	"github.com/TyrusRC/assay/internal/scanner"
)

type stubRunner struct{}

func (stubRunner) Run(_ context.Context, req api.ScanRequest) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{Targets: []string{req.Target}}, nil
}

func TestBuildServeMux_RoutesAPIAndUI(t *testing.T) {
	mux, err := buildServeMux(stubRunner{})
	if err != nil {
		t.Fatalf("buildServeMux: %v", err)
	}

	// API is mounted under /api/.
	recAPI := httptest.NewRecorder()
	mux.ServeHTTP(recAPI, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
	if recAPI.Code != http.StatusOK || !strings.Contains(recAPI.Body.String(), "ok") {
		t.Errorf("/api/health = %d %q", recAPI.Code, recAPI.Body.String())
	}

	// The SPA is served at the root.
	recUI := httptest.NewRecorder()
	mux.ServeHTTP(recUI, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if recUI.Code != http.StatusOK || recUI.Body.Len() == 0 {
		t.Errorf("/ = %d (len %d)", recUI.Code, recUI.Body.Len())
	}
}
