package iistilde

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

func TestScannerDetector_DetectsVulnerableIIS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "a~1") || strings.Contains(r.URL.Path, "A~1") {
			http.Error(w, "Bad", http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.DetectWithOptions(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true on differential IIS host")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "iis_tilde_disclosure" {
		t.Errorf("unexpected type %q", f.Type)
	}
	if f.Severity != core.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %q", f.Severity)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestScannerDetector_NotVulnerableNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, &http.Request{})
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.DetectWithOptions(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Error("expected Vulnerable=false on uniform 404 server")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

func TestScannerDetector_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	d := New(srv.Client())
	_, err := d.DetectWithOptions(ctx, srv.URL, DefaultOptions())
	if err == nil {
		t.Error("expected error when ctx cancels before probe finishes")
	}
}
