package oauthflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func TestDetectResourceIndicatorConfusion_VulnerableServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// IdP that doesn't validate resource → redirects to login.
		http.Redirect(w, r, "https://idp.example/login?continue="+r.URL.RawQuery, http.StatusFound)
	}))
	defer srv.Close()

	d := New(scanhttp.NewClient())
	opts := DefaultOptions()
	opts.ClientID = "test-client"
	opts.RegisteredRedirectURI = "https://app.example/cb"
	res, err := d.DetectResourceIndicatorConfusion(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on accepting IdP")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %q", f.Severity)
	}
	if !strings.Contains(f.Title, "resource-indicator") &&
		!strings.Contains(f.Title, "multi-resource") {
		t.Errorf("unexpected title %q", f.Title)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestDetectResourceIndicatorConfusion_HardenedServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server correctly rejects multi-resource with the documented error.
		resources := r.URL.Query()["resource"]
		if len(resources) > 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_resource","error_description":"unknown audience"}`))
			return
		}
		http.Redirect(w, r, "https://idp.example/login", http.StatusFound)
	}))
	defer srv.Close()

	d := New(scanhttp.NewClient())
	opts := DefaultOptions()
	res, err := d.DetectResourceIndicatorConfusion(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened server flagged: %v", res.Findings)
	}
}

func TestDetectResourceIndicatorConfusion_BadURL(t *testing.T) {
	d := New(scanhttp.NewClient())
	opts := DefaultOptions()
	_, err := d.DetectResourceIndicatorConfusion(context.Background(), "://broken-url", opts)
	if err == nil {
		t.Error("expected error on malformed URL")
	}
}
