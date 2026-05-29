package vhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_FindsDistinctVHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "admin.") {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>INTERNAL ADMIN PANEL</html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("public homepage"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	opts := DefaultOptions()
	opts.MaxVHosts = 200 // ensure 'admin' candidate is in range
	res, err := d.Detect(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true when admin.* returns distinct content")
	}
	found := false
	for _, h := range res.FoundHosts {
		if strings.HasPrefix(h, "admin.") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected admin.* in found hosts, got %v", res.FoundHosts)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
	f := res.Findings[0]
	if f.Type != "virtualhost_disclosure" {
		t.Errorf("unexpected type %q", f.Type)
	}
	if f.Severity != core.SeverityLow {
		t.Errorf("expected SeverityLow, got %q", f.Severity)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestDetector_Detect_NoFindingsForUniformServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("static response, same for every Host"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on uniform server, got %v", res.FoundHosts)
	}
}

func TestDetector_Detect_RespectMaxFindings(t *testing.T) {
	// Every Host: header gets a unique response body — capped at MaxFindings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response for " + r.Host))
	}))
	defer srv.Close()

	d := New(srv.Client())
	opts := DefaultOptions()
	opts.MaxFindings = 3
	opts.MaxVHosts = 50
	res, err := d.Detect(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 3 {
		t.Errorf("expected findings capped at 3, got %d", len(res.Findings))
	}
}

func TestDetector_Detect_BadURLError(t *testing.T) {
	d := New(http.DefaultClient)
	_, err := d.Detect(context.Background(), "://broken-url", DefaultOptions())
	if err == nil {
		t.Error("expected error for malformed URL")
	}
}

func TestDetector_Detect_TimeoutSurvives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("slow"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	opts := DefaultOptions()
	opts.MaxVHosts = 5
	opts.Timeout = 200 * time.Millisecond
	_, err := d.Detect(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("Detect should tolerate slow baselines: %v", err)
	}
}

func TestRootDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"single", "single"},
	}
	for _, c := range cases {
		if got := rootDomain(c.in); got != c.want {
			t.Errorf("rootDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
