package iistilde

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbes_NonEmpty(t *testing.T) {
	got := Probes()
	if len(got) < 4 {
		t.Errorf("expected at least 4 tilde probes, got %d", len(got))
	}
	for _, p := range got {
		if !strings.Contains(p.Path, "~1") {
			t.Errorf("probe path %q missing ~1 short-name marker", p.Path)
		}
	}
}

func TestProbeMethods_AreServerSafe(t *testing.T) {
	got := Probes()
	if len(got) == 0 {
		t.Fatal("no probes to assert on")
	}
	for _, p := range got {
		// IIS tilde enumeration relies on the differential between an
		// HTTP method that produces 404 (no match) vs. the method that
		// produces a distinguishing code (e.g. 200/400) — both must be
		// read-only methods.
		switch p.Method {
		case http.MethodGet, http.MethodOptions, "DEBUG", "TRACK":
			// ok
		default:
			t.Errorf("probe %q uses non-read-safe method %q", p.Path, p.Method)
		}
	}
}

func TestDetectVulnerable_DifferentialResponse(t *testing.T) {
	// Mock IIS that returns 404 only when the short name doesn't exist
	// (the tilde-vulnerability tell). Existing names get 400.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Per the vulnerability: a matching short name yields 400, a
		// non-matching one yields 404.
		if strings.Contains(r.URL.Path, "A~1") || strings.Contains(r.URL.Path, "a~1") {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, err := Detect(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true on differential server, got %+v", res)
	}
	if res.Evidence == "" {
		t.Errorf("expected non-empty Evidence on vulnerable host")
	}
}

func TestDetectNotVulnerable_UniformResponse(t *testing.T) {
	// Server that returns 404 for everything — no tilde leakage.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, &http.Request{})
	}))
	defer srv.Close()

	res, err := Detect(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on uniform 404 server, got %+v", res)
	}
}

func TestDetect_BadURLError(t *testing.T) {
	if _, err := Detect("://not-a-url", http.DefaultClient); err == nil {
		t.Error("expected error for invalid URL")
	}
}
