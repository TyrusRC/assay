package nodejsinject

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_NoParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on no-param URL")
	}
}

func TestDetector_Detect_FlagsNodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "require") || strings.Contains(q, "child_process") || strings.Contains(q, "constructor") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("SyntaxError: Unexpected token in JSON\n    at node:vm.runInContext"))
			return
		}
		_, _ = w.Write([]byte("normal"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	opts := DefaultOptions()
	opts.ConfirmedNodeOnly = false
	res, err := d.Detect(context.Background(), srv.URL+"/?q=hello", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on Node error reflection")
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.Type, "nodejs_ssji_") {
			t.Errorf("unexpected type %q", f.Type)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
	}
	if !res.NodeDetected {
		t.Error("expected NodeDetected=true")
	}
}

func TestDetector_Detect_FlagsTimeBlind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		q := r.URL.Query().Get("q")
		// Simulate child_process.execSync('sleep 5') landing.
		if strings.Contains(q, "sleep") {
			time.Sleep(500 * time.Millisecond)
		}
		_, _ = w.Write([]byte("response"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	opts := DefaultOptions()
	opts.TimeBlindThreshold = 300 * time.Millisecond
	opts.ConfirmedNodeOnly = false
	res, err := d.Detect(context.Background(), srv.URL+"/?q=hello", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// At least one TypeBlind 'sleep' payload should trigger the time delta.
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true on time-blind sleep")
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "time delta") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected at least one finding with time-delta evidence, got %+v", res.Findings)
	}
}

func TestIsNodeResponse_HeaderTells(t *testing.T) {
	cases := []struct {
		header http.Header
		body   string
		want   bool
	}{
		{http.Header{"X-Powered-By": {"Express"}}, "", true},
		{http.Header{"X-Powered-By": {"Next.js"}}, "", true},
		{http.Header{"X-Powered-By": {"PHP/7.4"}}, "", false},
		{http.Header{}, "ReferenceError: x is not defined", true},
		{http.Header{}, "<html>nothing</html>", false},
	}
	for i, c := range cases {
		if got := isNodeResponse(&http.Response{Header: c.header}, c.body); got != c.want {
			t.Errorf("case %d: isNodeResponse() = %v, want %v", i, got, c.want)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   Impact
		want core.Severity
	}{
		{ImpactRCE, core.SeverityCritical},
		{ImpactSandboxEsc, core.SeverityHigh},
		{ImpactInfoLeak, core.SeverityMedium},
		{ImpactBlind, core.SeverityMedium},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
