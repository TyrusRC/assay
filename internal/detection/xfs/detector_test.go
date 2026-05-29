package xfs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_FlagsUnprotectedPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>no protection here</body></html>"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true on unprotected page")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "clickjacking_exposure" {
		t.Errorf("unexpected type %q", f.Type)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %q", f.Severity)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("finding failed Validate: %v", err)
	}
}

func TestDetector_Detect_ProtectedNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Error("XFO=DENY → expected Vulnerable=false")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings on protected page, got %d", len(res.Findings))
	}
}

func TestDetector_Detect_RequestError(t *testing.T) {
	d := New(http.DefaultClient)
	_, err := d.Detect(context.Background(), "http://127.0.0.1:1/missing", DetectOptions{Timeout: 200000000})
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestMapSeverity_Buckets(t *testing.T) {
	cases := []struct {
		in   Severity
		want core.Severity
	}{
		{SeverityHigh, core.SeverityHigh},
		{SeverityMedium, core.SeverityMedium},
		{SeverityLow, core.SeverityLow},
		{SeverityInfo, core.SeverityInfo},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
