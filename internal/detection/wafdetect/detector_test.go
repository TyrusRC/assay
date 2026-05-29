package wafdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_EmitsFindingsForKnownWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "abc123-IAD")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true on Cloudflare server")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	found := false
	for _, f := range res.Findings {
		if f.Type != "waf_detected" {
			t.Errorf("unexpected finding type %q", f.Type)
		}
		if f.Severity != core.SeverityInfo {
			t.Errorf("waf_detected severity should be info, got %q", f.Severity)
		}
		if f.URL != srv.URL {
			t.Errorf("finding URL = %q, want %q", f.URL, srv.URL)
		}
		if strings.Contains(f.Title, "Cloudflare") {
			found = true
		}
		if f.Tool != "wafdetect" {
			t.Errorf("Tool = %q, want wafdetect", f.Tool)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding failed Validate: %v", err)
		}
	}
	if !found {
		t.Errorf("expected a Cloudflare finding")
	}
}

func TestDetector_Detect_NoWAFEmitsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("nothing to fingerprint"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("plain nginx should not be flagged Vulnerable")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

func TestDetector_Detect_RequestError(t *testing.T) {
	d := New(http.DefaultClient)
	_, err := d.Detect(context.Background(), "http://127.0.0.1:1/no-such-server", DetectOptions{Timeout: 100 * time.Millisecond})
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestDetector_Detect_NilClient(t *testing.T) {
	d := New(nil)
	if d.client == nil {
		t.Error("New(nil) should fall back to http.DefaultClient")
	}
}

func TestMapConfidence_Buckets(t *testing.T) {
	cases := []struct {
		in   int
		want core.Confidence
	}{
		{95, core.ConfidenceHigh},
		{85, core.ConfidenceHigh},
		{70, core.ConfidenceMedium},
		{60, core.ConfidenceMedium},
		{30, core.ConfidenceLow},
	}
	for _, c := range cases {
		if got := mapConfidence(c.in); got != c.want {
			t.Errorf("mapConfidence(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
