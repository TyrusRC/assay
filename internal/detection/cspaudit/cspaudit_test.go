package cspaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_NoCSP(t *testing.T) {
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
		t.Error("missing CSP should be Info only, not Vulnerable")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 Info finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != core.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %q", res.Findings[0].Severity)
	}
}

func TestDetector_Detect_ReportOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'self'")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.ReportOnly {
		t.Error("expected ReportOnly=true")
	}
	if !res.Vulnerable {
		t.Error("report-only should be flagged Vulnerable (Medium)")
	}
}

func TestDetector_Detect_WildcardScriptSrc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src *")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Error("script-src * should be flagged")
	}
	found := false
	for _, f := range res.Findings {
		if f.Metadata["issue"] == string(IssueWildcardSource) {
			found = true
			if f.Severity != core.SeverityHigh {
				t.Errorf("wildcard severity = %q, want high", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected wildcard_source finding")
	}
}

func TestDetector_Detect_UnsafeEvalWithNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-abc123' 'unsafe-eval'")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Error("'unsafe-eval' + nonce should be flagged")
	}
	found := false
	for _, f := range res.Findings {
		if f.Metadata["issue"] == string(IssueUnsafeEval) {
			found = true
			if f.Severity != core.SeverityHigh {
				t.Errorf("unsafe-eval severity = %q, want high", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected unsafe_eval_with_nonce finding")
	}
}

func TestDetector_Detect_StrictDynamicWithBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-x' 'strict-dynamic' https:")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Metadata["issue"] == string(IssueStrictDynamicBad) {
			found = true
		}
	}
	if !found {
		t.Error("expected strict_dynamic_with_baseline finding")
	}
}

func TestDetector_Detect_NonceReuse(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		// Static nonce — the bug we're hunting.
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-STATIC123'")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Errorf("expected 2 server hits for nonce-reuse check, got %d", hits)
	}
	if !res.Vulnerable {
		t.Error("static nonce should be flagged Vulnerable")
	}
	found := false
	for _, f := range res.Findings {
		if f.Type == "csp_nonce_reuse" {
			found = true
			if f.Severity != core.SeverityHigh {
				t.Errorf("nonce-reuse severity = %q, want high", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected csp_nonce_reuse finding")
	}
}

func TestDetector_Detect_FreshNoncesPass(t *testing.T) {
	var counter int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&counter, 1)
		w.Header().Set("Content-Security-Policy",
			"script-src 'nonce-FRESH"+itoa(n)+"'")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range res.Findings {
		if f.Type == "csp_nonce_reuse" {
			t.Errorf("fresh nonces flagged as reuse: %s", f.Evidence)
		}
	}
}

func TestExtractNonce(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"script-src 'nonce-abc123'", "abc123"},
		{"script-src 'nonce-x_y-z='", "x_y-z="},
		{"script-src 'self'", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractNonce(c.in); got != c.want {
			t.Errorf("extractNonce(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseDirectives(t *testing.T) {
	policy := "default-src 'self'; script-src 'nonce-a' 'strict-dynamic'; style-src 'self' 'unsafe-inline'"
	got := parseDirectives(policy)
	if got["script-src"][0] != "'nonce-a'" {
		t.Errorf("unexpected script-src: %v", got["script-src"])
	}
	if len(got["style-src"]) != 2 {
		t.Errorf("expected 2 style-src entries, got %v", got["style-src"])
	}
}

func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string('0'+byte(n%10)) + digits
		n /= 10
	}
	return digits
}
