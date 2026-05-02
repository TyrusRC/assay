package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// fastDetector returns a ratelimit detector with tight timings so tests
// don't sleep for seconds.
func fastDetector(client *skwshttp.Client) *Detector {
	d := New(client)
	d.burstSize = 6
	d.burstWindow = 60 * time.Millisecond
	return d
}

func TestDetect_FlagsUnlimitedEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	det := fastDetector(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/login")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding on unrate-limited /login, got %d", len(res.Findings))
	}
	// /login is in the sensitive list → severity High.
	if res.Findings[0].Severity != core.SeverityHigh {
		t.Errorf("expected High severity on /login, got %v", res.Findings[0].Severity)
	}
}

func TestDetect_Respects429(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		if n > 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := fastDetector(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/login")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when 429 is returned, got %d", len(res.Findings))
	}
}

func TestDetect_RespectsRetryAfterHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "99")
		w.Header().Set("X-RateLimit-Limit", "100")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := fastDetector(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when X-RateLimit-* headers are present, got %d", len(res.Findings))
	}
}

func TestDetect_NonSensitivePathIsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	det := fastDetector(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/products")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != core.SeverityMedium {
		t.Errorf("expected Medium on non-sensitive path, got %v", res.Findings[0].Severity)
	}
}

func TestDetect_SkipsOnPartialFailure(t *testing.T) {
	// Server returns 500 for some requests — we cannot make a clean
	// "no rate limit" claim.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		if n%2 == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := fastDetector(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on flaky upstream, got %d", len(res.Findings))
	}
}

func TestDetect_NilClientNoOp(t *testing.T) {
	det := New(nil)
	res, err := det.Detect(context.Background(), "http://x.test/")
	if err != nil {
		t.Fatalf("nil-client should not error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("nil-client should produce 0 findings, got %d", len(res.Findings))
	}
}
