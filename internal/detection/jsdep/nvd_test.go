package jsdep

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewNVDClient_TierPicksInterval confirms NewNVDClient picks the
// public-tier 6s gap when no key is provided, and the authenticated
// 600ms gap when a key is set. Wrong defaults would either rate-limit
// the user (slow scans) or get them throttled by NVD.
func TestNewNVDClient_TierPicksInterval(t *testing.T) {
	anon := NewNVDClient("")
	if anon.HasAPIKey() {
		t.Error("anon client should not report HasAPIKey()=true")
	}
	if anon.MinInterval != 6*time.Second {
		t.Errorf("anon MinInterval = %v, want 6s", anon.MinInterval)
	}
	auth := NewNVDClient("test-key")
	if !auth.HasAPIKey() {
		t.Error("authenticated client should report HasAPIKey()=true")
	}
	if auth.MinInterval != 600*time.Millisecond {
		t.Errorf("auth MinInterval = %v, want 600ms", auth.MinInterval)
	}
}

// TestNVDClient_FindByCPE_SetsAPIKeyHeader confirms a non-empty APIKey
// gets forwarded as the apiKey header, which is how NVD identifies the
// authenticated tier. Forgetting this would silently downgrade users.
func TestNVDClient_FindByCPE_SetsAPIKeyHeader(t *testing.T) {
	got := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities": []}`))
	}))
	defer srv.Close()

	c := &NVDClient{
		Endpoint:    srv.URL,
		APIKey:      "secret-key",
		HTTPClient:  srv.Client(),
		MinInterval: 0,
	}
	if _, err := c.FindByCPE(context.Background(), "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"); err != nil {
		t.Fatalf("FindByCPE error: %v", err)
	}
	if got != "secret-key" {
		t.Errorf("apiKey header = %q, want %q", got, "secret-key")
	}
}

// TestNVDClient_Throttle_PacesRequests confirms back-to-back FindByCPE
// calls respect MinInterval. We use a small interval (40ms) and three
// calls; total elapsed must exceed 2 × interval.
func TestNVDClient_Throttle_PacesRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities": []}`))
	}))
	defer srv.Close()

	c := &NVDClient{
		Endpoint:    srv.URL,
		HTTPClient:  srv.Client(),
		MinInterval: 40 * time.Millisecond,
	}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := c.FindByCPE(context.Background(), "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"); err != nil {
			t.Fatalf("FindByCPE error: %v", err)
		}
	}
	elapsed := time.Since(start)
	// 3 calls at 40ms minimum gap → at least 80ms (after the first).
	if elapsed < 80*time.Millisecond {
		t.Errorf("3 paced requests took %v, expected ≥ 80ms", elapsed)
	}
}

// TestNVDClient_Throttle_RespectsContextCancel ensures a cancelled
// context aborts the throttle wait promptly rather than blocking for
// the full MinInterval.
func TestNVDClient_Throttle_RespectsContextCancel(t *testing.T) {
	c := &NVDClient{MinInterval: 5 * time.Second}
	c.lastReq = time.Now() // pretend we just made a request

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	start := time.Now()
	err := c.throttle(ctx)
	if err == nil {
		t.Fatal("throttle should return an error when ctx is cancelled")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("throttle took too long under cancellation: %v", time.Since(start))
	}
}
