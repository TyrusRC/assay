package headless

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestFetchHeaders_ReadsResponseHeaders verifies that FetchHeaders runs a
// same-origin fetch from inside the page and returns the headers from
// the live response. It's the canonical primitive that other detectors
// (CSP audit, Trusted Types audit) build on top of.
func TestFetchHeaders_ReadsResponseHeaders(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>headers test</body></html>`))
	}))
	defer srv.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Skipf("pool unavailable: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	page, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(page)

	if err := page.Navigate(ctx, srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	headers, err := page.FetchHeaders(ctx, srv.URL)
	if err != nil {
		t.Fatalf("FetchHeaders: %v", err)
	}

	csp, ok := headers["content-security-policy"]
	if !ok {
		t.Fatalf("FetchHeaders missing CSP. Got: %v", headers)
	}
	if !strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP value mangled: %q", csp)
	}
	if v, ok := headers["x-frame-options"]; !ok || v != "DENY" {
		t.Errorf("X-Frame-Options not surfaced: %q (ok=%v)", v, ok)
	}
}

// TestGetServiceWorkers_EmptyOnVanillaPage verifies the no-SW case
// returns an empty slice cleanly. We can't reliably register a real
// SW from a httptest server (the script source must be served with
// the right MIME and the registration is async), so the negative
// path is what's deterministic to test without browser flakiness.
func TestGetServiceWorkers_EmptyOnVanillaPage(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>no sw</body></html>`))
	}))
	defer srv.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Skipf("pool unavailable: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	page, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(page)

	if err := page.Navigate(ctx, srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	sws, err := page.GetServiceWorkers(ctx)
	if err != nil {
		t.Fatalf("GetServiceWorkers: %v", err)
	}
	if len(sws) != 0 {
		t.Errorf("expected 0 service workers on vanilla page, got %d (%v)", len(sws), sws)
	}
}

// TestProbePostMessageOrigin_ExposesUnvalidatedHandler dispatches a
// synthetic MessageEvent claiming an attacker origin and checks that a
// vulnerable handler (one that writes the payload to document.title
// without validating event.origin) is detected.
func TestProbePostMessageOrigin_ExposesUnvalidatedHandler(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><script>
			window.addEventListener('message', function(e) {
				// Vulnerable: trusts event.data with no origin check.
				document.title = String(e.data);
			});
		</script></body></html>`))
	}))
	defer srv.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Skipf("pool unavailable: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	page, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(page)

	if err := page.Navigate(ctx, srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	res, err := page.ProbePostMessageOrigin(ctx, "https://attacker.example", "PWNED-MARKER")
	if err != nil {
		t.Fatalf("ProbePostMessageOrigin: %v", err)
	}
	if !res.HandlerFired {
		t.Fatalf("expected vulnerable handler to fire, got none. result=%+v", res)
	}
	if !contains(res.Mutations, "title") {
		t.Errorf("expected title mutation, got %v", res.Mutations)
	}
	if res.AttackerOrigin != "https://attacker.example" {
		t.Errorf("AttackerOrigin echoed wrong: %q", res.AttackerOrigin)
	}
}

// TestProbePostMessageOrigin_GuardedHandlerDoesNotFire confirms that a
// listener that validates event.origin against an allowlist correctly
// produces no mutations under our synthetic dispatch. Negative cases
// matter — a probe that flags every page is useless.
func TestProbePostMessageOrigin_GuardedHandlerDoesNotFire(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><script>
			window.addEventListener('message', function(e) {
				if (e.origin !== 'https://trusted.example') return;
				document.title = String(e.data);
			});
		</script></body></html>`))
	}))
	defer srv.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Skipf("pool unavailable: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	page, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(page)

	if err := page.Navigate(ctx, srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	res, err := page.ProbePostMessageOrigin(ctx, "https://attacker.example", "PWNED-MARKER")
	if err != nil {
		t.Fatalf("ProbePostMessageOrigin: %v", err)
	}
	if res.HandlerFired {
		t.Fatalf("guarded handler fired against attacker origin. result=%+v", res)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
