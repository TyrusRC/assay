package headless

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProbeServiceWorkerHijack_DetectsBroadScopeOverride verifies that a
// Service Worker registered from an attacker-controlled upload path
// (`/static/uploads/sw.js`) but allowed to claim the root scope (`/`) is
// flagged. Per the WHATWG Service Worker spec, the default allowed
// max-scope is the directory of the script URL; servers can broaden that
// only via the `Service-Worker-Allowed` response header. A server that
// returns `Service-Worker-Allowed: /` on a user-controlled upload is
// game-over: the worker now intercepts every request site-wide.
func TestProbeServiceWorkerHijack_DetectsBroadScopeOverride(t *testing.T) {
	skipIfPoolUnavailable(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>root</body></html>`))
	})
	mux.HandleFunc("/static/uploads/sw.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// Vulnerable: server allows the SW to claim broader scope than
		// its script path would normally permit.
		w.Header().Set("Service-Worker-Allowed", "/")
		_, _ = w.Write([]byte(`
			self.addEventListener('install', e => self.skipWaiting());
			self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
			self.addEventListener('message', e => {
				e.source && e.source.postMessage({scope: self.registration.scope});
			});
		`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Skipf("pool unavailable: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	page, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(page)

	if err := page.Navigate(ctx, srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	res, err := page.ProbeServiceWorkerHijack(ctx, "/static/uploads/sw.js")
	if err != nil {
		// Some headless Chromium builds disable SW on http:// origins
		// entirely; in that case the probe surfaces an error and we skip
		// to avoid environmental flakes.
		t.Skipf("ProbeServiceWorkerHijack failed (likely SW disabled): %v", err)
	}
	if !res.Registered {
		t.Skipf("SW did not register in this environment; result=%+v", res)
	}
	// The script lived under /static/uploads/, so a scope of "/" means
	// the server allowed a broader claim than the script's directory.
	if !strings.HasSuffix(res.Scope, "/") || strings.Contains(res.Scope, "/static/uploads/") {
		t.Fatalf("expected broad scope, got %q (full result=%+v)", res.Scope, res)
	}
	if !res.Vulnerable {
		t.Fatalf("expected Vulnerable=true given broad scope claim, got %+v", res)
	}
}

// TestProbeServiceWorkerHijack_NoServiceWorker confirms the negative case
// — a page with no SW reports Registered=false and Vulnerable=false.
func TestProbeServiceWorkerHijack_NoServiceWorker(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>no-sw</body></html>`))
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
	// Path that does not exist — registration will fail; the probe must
	// surface that cleanly as Registered=false, not error out.
	res, err := page.ProbeServiceWorkerHijack(ctx, "/does-not-exist.js")
	if err != nil {
		t.Fatalf("ProbeServiceWorkerHijack returned error on missing SW: %v", err)
	}
	if res.Registered {
		t.Errorf("expected Registered=false on missing SW, got %+v", res)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on missing SW, got %+v", res)
	}
}

// TestProbeCOOPCOEPEffect_FlagsMissingIsolationHeaders verifies that a
// page served with NO Cross-Origin-Opener-Policy /
// Cross-Origin-Embedder-Policy / Cross-Origin-Resource-Policy headers is
// flagged. The probe should also detect that a popup opened from the
// page exposes `window.opener` back to it — the canonical reverse-tab
// nabbing primitive that COOP prevents.
func TestProbeCOOPCOEPEffect_FlagsMissingIsolationHeaders(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Intentionally NO COOP/COEP/CORP headers.
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>weak isolation</body></html>`))
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
	res, err := page.ProbeCOOPCOEPEffect(ctx)
	if err != nil {
		t.Fatalf("ProbeCOOPCOEPEffect: %v", err)
	}
	if res.COOP != "" || res.COEP != "" || res.CORP != "" {
		t.Errorf("expected empty isolation headers, got COOP=%q COEP=%q CORP=%q",
			res.COOP, res.COEP, res.CORP)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true on weak-isolation page, got %+v", res)
	}
	if len(res.Findings) == 0 {
		t.Errorf("expected at least one finding, got none. result=%+v", res)
	}
	// Body must mention the missing COOP header somewhere.
	joined := strings.ToLower(strings.Join(res.Findings, "|"))
	if !strings.Contains(joined, "coop") && !strings.Contains(joined, "cross-origin-opener") {
		t.Errorf("findings should mention COOP, got %v", res.Findings)
	}
}

// TestProbeCOOPCOEPEffect_StrongIsolationPasses checks that a page with
// COOP: same-origin, COEP: require-corp, and CORP: same-origin is
// reported as Vulnerable=false.
func TestProbeCOOPCOEPEffect_StrongIsolationPasses(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>isolated</body></html>`))
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
	res, err := page.ProbeCOOPCOEPEffect(ctx)
	if err != nil {
		t.Fatalf("ProbeCOOPCOEPEffect: %v", err)
	}
	if res.COOP == "" || res.COEP == "" || res.CORP == "" {
		t.Errorf("expected all isolation headers populated, got %+v", res)
	}
	if res.Vulnerable {
		t.Errorf("strong isolation should not be Vulnerable, got %+v", res)
	}
}

// TestProbeTrustedTypesBypass_FlagsUnenforcedHeader verifies that a page
// WITHOUT Trusted Types enforcement (no `Content-Security-Policy:
// require-trusted-types-for 'script'`) is flagged: an innerHTML
// assignment of a string-typed payload succeeds, which means Trusted
// Types is NOT enforced — even if a report-only header is present.
func TestProbeTrustedTypesBypass_FlagsUnenforcedHeader(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Report-only (won't actually block) — should still flag as
		// "header present but not enforced".
		w.Header().Set("Content-Security-Policy-Report-Only", "require-trusted-types-for 'script'")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><div id="sink"></div></body></html>`))
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
	res, err := page.ProbeTrustedTypesBypass(ctx, "<img src=x onerror=1>")
	if err != nil {
		t.Fatalf("ProbeTrustedTypesBypass: %v", err)
	}
	if res.AssignmentBlocked {
		t.Errorf("assignment should NOT be blocked (TT not enforced), got %+v", res)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true (TT not enforced), got %+v", res)
	}
}

// TestProbeTrustedTypesBypass_EnforcedHeaderBlocks verifies that a page
// served with `Content-Security-Policy: require-trusted-types-for
// 'script'` (enforcing) throws a TypeError on a string-typed innerHTML
// assignment. The probe must report AssignmentBlocked=true and
// Vulnerable=false.
func TestProbeTrustedTypesBypass_EnforcedHeaderBlocks(t *testing.T) {
	skipIfPoolUnavailable(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"require-trusted-types-for 'script'; trusted-types skws-policy")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><div id="sink"></div></body></html>`))
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
	res, err := page.ProbeTrustedTypesBypass(ctx, "<img src=x onerror=1>")
	if err != nil {
		t.Fatalf("ProbeTrustedTypesBypass: %v", err)
	}
	if !res.HeaderPresent {
		t.Errorf("HeaderPresent should be true, got %+v", res)
	}
	// Chrome enforces TrustedTypes — string assignment must throw.
	if !res.AssignmentBlocked {
		t.Errorf("expected assignment blocked under enforced TT, got %+v", res)
	}
	if res.Vulnerable {
		t.Errorf("enforced TT should not be Vulnerable, got %+v", res)
	}
}
