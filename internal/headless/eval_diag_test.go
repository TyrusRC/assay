package headless

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// skipIfPoolUnavailable mirrors storageinj's helper: skips only when
// NewPool actually fails. Rod auto-downloads Chromium on first run, so
// this is more permissive than findChrome().
func skipIfPoolUnavailable(t *testing.T) {
	t.Helper()
	pool, err := NewPool(DefaultPoolConfig())
	if errors.Is(err, ErrBrowserUnavailable) {
		t.Skip("Skipping: browser pool unavailable")
	}
	if pool != nil {
		pool.Close()
	}
}

// TestEvalJS_StringRoundTrip is a diagnostic for the rod swap: verifies
// EvalJS returns plain Go strings for string-typed JS results, not
// JSON-quoted ("foo") strings. The chromedp version behaved this way;
// any regression breaks getStorageData and every detector that compares
// against a literal sentinel (HIT, POLLUTED).
func TestEvalJS_StringRoundTrip(t *testing.T) {
	skipIfPoolUnavailable(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><script>
			localStorage.setItem("auth_token", "secret123");
			localStorage.setItem("theme", "dark");
		</script></head><body></body></html>`))
	}))
	defer ts.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(page)

	if err := page.Navigate(context.Background(), ts.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	// Plain string return
	got, err := page.EvalJS(context.Background(), `"hello"`)
	if err != nil {
		t.Fatalf("EvalJS string: %v", err)
	}
	if got != "hello" {
		t.Errorf(`EvalJS("\"hello\"") = %q, want "hello"`, got)
	}

	// JSON.stringify return — what GetLocalStorage relies on
	got, err = page.EvalJS(context.Background(), `JSON.stringify({"k":"v"})`)
	if err != nil {
		t.Fatalf("EvalJS json: %v", err)
	}
	if got != `{"k":"v"}` {
		t.Errorf("EvalJS(JSON.stringify) = %q, want %q", got, `{"k":"v"}`)
	}

	// GetLocalStorage round-trip
	store, err := page.GetLocalStorage(context.Background())
	if err != nil {
		t.Fatalf("GetLocalStorage: %v", err)
	}
	if store["auth_token"] != "secret123" {
		t.Errorf("localStorage[auth_token] = %q, want secret123 (full map: %v)", store["auth_token"], store)
	}
}
