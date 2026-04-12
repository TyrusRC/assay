package headless

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestServer creates an httptest server for browser tests that need a proper origin.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Test</title></head><body>Test Page</body></html>`))
	}))
}

// skipIfNoBrowser skips the test if Chrome is not available.
func skipIfNoBrowser(t *testing.T) {
	t.Helper()
	if findChrome() == "" {
		t.Skip("Skipping: Chrome/Chromium not available")
	}
}

func TestErrBrowserUnavailable(t *testing.T) {
	if !errors.Is(ErrBrowserUnavailable, ErrBrowserUnavailable) {
		t.Error("ErrBrowserUnavailable should be a sentinel error")
	}
}

func TestDefaultPoolConfig(t *testing.T) {
	config := DefaultPoolConfig()

	if config.MaxBrowsers != 3 {
		t.Errorf("MaxBrowsers = %d, want 3", config.MaxBrowsers)
	}
	if config.NavigateTimeout != 15*time.Second {
		t.Errorf("NavigateTimeout = %v, want 15s", config.NavigateTimeout)
	}
	if !config.Headless {
		t.Error("Headless should be true by default")
	}
}

func TestNewPool_NoBrowser(t *testing.T) {
	config := DefaultPoolConfig()
	config.ExecPath = "/nonexistent/chrome"

	_, err := NewPool(config)
	if !errors.Is(err, ErrBrowserUnavailable) {
		t.Errorf("NewPool() error = %v, want ErrBrowserUnavailable", err)
	}
}

func TestNewPool_WithBrowser(t *testing.T) {
	skipIfNoBrowser(t)

	config := DefaultPoolConfig()
	pool, err := NewPool(config)
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	if pool == nil {
		t.Fatal("NewPool() returned nil")
	}
}

func TestPool_AcquireRelease(t *testing.T) {
	skipIfNoBrowser(t)

	config := DefaultPoolConfig()
	config.MaxBrowsers = 2
	pool, err := NewPool(config)
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Acquire a page
	page, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if page == nil {
		t.Fatal("Acquire() returned nil page")
	}

	// Release it back
	pool.Release(page)

	// Acquire again (should get the cached page)
	page2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if page2 == nil {
		t.Fatal("second Acquire() returned nil page")
	}
	pool.Release(page2)
}

func TestPool_Close(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}

	pool.Close()
	// Double close should not panic
	pool.Close()

	// Acquire after close should fail
	_, err = pool.Acquire(context.Background())
	if err == nil {
		t.Error("Acquire() after Close() should fail")
	}
}

func TestPage_Navigate(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer pool.Release(page)

	// Navigate to about:blank (always available)
	if err := page.Navigate(context.Background(), "about:blank"); err != nil {
		t.Fatalf("Navigate() error = %v", err)
	}
}

func TestPage_EvalJS(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer pool.Release(page)

	ctx := context.Background()
	if err := page.Navigate(ctx, "about:blank"); err != nil {
		t.Fatalf("Navigate() error = %v", err)
	}

	result, err := page.EvalJS(ctx, `"hello" + " " + "world"`)
	if err != nil {
		t.Fatalf("EvalJS() error = %v", err)
	}
	if result != "hello world" {
		t.Errorf("EvalJS() = %q, want %q", result, "hello world")
	}
}

func TestPage_LocalStorage(t *testing.T) {
	skipIfNoBrowser(t)

	// Start httptest server so localStorage has a proper origin
	ts := newTestServer(t)
	defer ts.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer pool.Release(page)

	ctx := context.Background()
	if err := page.Navigate(ctx, ts.URL); err != nil {
		t.Fatalf("Navigate() error = %v", err)
	}

	// Set and get localStorage
	if err := page.SetLocalStorage(ctx, "testKey", "testValue"); err != nil {
		t.Fatalf("SetLocalStorage() error = %v", err)
	}

	data, err := page.GetLocalStorage(ctx)
	if err != nil {
		t.Fatalf("GetLocalStorage() error = %v", err)
	}

	if data["testKey"] != "testValue" {
		t.Errorf("localStorage[testKey] = %q, want %q", data["testKey"], "testValue")
	}
}

func TestPage_SessionStorage(t *testing.T) {
	skipIfNoBrowser(t)

	ts := newTestServer(t)
	defer ts.Close()

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer pool.Release(page)

	ctx := context.Background()
	if err := page.Navigate(ctx, ts.URL); err != nil {
		t.Fatalf("Navigate() error = %v", err)
	}

	if err := page.SetSessionStorage(ctx, "sess_key", "sess_value"); err != nil {
		t.Fatalf("SetSessionStorage() error = %v", err)
	}

	data, err := page.GetSessionStorage(ctx)
	if err != nil {
		t.Fatalf("GetSessionStorage() error = %v", err)
	}

	if data["sess_key"] != "sess_value" {
		t.Errorf("sessionStorage[sess_key] = %q, want %q", data["sess_key"], "sess_value")
	}
}

func TestPage_WindowName(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer pool.Release(page)

	ctx := context.Background()
	if err := page.Navigate(ctx, "about:blank"); err != nil {
		t.Fatalf("Navigate() error = %v", err)
	}

	if err := page.SetWindowName(ctx, "test_window"); err != nil {
		t.Fatalf("SetWindowName() error = %v", err)
	}

	name, err := page.GetWindowName(ctx)
	if err != nil {
		t.Fatalf("GetWindowName() error = %v", err)
	}
	if name != "test_window" {
		t.Errorf("GetWindowName() = %q, want %q", name, "test_window")
	}
}

func TestPage_GetDOM(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer pool.Release(page)

	ctx := context.Background()
	if err := page.Navigate(ctx, "about:blank"); err != nil {
		t.Fatalf("Navigate() error = %v", err)
	}

	html, err := page.GetDOM(ctx)
	if err != nil {
		t.Fatalf("GetDOM() error = %v", err)
	}
	if html == "" {
		t.Error("GetDOM() returned empty string")
	}
}

func TestPage_Reset(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer pool.Release(page)

	ctx := context.Background()
	if err := page.Navigate(ctx, "about:blank"); err != nil {
		t.Fatalf("Navigate() error = %v", err)
	}

	if err := page.Reset(ctx); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
}

func TestPool_ReleaseNilPage(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := NewPool(DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	// Should not panic
	pool.Release(nil)
}

func TestSplitCookieString(t *testing.T) {
	tests := []struct {
		input    string
		expected [][2]string
	}{
		{
			input:    "key1=val1; key2=val2",
			expected: [][2]string{{"key1", "val1"}, {"key2", "val2"}},
		},
		{
			input:    "single=value",
			expected: [][2]string{{"single", "value"}},
		},
		{
			input:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		pairs := splitCookieString(tt.input)
		if len(pairs) != len(tt.expected) {
			t.Errorf("splitCookieString(%q) count = %d, want %d", tt.input, len(pairs), len(tt.expected))
			continue
		}
		for i, pair := range pairs {
			if pair != tt.expected[i] {
				t.Errorf("splitCookieString(%q)[%d] = %v, want %v", tt.input, i, pair, tt.expected[i])
			}
		}
	}
}
