package storageinj

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
)

// skipIfNoBrowser skips the test if Chrome is not available.
func skipIfNoBrowser(t *testing.T) {
	t.Helper()
	config := headless.DefaultPoolConfig()
	_, err := headless.NewPool(config)
	if errors.Is(err, headless.ErrBrowserUnavailable) {
		t.Skip("Skipping: Chrome/Chromium not available")
	}
}

func TestNew(t *testing.T) {
	d := New(nil)
	if d == nil {
		t.Fatal("New(nil) returned nil")
	}
}

func TestDetector_NilPool(t *testing.T) {
	d := New(nil)
	result, err := d.Detect(context.Background(), "http://example.com", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if result.Vulnerable {
		t.Error("Detect() with nil pool should not be vulnerable")
	}
	if len(result.Findings) != 0 {
		t.Errorf("Detect() with nil pool should have 0 findings, got %d", len(result.Findings))
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
	if !opts.CheckSensitive {
		t.Error("CheckSensitive should be true by default")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	d := New(nil).WithVerbose(true)
	if !d.verbose {
		t.Error("WithVerbose(true) should set verbose")
	}
}

func TestDetector_SensitiveDataDetection(t *testing.T) {
	skipIfNoBrowser(t)

	// Create a test server that sets sensitive storage keys via JS
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Test</title></head><body>
			<script>
				localStorage.setItem("auth_token", "secret123");
				localStorage.setItem("jwt_data", "eyJhbGciOiJIUzI1NiJ9");
				localStorage.setItem("theme", "dark");
			</script>
		</body></html>`))
	}))
	defer ts.Close()

	pool, err := headless.NewPool(headless.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	d := New(pool)
	opts := DefaultOptions()
	opts.Timeout = 15 * time.Second
	opts.CheckSensitive = true

	result, err := d.Detect(context.Background(), ts.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should find sensitive data in localStorage (auth_token and jwt_data)
	if !result.Vulnerable {
		t.Error("Detect() should find sensitive data in storage")
	}

	foundToken := false
	foundJWT := false
	for _, f := range result.Findings {
		if f.Parameter == "auth_token" {
			foundToken = true
		}
		if f.Parameter == "jwt_data" {
			foundJWT = true
		}
	}
	if !foundToken {
		t.Error("should detect auth_token as sensitive")
	}
	if !foundJWT {
		t.Error("should detect jwt_data as sensitive")
	}
}

func TestDetector_NoVulnerability(t *testing.T) {
	skipIfNoBrowser(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Safe</title></head><body><p>No storage used</p></body></html>`))
	}))
	defer ts.Close()

	pool, err := headless.NewPool(headless.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	d := New(pool)
	opts := DefaultOptions()
	opts.Timeout = 15 * time.Second

	result, err := d.Detect(context.Background(), ts.URL, opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.Vulnerable {
		t.Errorf("Detect() should not be vulnerable on safe page, got %d findings", len(result.Findings))
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	skipIfNoBrowser(t)

	pool, err := headless.NewPool(headless.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	defer pool.Close()

	d := New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := d.Detect(ctx, "http://example.com", DefaultOptions())
	// Should handle cancellation gracefully
	if err != nil {
		t.Logf("Detect() with cancelled context error: %v (acceptable)", err)
	}
	if result == nil {
		t.Fatal("Detect() returned nil result")
	}
}
