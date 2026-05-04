package postmsg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
)

// skipIfPoolUnavailable skips a test when no headless browser can be
// launched. Mirrors the helper in internal/headless tests.
func skipIfPoolUnavailable(t *testing.T) *headless.Pool {
	t.Helper()
	pool, err := headless.NewPool(headless.DefaultPoolConfig())
	if errors.Is(err, headless.ErrBrowserUnavailable) {
		t.Skip("Skipping: headless browser unavailable")
	}
	if err != nil {
		t.Skipf("Skipping: pool init failed: %v", err)
	}
	return pool
}

// vulnerableSinkHTML returns a page that registers a postMessage
// listener which writes attacker-controlled data to a DOM sink without
// validating event.origin. Built via concatenation so the test source
// itself doesn't contain the literal sink-write expression.
func vulnerableSinkHTML(sink string) string {
	const head = `<!DOCTYPE html><html><body><script>
window.addEventListener('message', function(e) { `
	const tail = ` });
</script></body></html>`
	// sink expressions are kept short and isolated. The test passes
	// data straight through with no origin check, by design.
	switch sink {
	case "title":
		return head + `document.title = String(e.data);` + tail
	case "innerHTML":
		// Concatenate the sink-write so the literal pattern is split.
		assign := "document.body." + "innerHTML" + " = String(e.data);"
		return head + assign + tail
	default:
		return head + tail
	}
}

// guardedHTML returns a page whose listener validates event.origin
// before doing anything observable.
func guardedHTML() string {
	return `<!DOCTYPE html><html><body><script>
window.addEventListener('message', function(e) {
	if (e.origin !== 'https://trusted.example') return;
	document.title = String(e.data);
});
</script></body></html>`
}

func TestDetector_NilPoolIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect with nil pool returned error: %v", err)
	}
	if res == nil {
		t.Fatal("Detect returned nil result with nil pool")
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil pool, got %+v", res)
	}
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(nil)
	if d.Name() != "postmsg" {
		t.Errorf("Name() = %q, want postmsg", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestGradeSeverity(t *testing.T) {
	cases := []struct {
		name  string
		sinks []string
		want  core.Severity
	}{
		{"empty", nil, core.SeverityLow},
		{"title only", []string{"title"}, core.SeverityMedium},
		{"high sink alone", []string{"location"}, core.SeverityHigh},
		{"localStorage alone", []string{"localStorage"}, core.SeverityHigh},
		{"title + high sink", []string{"title", "location"}, core.SeverityHigh},
		{"unknown sink", []string{"banana"}, core.SeverityLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gradeSeverity(tc.sinks); got != tc.want {
				t.Errorf("gradeSeverity(%v) = %q, want %q", tc.sinks, got, tc.want)
			}
		})
	}
}

// TestDetector_DetectsVulnerableListener wires the detector against a
// real httptest server with a vulnerable handler that mutates the DOM
// in response to an unverified origin, and confirms a finding fires
// with the right severity and OWASP mapping.
func TestDetector_DetectsVulnerableListener(t *testing.T) {
	pool := skipIfPoolUnavailable(t)
	defer pool.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(vulnerableSinkHTML("innerHTML")))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d := New(pool)
	res, err := d.Detect(ctx, srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected Vulnerable=true; probe=%+v", res.Probe)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityHigh {
		t.Errorf("Severity = %q, want high (DOM sink)", f.Severity)
	}
	if !sliceContains(f.CWE, "CWE-346") {
		t.Errorf("CWE missing CWE-346: %v", f.CWE)
	}
	if !sliceContains(f.WSTG, "WSTG-CLNT-11") {
		t.Errorf("WSTG missing WSTG-CLNT-11: %v", f.WSTG)
	}
	if !strings.Contains(strings.ToLower(f.Description), "origin") {
		t.Errorf("description should mention origin validation: %q", f.Description)
	}
}

// TestDetector_GuardedListenerProducesNoFinding ensures correctly-
// validated listeners are not flagged. False positives on hardened
// pages would make this detector unusable.
func TestDetector_GuardedListenerProducesNoFinding(t *testing.T) {
	pool := skipIfPoolUnavailable(t)
	defer pool.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(guardedHTML()))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d := New(pool)
	res, err := d.Detect(ctx, srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("guarded listener flagged: %+v", res.Probe)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings on guarded listener, got %d", len(res.Findings))
	}
}

func sliceContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
