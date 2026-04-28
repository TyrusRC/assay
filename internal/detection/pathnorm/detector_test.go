package pathnorm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector.Name() != "pathnorm" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "pathnorm")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads <= 0 {
		t.Error("DefaultOptions() MaxPayloads should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()

	detector := New(client).WithVerbose(true)
	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}

	detector2 := New(client).WithVerbose(false)
	if detector2.verbose {
		t.Error("WithVerbose(false) should leave verbose as false")
	}
}

func TestDetector_Detect_BypassFound(t *testing.T) {
	// Server that returns 403 for /admin but 200 for bypass paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden"))
			return
		}

		// Any other path (bypass attempts) returns 200
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Admin Panel Content"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	// Verify finding properties
	if result.Vulnerable {
		finding := result.Findings[0]
		if finding.Tool != "pathnorm-detector" {
			t.Errorf("Tool = %q, want %q", finding.Tool, "pathnorm-detector")
		}
		if len(finding.WSTG) == 0 {
			t.Error("Expected WSTG mappings")
		}
		if len(finding.Top10) == 0 {
			t.Error("Expected Top10 mappings")
		}
		if len(finding.CWE) == 0 {
			t.Error("Expected CWE mappings")
		}
		if finding.Remediation == "" {
			t.Error("Expected non-empty Remediation")
		}
	}
}

func TestDetector_Detect_NoBypass(t *testing.T) {
	// Server that returns 403 for all paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when all paths return 403")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result.Findings))
	}
}

func TestDetector_Detect_OriginalReturns200(t *testing.T) {
	// Server that returns 200 for everything - no bypass needed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when original returns 200")
	}

	// Should not even test payloads since original is 200
	if result.TestedPayloads != 0 {
		t.Errorf("Expected 0 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := detector.Detect(ctx, server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	// Either the original request fails or context cancellation is returned
	if err == nil {
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
	}
}

func TestDetector_Detect_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), serverURL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 5,
	})

	if err == nil {
		t.Error("Expected error when server is down")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "failed to get original response") {
		t.Errorf("Expected original response error, got: %v", err)
	}
}

func TestDetector_Detect_PayloadLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 2,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads > 2 {
		t.Errorf("Expected at most 2 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_401Unauthorized(t *testing.T) {
	// Server that returns 401 for /admin but 200 for bypass paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("401 Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Admin Panel"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "admin", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected for 401 bypass")
	}
}

func TestDetector_Detect_EmptyParam(t *testing.T) {
	// When param is empty, the detector should use the path from the URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Bypassed"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/admin", "", "GET", DetectOptions{
		MaxPayloads: 10,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected with empty param")
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	payload := bypassPayload{
		Template:    "..;/%s",
		Description: "Semicolon path traversal",
	}

	originalResp := &internalhttp.Response{StatusCode: 403, Body: "Forbidden"}
	bypassResp := &internalhttp.Response{StatusCode: 200, Body: "Admin Panel"}

	finding := detector.createFinding("http://example.com/admin", "http://example.com/..;/admin", payload, originalResp, bypassResp)

	if finding == nil {
		t.Fatal("createFinding() returned nil")
	}
	if finding.Tool != "pathnorm-detector" {
		t.Errorf("Tool = %q, want %q", finding.Tool, "pathnorm-detector")
	}
	if finding.URL != "http://example.com/admin" {
		t.Errorf("URL = %q, want %q", finding.URL, "http://example.com/admin")
	}
	if finding.Description == "" {
		t.Error("Expected non-empty Description")
	}
	if finding.Evidence == "" {
		t.Error("Expected non-empty Evidence")
	}
	if finding.Remediation == "" {
		t.Error("Expected non-empty Remediation")
	}
	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-ATHZ-02" {
		t.Error("Expected WSTG-ATHZ-02 mapping")
	}
	if len(finding.Top10) == 0 || finding.Top10[0] != "A01:2025" {
		t.Error("Expected A01:2025 mapping")
	}
	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-22" {
		t.Error("Expected CWE-22 mapping")
	}
}

// TestDetect_FPGuard_SameBodyAtStatus200: an SPA that returns the SAME
// forbidden body but at status 200 (a common "internal redirect to login"
// pattern) must not produce findings. Without this guard, every such app
// trips on every payload — pure noise.
func TestDetect_FPGuard_SameBodyAtStatus200(t *testing.T) {
	const denied = `<!doctype html><html><body>
		<h1>Access denied</h1><p>Please <a href="/login">log in</a>.</p>
		</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(denied))
			return
		}
		// SPA pattern: same body, status 200
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(denied))
	}))
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.Detect(context.Background(), srv.URL+"/admin", "admin", "GET", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("SPA-style soft-403 must NOT trip the detector; got %+v", res.Findings)
	}
}

// TestDetect_CriticalGrading_OnAdminMarkers: a bypass whose body contains
// multiple admin-dashboard markers should be promoted to Critical.
func TestDetect_CriticalGrading_OnAdminMarkers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden"))
			return
		}
		// Bypass response: realistic admin dashboard body with several markers
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>
			<h1>Admin Panel</h1>
			<a href="/logout">Logout</a>
			<section>Manage Users</section>
			<section>Settings</section>
			<table id="audit-log"><caption>Audit Log</caption></table>
			</body></html>`))
	}))
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.Detect(context.Background(), srv.URL+"/admin", "admin", "GET", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected at least one finding")
	}
	hasCritical := false
	for _, f := range res.Findings {
		if f.Severity == core.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Errorf("expected at least one Critical finding when admin markers present; got %+v", res.Findings)
	}
}

// TestDefaultPayloads_Coverage: pin the expanded payload set so a future
// contributor can't accidentally drop it back to the original 6.
func TestDefaultPayloads_Coverage(t *testing.T) {
	p := defaultPayloads()
	if len(p) < 20 {
		t.Errorf("defaultPayloads should have at least 20 entries; got %d", len(p))
	}
	families := map[string]bool{}
	for _, b := range p {
		switch {
		case strings.Contains(b.Description, "Semicolon"):
			families["semicolon"] = true
		case strings.Contains(b.Description, "Encoded") || strings.Contains(b.Description, "encoded"):
			families["encoded"] = true
		case strings.Contains(b.Description, "extension"):
			families["extension"] = true
		case strings.Contains(b.Description, "Trailing") || strings.Contains(b.Description, "trailing"):
			families["trailing"] = true
		case strings.Contains(b.Description, "traversal") || strings.Contains(b.Description, "Traversal"):
			families["traversal"] = true
		}
	}
	for _, want := range []string{"semicolon", "encoded", "extension", "trailing", "traversal"} {
		if !families[want] {
			t.Errorf("missing payload family %q in defaultPayloads", want)
		}
	}
}

// --- analyzer-level unit tests ---

func TestBodyShapeDiverged(t *testing.T) {
	cases := []struct {
		name           string
		canonical      string
		bypass         string
		wantDivergence bool
	}{
		{"identical", "abc", "abc", false},
		{"both empty", "", "", false},
		{"one empty", "", "abc", true},
		{"length wildly different", strings.Repeat("a", 100), strings.Repeat("a", 200), true},
		{"high token overlap",
			"the quick brown fox jumps over the lazy dog by the river bank watching",
			"the quick brown fox jumps over the lazy dog by the river bank watching today", false},
		{"low token overlap, similar length",
			"login required please authenticate",
			"admin dashboard manage users settings", true},
		{"tiny bodies", "no", "ok", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bodyShapeDiverged(tc.canonical, tc.bypass); got != tc.wantDivergence {
				t.Errorf("bodyShapeDiverged: got %v, want %v", got, tc.wantDivergence)
			}
		})
	}
}

func TestHasAdminMarkers(t *testing.T) {
	cases := map[string]bool{
		"<h1>Admin Panel</h1><a href=/logout>Logout</a>":          true,
		"<h1>Dashboard</h1><a>Settings</a>":                       true,
		"You are signed in as alice. Logout?":                     true,
		"Admin":                                                   false, // single weak hit
		"Welcome to our marketing site":                           false,
		"<title>404 not found</title><body>nothing here</body>":   false,
		"audit log shows: action=delete user, role: admin":        true,
	}
	for body, want := range cases {
		t.Run(body[:min(len(body), 30)], func(t *testing.T) {
			if got := hasAdminMarkers(body); got != want {
				t.Errorf("hasAdminMarkers(%q) = %v, want %v", body, got, want)
			}
		})
	}
}
