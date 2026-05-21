package xsleaks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func newClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second)
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(newClient())
	if d.Name() != "xsleaks" {
		t.Errorf("Name() = %q, want xsleaks", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NilClientIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect with nil client returned error: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil client, got %+v", res)
	}
}

// TestPrimitives_AllHeadersPresent_NoPrimitives confirms a fully isolated
// response yields no xsleak primitives and therefore no finding.
func TestPrimitives_AllHeadersPresent_NoPrimitives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Set-Cookie", "session=abc; Path=/; HttpOnly; Secure; SameSite=Strict")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>account</body></html>`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected hardened response to be non-vulnerable; primitives=%v", res.Primitives)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

// TestPrimitives_ExposedAuthEndpoint_HighSeverity covers the worst-case
// real-world combination: an auth-sensitive path is framable, lacks
// Cross-Origin-Opener-Policy, and ships SameSite=Lax cookies (the
// default), giving an attacker both popup and iframe primitives plus
// the user's auth context.
func TestPrimitives_ExposedAuthEndpoint_HighSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc; Path=/; SameSite=Lax")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>your account</body></html>`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable; primitives=%v", res.Primitives)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if !contains(f.CWE, "CWE-200") {
		t.Errorf("CWE missing CWE-200: %v", f.CWE)
	}
	if !contains(f.WSTG, "WSTG-CLNT-13") {
		t.Errorf("WSTG missing WSTG-CLNT-13: %v", f.WSTG)
	}
	if !contains(res.Primitives, "framable") {
		t.Errorf("primitives missing 'framable': %v", res.Primitives)
	}
	if !contains(res.Primitives, "no_coop") {
		t.Errorf("primitives missing 'no_coop': %v", res.Primitives)
	}
	if !contains(res.Primitives, "samesite_cross_site") {
		t.Errorf("primitives missing 'samesite_cross_site': %v", res.Primitives)
	}
	if !contains(res.Primitives, "auth_sensitive_path") {
		t.Errorf("primitives missing 'auth_sensitive_path': %v", res.Primitives)
	}
	if !strings.Contains(strings.ToLower(f.Description), "cross-site leak") {
		t.Errorf("description should mention cross-site leak: %q", f.Description)
	}
}

// TestPrimitives_PublicFramableEndpoint_MediumSeverity covers a framable
// page with no isolation headers but no auth-sensitive path and Strict
// cookies. Less exploitable, but still a defense-in-depth gap worth a
// medium finding (frame-count primitive available).
func TestPrimitives_PublicFramableEndpoint_MediumSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc; SameSite=Strict")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>public</body></html>`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/search?q=foo", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected medium-severity finding; primitives=%v", res.Primitives)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != core.SeverityMedium {
		t.Errorf("Severity = %q, want medium", res.Findings[0].Severity)
	}
}

// TestPrimitives_JSONResponseNoCORP_MediumSeverity covers the resource-
// isolation gap: a JSON endpoint with no CORP and cookies that ship on
// cross-site GETs is loadable cross-origin and timeable/size-leakable.
func TestPrimitives_JSONResponseNoCORP_MediumSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc; SameSite=None; Secure")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":"alice"}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/api/user", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected resource-isolation finding; primitives=%v", res.Primitives)
	}
	if !contains(res.Primitives, "no_corp") {
		t.Errorf("primitives missing 'no_corp': %v", res.Primitives)
	}
	if !contains(res.Primitives, "json_response") {
		t.Errorf("primitives missing 'json_response': %v", res.Primitives)
	}
}

// TestPrimitives_CSPFrameAncestorsBlocksFraming ensures CSP
// frame-ancestors 'none' is treated as an XFO equivalent: framing
// disabled, so frame-count primitive is unavailable.
func TestPrimitives_CSPFrameAncestorsBlocksFraming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Set-Cookie", "session=abc; SameSite=Strict")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>account</body></html>`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("frame-ancestors should block framing primitive; primitives=%v", res.Primitives)
	}
	if contains(res.Primitives, "framable") {
		t.Errorf("framable should not be set when CSP frame-ancestors restricts: %v", res.Primitives)
	}
}

func TestGradeSeverity(t *testing.T) {
	cases := []struct {
		name       string
		primitives []string
		want       core.Severity
	}{
		{"empty", nil, core.SeverityInfo},
		{"single low", []string{"no_coep"}, core.SeverityLow},
		{"framable alone", []string{"framable"}, core.SeverityLow},
		{"framable + no_coop public", []string{"framable", "no_coop"}, core.SeverityMedium},
		{"framable + no_coop + auth", []string{"framable", "no_coop", "auth_sensitive_path"}, core.SeverityHigh},
		{"framable + samesite + auth", []string{"framable", "samesite_cross_site", "auth_sensitive_path"}, core.SeverityHigh},
		{"json + no_corp + samesite", []string{"json_response", "no_corp", "samesite_cross_site"}, core.SeverityMedium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gradeSeverity(tc.primitives); got != tc.want {
				t.Errorf("gradeSeverity(%v) = %q, want %q", tc.primitives, got, tc.want)
			}
		})
	}
}

func TestIsAuthSensitivePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/account", true},
		{"/api/user", true},
		{"/api/me", true},
		{"/admin", true},
		{"/admin/users", true},
		{"/dashboard", true},
		{"/settings/profile", true},
		{"/profile", true},
		{"/search", false},
		{"/", false},
		{"/static/css/app.css", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := isAuthSensitivePath(tc.path); got != tc.want {
				t.Errorf("isAuthSensitivePath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseSameSite(t *testing.T) {
	cases := []struct {
		setCookie  string
		crossSite  bool // cookie sent on cross-site GET
		hasSession bool
	}{
		{"session=abc; SameSite=Strict", false, true},
		{"session=abc; SameSite=Lax", true, true}, // Lax sends on top-level cross-site GET
		{"session=abc; SameSite=None; Secure", true, true},
		{"session=abc", true, true}, // missing SameSite → browsers vary; treat as cross-site
		{"theme=dark; SameSite=Strict", false, false},
		{"", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.setCookie, func(t *testing.T) {
			cross, sess := analyzeSetCookie(tc.setCookie)
			if cross != tc.crossSite {
				t.Errorf("crossSite = %v, want %v", cross, tc.crossSite)
			}
			if sess != tc.hasSession {
				t.Errorf("hasSession = %v, want %v", sess, tc.hasSession)
			}
		})
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
