package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	client := &http.Client{}
	d := New(client)

	if d == nil {
		t.Fatal("New() returned nil")
	}
	if d.client != client {
		t.Error("New() did not set client")
	}
}

func TestDetector_Name(t *testing.T) {
	d := New(&http.Client{})
	if d.Name() != "storage" {
		t.Errorf("Name() = %q, want %q", d.Name(), "storage")
	}
}

func TestDetector_Description(t *testing.T) {
	d := New(&http.Client{})
	desc := d.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	d := New(&http.Client{}).WithVerbose(true)
	if !d.verbose {
		t.Error("WithVerbose(true) should set verbose to true")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout != 10*time.Second {
		t.Errorf("DefaultOptions().Timeout = %v, want 10s", opts.Timeout)
	}
	if !opts.CheckCookieFlags {
		t.Error("DefaultOptions().CheckCookieFlags should be true")
	}
	if !opts.CheckSessionMgmt {
		t.Error("DefaultOptions().CheckSessionMgmt should be true")
	}
}

func TestDetectionResult_Fields(t *testing.T) {
	result := &DetectionResult{
		Vulnerable:      true,
		AnalyzedCookies: 3,
		InsecureCookies: []string{"session", "tracking"},
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.AnalyzedCookies != 3 {
		t.Errorf("AnalyzedCookies = %d, want 3", result.AnalyzedCookies)
	}
	if len(result.InsecureCookies) != 2 {
		t.Errorf("InsecureCookies length = %d, want 2", len(result.InsecureCookies))
	}
}

// TestDetect_InsecureCookies tests detection of cookies missing security flags.
func TestDetect_InsecureCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set cookies without Secure or HttpOnly flags
		http.SetCookie(w, &http.Cookie{
			Name:  "session_id",
			Value: "abc123def456ghi789jkl012mno345pq",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "tracking",
			Value: "user-track-value",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerabilities for insecure cookies")
	}
	if result.AnalyzedCookies != 2 {
		t.Errorf("AnalyzedCookies = %d, want 2", result.AnalyzedCookies)
	}
	if len(result.InsecureCookies) == 0 {
		t.Error("Expected insecure cookies to be listed")
	}
	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding for insecure cookies")
	}
}

// TestDetect_SecureCookies tests that properly secured cookies produce no findings.
func TestDetect_SecureCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "k8Xm2pQ9rT5vW1yZ3aB6cD8eF0gH4iJ",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.AnalyzedCookies != 1 {
		t.Errorf("AnalyzedCookies = %d, want 1", result.AnalyzedCookies)
	}
	// A fully secure cookie should not produce cookie-flag findings.
	for _, f := range result.Findings {
		if f.Parameter == "session_id" && strings.Contains(f.Description, "Secure") {
			t.Error("Secure cookie should not produce a missing-Secure finding")
		}
		if f.Parameter == "session_id" && strings.Contains(f.Description, "HttpOnly") {
			t.Error("HttpOnly cookie should not produce a missing-HttpOnly finding")
		}
	}
}

// TestDetect_MissingSecureFlag tests that a cookie without Secure flag is flagged.
func TestDetect_MissingSecureFlag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "somevalue",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			// Secure is missing
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerability for missing Secure flag")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "Secure") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a finding about missing Secure flag")
	}
}

// TestDetect_MissingHttpOnlyFlag tests that a cookie without HttpOnly is flagged.
func TestDetect_MissingHttpOnlyFlag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "auth",
			Value:    "secretvalue",
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			// HttpOnly is missing
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerability for missing HttpOnly flag")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "HttpOnly") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a finding about missing HttpOnly flag")
	}
}

// TestDetect_MissingSameSite tests that a cookie without SameSite is flagged.
func TestDetect_MissingSameSite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    "tokenvalue",
			Secure:   true,
			HttpOnly: true,
			// SameSite is missing (defaults to SameSiteDefaultMode = 0)
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerability for missing SameSite attribute")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "SameSite") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a finding about missing SameSite attribute")
	}
}

// TestDetect_WeakSameSiteNone tests that SameSite=None is flagged as weak.
func TestDetect_WeakSameSiteNone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "mysession",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerability for SameSite=None")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "SameSite") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a finding about weak SameSite=None")
	}
}

// TestDetect_BroadDomain tests that an overly broad Domain attribute is flagged.
func TestDetect_BroadDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "prefs",
			Value:    "language=en",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Domain:   ".example.com",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerability for broad Domain attribute")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "Domain") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a finding about overly broad Domain attribute")
	}
}

// TestDetect_NoCookies tests that a server with no cookies produces no findings.
func TestDetect_NoCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("no cookies here"))
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.AnalyzedCookies != 0 {
		t.Errorf("AnalyzedCookies = %d, want 0", result.AnalyzedCookies)
	}
	if result.Vulnerable {
		t.Error("Expected no vulnerability when no cookies present")
	}
}

// TestDetect_ContextCancellation tests that context cancellation is respected.
func TestDetect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := d.Detect(ctx, server.URL, DefaultOptions())
	if err == nil {
		t.Error("Expected error from context cancellation")
	}
}

// TestDetect_InvalidURL tests that an invalid URL returns an error.
func TestDetect_InvalidURL(t *testing.T) {
	d := New(&http.Client{})
	_, err := d.Detect(context.Background(), "://bad-url", DefaultOptions())
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

// TestDetect_ConnectionRefused tests that a connection error returns an error.
func TestDetect_ConnectionRefused(t *testing.T) {
	d := New(&http.Client{Timeout: 1 * time.Second})
	_, err := d.Detect(context.Background(), "http://127.0.0.1:1", DefaultOptions())
	if err == nil {
		t.Error("Expected error for connection refused")
	}
}

// TestDetect_CookieFlagsDisabled tests that cookie flag checks can be disabled.
func TestDetect_CookieFlagsDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "insecure",
			Value: "value",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	opts := DefaultOptions()
	opts.CheckCookieFlags = false
	opts.CheckSessionMgmt = false

	result, err := d.Detect(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	// Cookie flags are not checked, so no cookie-flag findings should be present.
	if result.AnalyzedCookies != 1 {
		t.Errorf("AnalyzedCookies = %d, want 1", result.AnalyzedCookies)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Expected no findings when checks disabled, got %d", len(result.Findings))
	}
}

// TestDetect_LowEntropySessionID tests detection of predictable session IDs.
func TestDetect_LowEntropySessionID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "JSESSIONID",
			Value:    "1234",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	opts := DefaultOptions()
	opts.CheckCookieFlags = false // Isolate session mgmt checks
	opts.CheckSessionMgmt = true

	result, err := d.Detect(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerability for low-entropy session ID")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "entropy") || strings.Contains(f.Description, "predictable") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a finding about low-entropy session ID")
	}
}

// TestDetect_HighEntropySessionID tests that a high-entropy session ID is not flagged.
func TestDetect_HighEntropySessionID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "JSESSIONID",
			Value:    "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ123456",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	opts := DefaultOptions()
	opts.CheckCookieFlags = false
	opts.CheckSessionMgmt = true

	result, err := d.Detect(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	for _, f := range result.Findings {
		if strings.Contains(f.Description, "entropy") || strings.Contains(f.Description, "predictable") {
			t.Error("High-entropy session ID should not produce a low-entropy finding")
		}
	}
}

// TestDetect_SessionFixation tests detection of session fixation vulnerability.
func TestDetect_SessionFixation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server accepts and echoes back externally set session IDs
		incoming := ""
		for _, c := range r.Cookies() {
			if c.Name == "PHPSESSID" {
				incoming = c.Value
			}
		}
		if incoming != "" {
			// Accepts the externally provided session ID without regenerating
			http.SetCookie(w, &http.Cookie{
				Name:     "PHPSESSID",
				Value:    incoming,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		} else {
			http.SetCookie(w, &http.Cookie{
				Name:     "PHPSESSID",
				Value:    "server-generated-session-id-random",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	opts := DefaultOptions()
	opts.CheckCookieFlags = false
	opts.CheckSessionMgmt = true

	result, err := d.Detect(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerability for session fixation")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "fixation") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a finding about session fixation")
	}
}

// TestDetect_NoSessionFixation tests that regenerated session IDs are not flagged.
func TestDetect_NoSessionFixation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server always generates a new session ID regardless of input
		http.SetCookie(w, &http.Cookie{
			Name:     "PHPSESSID",
			Value:    "brand-new-server-generated-unique-random-id",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	opts := DefaultOptions()
	opts.CheckCookieFlags = false
	opts.CheckSessionMgmt = true

	result, err := d.Detect(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	for _, f := range result.Findings {
		if strings.Contains(f.Description, "fixation") {
			t.Error("Server that regenerates session IDs should not produce fixation finding")
		}
	}
}

// TestDetect_MultipleCookies tests analyzing multiple cookies in a single response.
func TestDetect_MultipleCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "secure_cookie",
			Value:    "value1",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "insecure_cookie",
			Value: "value2",
			// Missing all security flags
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "partial_cookie",
			Value:    "value3",
			Secure:   true,
			HttpOnly: false,
			// Missing SameSite
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.AnalyzedCookies != 3 {
		t.Errorf("AnalyzedCookies = %d, want 3", result.AnalyzedCookies)
	}
	if !result.Vulnerable {
		t.Error("Expected vulnerabilities for mixed-security cookies")
	}
	// insecure_cookie and partial_cookie should be listed
	if len(result.InsecureCookies) < 2 {
		t.Errorf("InsecureCookies length = %d, want >= 2", len(result.InsecureCookies))
	}
}

// TestDetect_OWASPMapping verifies OWASP mappings on generated findings.
func TestDetect_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "insecure-value",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := New(server.Client())
	result, err := d.Detect(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	f := result.Findings[0]
	if len(f.WSTG) == 0 {
		t.Error("Expected WSTG mapping on finding")
	}
	if len(f.CWE) == 0 {
		t.Error("Expected CWE mapping on finding")
	}
}

// TestIsSessionCookieName verifies the heuristic for identifying session cookie names.
func TestIsSessionCookieName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"JSESSIONID", "JSESSIONID", true},
		{"PHPSESSID", "PHPSESSID", true},
		{"ASP.NET_SessionId", "ASP.NET_SessionId", true},
		{"session_id", "session_id", true},
		{"sid", "sid", true},
		{"connect.sid", "connect.sid", true},
		{"SESSIONID", "SESSIONID", true},
		{"token", "token", true},
		{"auth_token", "auth_token", true},
		{"preference", "preference", false},
		{"language", "language", false},
		{"theme", "theme", false},
		{"_ga", "_ga", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSessionCookieName(tt.input)
			if result != tt.expected {
				t.Errorf("isSessionCookieName(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestCalculateEntropy verifies Shannon entropy calculation for session IDs.
func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLow bool // true means we expect low entropy
	}{
		{"all same chars", "aaaaaaaaaaaaaaaa", true},
		{"sequential digits", "1234", true},
		{"short value", "ab", true},
		{"high entropy hex", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", false},
		{"mixed case alphanumeric", "k8Xm2pQ9rT5vW1yZ3aB6cD8eF0gH4iJ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := calculateEntropy(tt.input)
			// A low entropy session ID has entropy per char < 3.0 or total length < 16
			isLow := entropy < 3.0 || len(tt.input) < 16
			if isLow != tt.wantLow {
				t.Errorf("calculateEntropy(%q) = %.2f, len=%d, isLow=%v, wantLow=%v",
					tt.input, entropy, len(tt.input), isLow, tt.wantLow)
			}
		})
	}
}
