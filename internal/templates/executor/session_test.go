package executor

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// normalizeDomain
// ---------------------------------------------------------------------------

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"https://example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com/some/path", "example.com"},
		{"http://example.com:8080/path", "example.com:8080"},
		{"Example.Com:9090", "example.com:9090"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeDomain(tt.input)
			if got != tt.want {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewSession
// ---------------------------------------------------------------------------

func TestNewSession(t *testing.T) {
	s := NewSession()
	if s == nil {
		t.Fatal("NewSession() returned nil")
	}
	if s.cookies == nil {
		t.Fatal("NewSession().cookies is nil")
	}
}

// ---------------------------------------------------------------------------
// SetCookie / GetCookies
// ---------------------------------------------------------------------------

func TestSession_SetCookie_GetCookies(t *testing.T) {
	s := NewSession()

	// No cookies initially
	if got := s.GetCookies("example.com"); got != nil {
		t.Errorf("expected nil cookies for unknown domain, got %v", got)
	}

	s.SetCookie("example.com", "session", "abc123")
	s.SetCookie("example.com", "csrf", "tok")

	cookies := s.GetCookies("example.com")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d: %v", len(cookies), cookies)
	}
	if cookies["session"] != "abc123" {
		t.Errorf("session = %q, want %q", cookies["session"], "abc123")
	}
	if cookies["csrf"] != "tok" {
		t.Errorf("csrf = %q, want %q", cookies["csrf"], "tok")
	}
}

func TestSession_SetCookie_NormalizesDomain(t *testing.T) {
	s := NewSession()
	// Set with scheme, get without
	s.SetCookie("https://EXAMPLE.COM", "x", "1")
	cookies := s.GetCookies("example.com")
	if cookies["x"] != "1" {
		t.Errorf("expected cookie set with scheme to be retrievable by plain domain")
	}
}

func TestSession_GetCookies_ReturnsCopy(t *testing.T) {
	s := NewSession()
	s.SetCookie("example.com", "a", "1")
	copy1 := s.GetCookies("example.com")
	copy1["b"] = "2" // modify copy
	copy2 := s.GetCookies("example.com")
	if _, ok := copy2["b"]; ok {
		t.Error("modifying returned map should not affect session state")
	}
}

// ---------------------------------------------------------------------------
// CookieHeader
// ---------------------------------------------------------------------------

func TestSession_CookieHeader_Empty(t *testing.T) {
	s := NewSession()
	if got := s.CookieHeader("example.com"); got != "" {
		t.Errorf("expected empty string for unknown domain, got %q", got)
	}
}

func TestSession_CookieHeader_Single(t *testing.T) {
	s := NewSession()
	s.SetCookie("example.com", "session", "abc123")
	header := s.CookieHeader("example.com")
	if header != "session=abc123" {
		t.Errorf("CookieHeader() = %q, want %q", header, "session=abc123")
	}
}

func TestSession_CookieHeader_Multiple(t *testing.T) {
	s := NewSession()
	s.SetCookie("example.com", "a", "1")
	s.SetCookie("example.com", "b", "2")
	header := s.CookieHeader("example.com")
	// Order is map-iteration order, so check both parts exist
	if !strings.Contains(header, "a=1") {
		t.Errorf("CookieHeader() missing a=1: %q", header)
	}
	if !strings.Contains(header, "b=2") {
		t.Errorf("CookieHeader() missing b=2: %q", header)
	}
	if !strings.Contains(header, "; ") {
		t.Errorf("CookieHeader() should use '; ' separator: %q", header)
	}
}

// ---------------------------------------------------------------------------
// ParseResponseCookies
// ---------------------------------------------------------------------------

func TestSession_ParseResponseCookies_Basic(t *testing.T) {
	s := NewSession()
	headers := map[string]string{
		"Set-Cookie":   "session=xyz123; Path=/; HttpOnly",
		"Content-Type": "text/html",
	}
	s.ParseResponseCookies("example.com", headers)
	cookies := s.GetCookies("example.com")
	if cookies["session"] != "xyz123" {
		t.Errorf("expected session=xyz123, got %v", cookies)
	}
}

func TestSession_ParseResponseCookies_NoSetCookie(t *testing.T) {
	s := NewSession()
	headers := map[string]string{
		"Content-Type": "text/html",
	}
	s.ParseResponseCookies("example.com", headers)
	if cookies := s.GetCookies("example.com"); len(cookies) != 0 {
		t.Errorf("expected no cookies, got %v", cookies)
	}
}

func TestSession_ParseResponseCookies_CaseInsensitive(t *testing.T) {
	s := NewSession()
	headers := map[string]string{
		"set-cookie": "token=abc; Secure",
	}
	s.ParseResponseCookies("example.com", headers)
	cookies := s.GetCookies("example.com")
	if cookies["token"] != "abc" {
		t.Errorf("expected token=abc (case-insensitive header match), got %v", cookies)
	}
}

func TestSession_ParseResponseCookies_MalformedSkipped(t *testing.T) {
	s := NewSession()
	// No '=' in cookie name/value part
	headers := map[string]string{
		"Set-Cookie": "noequalssign",
	}
	s.ParseResponseCookies("example.com", headers)
	if cookies := s.GetCookies("example.com"); len(cookies) != 0 {
		t.Errorf("expected no cookies for malformed header, got %v", cookies)
	}
}

// ---------------------------------------------------------------------------
// ParseResponseURL
// ---------------------------------------------------------------------------

func TestSession_ParseResponseURL_Basic(t *testing.T) {
	s := NewSession()
	headers := map[string]string{
		"Set-Cookie": "id=42; Path=/",
	}
	s.ParseResponseURL("https://api.example.com/v1/resource", headers)
	cookies := s.GetCookies("api.example.com")
	if cookies["id"] != "42" {
		t.Errorf("expected id=42 from URL domain, got %v", cookies)
	}
}

func TestSession_ParseResponseURL_InvalidURL(t *testing.T) {
	s := NewSession()
	headers := map[string]string{
		"Set-Cookie": "id=42",
	}
	// Should not panic on invalid URL
	s.ParseResponseURL("://bad-url", headers)
}

func TestSession_ParseResponseURL_NoHost(t *testing.T) {
	s := NewSession()
	headers := map[string]string{
		"Set-Cookie": "id=42",
	}
	// relative URL - no host
	s.ParseResponseURL("/relative/path", headers)
	// Should store nothing since there's no domain
	// Just verify it doesn't panic
}
