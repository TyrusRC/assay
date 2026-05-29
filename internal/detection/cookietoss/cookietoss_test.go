package cookietoss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_AuthCookieNoPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "sessionid",
			Value:    "abc123",
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
		})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("auth cookie without __Host- prefix should flag")
	}
	found := false
	for _, f := range res.Findings {
		if f.Metadata["cookie_name"] == "sessionid" && f.Type == "cookietoss_auth_cookie_no_prefix" {
			found = true
			if f.Severity != core.SeverityMedium {
				t.Errorf("no-prefix severity = %q, want medium", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected cookietoss_auth_cookie_no_prefix finding")
	}
}

func TestDetector_Detect_HostPrefixPasses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Use stdlib SetCookie which omits prefix-mode validation —
		// but the name still controls whether we flag.
		w.Header().Set("Set-Cookie", "__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range res.Findings {
		if f.Type == "cookietoss_auth_cookie_no_prefix" {
			t.Errorf("__Host- prefix should suppress no-prefix finding")
		}
	}
}

func TestDetector_Detect_OverbroadDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "tracking=abc; Domain=.example.com; Path=/")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Error("Domain=.example.com should flag")
	}
	found := false
	for _, f := range res.Findings {
		if f.Type == "cookietoss_overbroad_domain" {
			found = true
			if got := f.Metadata["domain"]; got != ".example.com" {
				t.Errorf("domain metadata = %v, want .example.com", got)
			}
		}
	}
	if !found {
		t.Error("expected cookietoss_overbroad_domain finding")
	}
}

func TestDetector_Detect_NoScopingMinimalConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Bare-bones cookie — no Domain, no Path, no SameSite, no Secure.
		w.Header().Set("Set-Cookie", "tracker=abc")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Type == "cookietoss_no_scoping_attributes" {
			found = true
			if f.Severity != core.SeverityLow {
				t.Errorf("no-scoping severity = %q, want low", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected cookietoss_no_scoping_attributes finding")
	}
}

func TestDetector_Detect_AuthCookieNoSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "JSESSIONID=abc; Path=/")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Type == "cookietoss_auth_cookie_no_secure" {
			found = true
			if f.Severity != core.SeverityHigh {
				t.Errorf("no-secure severity = %q, want high", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected cookietoss_auth_cookie_no_secure finding")
	}
}

func TestDetector_Detect_NoCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Error("no cookies in response must not flag")
	}
	if res.Cookies != 0 {
		t.Errorf("expected 0 cookies, got %d", res.Cookies)
	}
}

func TestIsAuthCookie(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"sessionid", true},
		{"PHPSESSID", true},
		{"JSESSIONID", true},
		{"access_token", true},
		{"jwt", true},
		{"csrf_token", true},
		{"tracking_id", false},
		{"locale", false},
		{"theme", false},
	}
	for _, c := range cases {
		if got := isAuthCookie(c.in); got != c.want {
			t.Errorf("isAuthCookie(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseSetCookie(t *testing.T) {
	raw := "foo=bar; Domain=.example.com; Path=/api; Secure; HttpOnly; SameSite=Strict"
	a := parseSetCookie(raw)
	if a.name != "foo" {
		t.Errorf("name = %q, want foo", a.name)
	}
	if a.domain != ".example.com" {
		t.Errorf("domain = %q", a.domain)
	}
	if a.path != "/api" {
		t.Errorf("path = %q", a.path)
	}
	if !a.secure {
		t.Error("expected Secure=true")
	}
	if !a.httpOnly {
		t.Error("expected HttpOnly=true")
	}
	if a.sameSite != "Strict" {
		t.Errorf("sameSite = %q, want Strict", a.sameSite)
	}
}
