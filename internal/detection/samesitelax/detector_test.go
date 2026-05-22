package samesitelax

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/TyrusRC/assay/internal/http"
)

// TestDetect_LaxOnSessionCookie covers the modern-browser default case:
// a session cookie carries SameSite=Lax, so top-level GET navigation
// from a malicious site still sends the cookie.
func TestDetect_LaxOnSessionCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "abc123",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected finding for SameSite=Lax session cookie; got %+v", res.Findings)
	}
	if len(res.Findings) == 0 || !strings.Contains(res.Findings[0].Evidence, "session") {
		t.Errorf("expected finding evidence to mention the cookie name; got %+v", res.Findings)
	}
}

// TestDetect_MissingSameSite covers cookies with no SameSite attribute.
// Chrome 80+ defaults missing SameSite to Lax, so this is the same risk
// as an explicit SameSite=Lax.
func TestDetect_MissingSameSite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "auth_token=tok; Path=/; HttpOnly")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected finding for missing SameSite on auth cookie; got %+v", res.Findings)
	}
}

// TestDetect_NoneOnSessionCookie covers SameSite=None, which is even
// looser than Lax — cross-site POST and GET both carry the cookie.
func TestDetect_NoneOnSessionCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "sid",
			Value:    "xyz",
			Path:     "/",
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected finding for SameSite=None session cookie; got %+v", res.Findings)
	}
}

// TestDetect_StrictOnSessionCookie covers the safe case — SameSite=Strict
// blocks all cross-site requests carrying the cookie.
func TestDetect_StrictOnSessionCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "JSESSIONID",
			Value:    "strict-session",
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no finding for SameSite=Strict; got %+v", res.Findings)
	}
}

// TestDetect_NonAuthCookieIgnored covers cookies that aren't auth-bearing
// (e.g., a UI preference). SameSite settings on those don't matter.
func TestDetect_NonAuthCookieIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "theme=dark; Path=/; SameSite=Lax")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no finding for non-auth cookie; got %+v", res.Findings)
	}
}

// TestDetect_LaxPlusGetLogout escalates the finding when the app accepts
// a state-changing GET (logout) — the canonical exploitable scenario.
func TestDetect_LaxPlusGetLogout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account":
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    "alice-session",
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			w.WriteHeader(http.StatusOK)
		case "/logout":
			// Accept GET, invalidate session by clearing the cookie.
			if r.Method != http.MethodGet {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:   "session",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	opts := DefaultOptions()
	opts.ProbeLogoutPaths = true

	res, err := d.Detect(context.Background(), srv.URL+"/account", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected finding with GET-logout escalation; got %+v", res.Findings)
	}
	// At least one finding should mention the confirmed GET-logout signal.
	escalated := false
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "GET /logout") || strings.Contains(f.Evidence, "GET-accepted state-changing endpoint") {
			escalated = true
			break
		}
	}
	if !escalated {
		t.Errorf("expected escalated finding mentioning GET-logout; got %+v", res.Findings)
	}
}

// TestDetect_NoCookies covers an endpoint that issues no cookies at all —
// the detector should return cleanly with no findings.
func TestDetect_NoCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no finding for an endpoint with no cookies; got %+v", res.Findings)
	}
}

// TestDetect_NilClient is a safety check — the detector must not panic
// when given a nil client (defensive guard for misconfigured pipelines).
func TestDetect_NilClient(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.com/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no finding with nil client; got %+v", res.Findings)
	}
}
