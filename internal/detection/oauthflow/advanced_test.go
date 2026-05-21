package oauthflow

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

func advClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second)
}

// TestExtendedRedirectURIVariants_NewBypasses asserts that the variant
// list now includes the canonical real-world bypasses missing from the
// v1 list (userinfo split, backslash quirk, fragment-confusion).
func TestExtendedRedirectURIVariants_NewBypasses(t *testing.T) {
	registered := "https://app.example.com/cb"
	got := extendedRedirectURIVariants(registered)

	required := []string{
		"@attacker.com",                   // userinfo @host bypass
		"#@attacker.com",                  // fragment-confusion
		"app.example.com%2f@attacker.com", // percent-encoded slash userinfo
	}
	for _, req := range required {
		if !anyContains(got, req) {
			t.Errorf("extended variant list missing pattern containing %q; got=%v", req, got)
		}
	}
}

// TestDetectResponseModeConfusion covers an IdP that honors a
// response_mode override the client never requested (e.g.,
// response_mode=query when the client registered for fragment) — a
// token-leak surface because URL query strings land in logs and
// referers while fragments don't.
func TestDetectResponseModeConfusion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := r.URL.Query().Get("response_mode")
		if mode == "query" || mode == "form_post" {
			// IdP accepts and would route the response that way.
			http.Redirect(w, r, "https://app.example.com/cb?code=ABC&state=x", http.StatusFound)
			return
		}
		// No mode override: behave normally.
		http.Redirect(w, r, "https://app.example.com/cb#code=ABC&state=x", http.StatusFound)
	}))
	defer srv.Close()

	d := New(advClient())
	res, err := d.DetectResponseModeConfusion(context.Background(), srv.URL, DetectOptions{
		ClientID:              "test-client",
		RegisteredRedirectURI: "https://app.example.com/cb",
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectResponseModeConfusion: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected response_mode confusion to fire; got %+v", res)
	}
	hasHigh := false
	for _, f := range res.Findings {
		if f.Severity == core.SeverityHigh || f.Severity == core.SeverityMedium {
			hasHigh = true
		}
		if !contains(f.CWE, "CWE-200") {
			t.Errorf("expected CWE-200 on response_mode finding; got %v", f.CWE)
		}
	}
	if !hasHigh {
		t.Error("expected at least one medium/high finding")
	}
}

// TestDetectResponseModeConfusion_Hardened_NoFinding confirms an IdP
// that rejects unknown response_mode values does not get flagged.
func TestDetectResponseModeConfusion_Hardened_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := r.URL.Query().Get("response_mode")
		if mode != "" && mode != "fragment" {
			http.Redirect(w, r, "https://app.example.com/cb?error=invalid_request", http.StatusFound)
			return
		}
		http.Redirect(w, r, "https://app.example.com/cb#code=ABC&state=x", http.StatusFound)
	}))
	defer srv.Close()

	d := New(advClient())
	res, err := d.DetectResponseModeConfusion(context.Background(), srv.URL, DetectOptions{
		ClientID:              "test-client",
		RegisteredRedirectURI: "https://app.example.com/cb",
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectResponseModeConfusion: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened IdP flagged: %+v", res)
	}
}

// TestDetectRedirectURIMatching_UserinfoBypass exercises the *full*
// matching probe (the existing one) with the *new* variants merged in,
// against an IdP that accepts the userinfo trick:
// `https://attacker.com@app.example.com/cb` — many naïve string
// validators look at the host substring `app.example.com` and pass.
func TestDetectRedirectURIMatching_UserinfoBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		if strings.Contains(ru, "@") {
			// IdP redirects to the supplied URI without validating.
			http.Redirect(w, r, ru+"?code=ABC&state=x", http.StatusFound)
			return
		}
		http.Redirect(w, r, ru+"?code=ABC&state=x", http.StatusFound)
	}))
	defer srv.Close()

	d := New(advClient())
	res, err := d.DetectRedirectURIMatching(context.Background(), srv.URL, DetectOptions{
		ClientID:              "test-client",
		RegisteredRedirectURI: "https://app.example.com/cb",
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectRedirectURIMatching: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected redirect_uri bypass; got %+v", res)
	}
}

func anyContains(list []string, needle string) bool {
	for _, s := range list {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
