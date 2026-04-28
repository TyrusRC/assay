package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

// idpHandler returns an httptest server that simulates an OIDC IdP. The
// metadata field controls the JSON served at the well-known endpoint.
// authorizeBehavior controls how the /authorize endpoint reacts to a
// hostile redirect_uri ("reject" -> 400, "redirect" -> 302 echoing it).
func idpHandler(t *testing.T, metadataJSON string, authorizeBehavior string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, metadataJSON)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redir := r.URL.Query().Get("redirect_uri")
		switch authorizeBehavior {
		case "reject":
			w.WriteHeader(http.StatusBadRequest)
		case "redirect":
			w.Header().Set("Location", redir+"?code=fake")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	return httptest.NewServer(mux)
}

// TestDetector_RedirectURIBypass: an IdP that redirects with the
// attacker host in Location is the classic open-redirect-via-OAuth.
//
// We need the metadata's authorization_endpoint to point at the SAME
// httptest server that's serving discovery, which means we can't use
// idpHandler's static metadata — its URL isn't known until ListenAndServe
// runs. Use a closure that captures the live server URL via a
// late-bound variable instead.
func TestDetector_RedirectURIBypass(t *testing.T) {
	var liveURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer": "%s",
			"authorization_endpoint": "%s/authorize",
			"token_endpoint": "%s/token",
			"jwks_uri": "%s/jwks.json",
			"response_types_supported": ["code"],
			"code_challenge_methods_supported": ["S256"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`, liveURL, liveURL, liveURL, liveURL)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redir := r.URL.Query().Get("redirect_uri")
		w.Header().Set("Location", redir+"?code=fake")
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	liveURL = srv.URL

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	hit := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "redirect_uri Exact-Match Bypass") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected redirect_uri-bypass finding, got %+v", res.Findings)
	}
}

// TestDetector_NoneAlgAdvertised: id_token alg=none is critical-severity
// authentication bypass.
func TestDetector_NoneAlgAdvertised(t *testing.T) {
	meta := `{"issuer":"http://idp","authorization_endpoint":"http://idp/authorize","id_token_signing_alg_values_supported":["RS256","none"],"code_challenge_methods_supported":["S256"]}`
	srv := idpHandler(t, meta, "reject")
	defer srv.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, _ := d.Detect(context.Background(), srv.URL, DefaultOptions())
	hit := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "alg=none") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected alg=none finding, got %+v", res.Findings)
	}
}

// TestDetector_MissingPKCE: when the metadata does not advertise any
// code_challenge_methods_supported, a medium-severity finding fires.
func TestDetector_MissingPKCE(t *testing.T) {
	meta := `{"issuer":"http://idp","authorization_endpoint":"http://idp/authorize","id_token_signing_alg_values_supported":["RS256"],"response_types_supported":["code"]}`
	srv := idpHandler(t, meta, "reject")
	defer srv.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, _ := d.Detect(context.Background(), srv.URL, DefaultOptions())
	hit := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "PKCE Not Advertised") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected missing-PKCE finding, got %+v", res.Findings)
	}
}

// TestDetector_HardenedIdP: a fully-locked-down IdP produces zero
// findings — the FP guardrail.
func TestDetector_HardenedIdP(t *testing.T) {
	meta := `{
		"issuer":"http://idp",
		"authorization_endpoint":"http://idp/authorize",
		"id_token_signing_alg_values_supported":["RS256","ES256"],
		"code_challenge_methods_supported":["S256"],
		"response_types_supported":["code"]
	}`
	srv := idpHandler(t, meta, "reject")
	defer srv.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, _ := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if res.Vulnerable || len(res.Findings) > 0 {
		t.Fatalf("expected zero findings on hardened IdP, got %+v", res.Findings)
	}
}

// TestDetector_NoOIDCSurface: a target with no /.well-known endpoint
// produces zero findings (and no errors).
func TestDetector_NoOIDCSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect should not error on missing OIDC surface: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero findings, got %+v", res.Findings)
	}
}
