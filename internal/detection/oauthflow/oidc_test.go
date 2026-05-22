package oauthflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func newOIDCClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second).WithFollowRedirects(false)
}

// TestDetectImplicitFlow_Accepted covers an IdP that still issues
// tokens via response_type=token.
func TestDetectImplicitFlow_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := r.URL.Query().Get("response_type")
		if rt == "token" || strings.Contains(rt, "id_token") {
			w.Header().Set("Location", "https://app.example.com/cb#access_token=ey...&token_type=Bearer")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "https://idp.example.com/error?error=unsupported_response_type")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	d := New(newOIDCClient())
	opts := DefaultOptions()
	opts.AuthzURL = srv.URL
	opts.ClientID = "client123"
	opts.RegisteredRedirectURI = "https://app.example.com/cb"

	res, err := d.DetectImplicitFlow(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("DetectImplicitFlow: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected implicit-flow finding; got %+v", res)
	}
}

// TestDetectImplicitFlow_Rejected covers a hardened IdP that returns
// error=unsupported_response_type for implicit grants.
func TestDetectImplicitFlow_Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://app.example.com/cb?error=unsupported_response_type")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	d := New(newOIDCClient())
	opts := DefaultOptions()
	opts.AuthzURL = srv.URL
	opts.ClientID = "client123"
	opts.RegisteredRedirectURI = "https://app.example.com/cb"

	res, err := d.DetectImplicitFlow(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("DetectImplicitFlow: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened IdP flagged: %+v", res)
	}
}

// TestDetectNonceMissing_Accepted covers an IdP that issues an
// id_token without enforcing nonce.
func TestDetectNonceMissing_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") == "id_token" && q.Get("nonce") == "" {
			w.Header().Set("Location", "https://app.example.com/cb#id_token=ey...")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "https://app.example.com/cb?error=invalid_request")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	d := New(newOIDCClient())
	opts := DefaultOptions()
	opts.AuthzURL = srv.URL
	opts.ClientID = "client123"
	opts.RegisteredRedirectURI = "https://app.example.com/cb"

	res, err := d.DetectNonceMissing(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("DetectNonceMissing: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected nonce-missing finding; got %+v", res)
	}
}

// TestDetectNonceMissing_Enforced covers a hardened IdP that rejects
// id_token requests without nonce.
func TestDetectNonceMissing_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") == "id_token" && q.Get("nonce") == "" {
			w.Header().Set("Location", "https://app.example.com/cb?error=invalid_request&error_description=nonce+required")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "https://app.example.com/cb#id_token=ok")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	d := New(newOIDCClient())
	opts := DefaultOptions()
	opts.AuthzURL = srv.URL
	opts.ClientID = "client123"
	opts.RegisteredRedirectURI = "https://app.example.com/cb"

	res, err := d.DetectNonceMissing(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("DetectNonceMissing: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened IdP flagged: %+v", res)
	}
}
