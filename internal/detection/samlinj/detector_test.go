package samlinj

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsAcceptingSP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: SP accepts every SAMLResponse and 302s with a
		// session cookie, regardless of envelope shape.
		if !strings.HasPrefix(r.URL.Path, "/saml/") && !strings.HasPrefix(r.URL.Path, "/SAML2/") &&
			!strings.HasPrefix(r.URL.Path, "/sso/") && !strings.HasPrefix(r.URL.Path, "/Shibboleth.sso/") {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok"})
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected SAML-injection-surface finding")
	}
}

func TestDetect_NoFindingOnStrictSP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// SP rejects every SAMLResponse with 400 — strict validator.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid SAML"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on strict SP, got %d", len(res.Findings))
	}
}

func TestDetect_NilClientNoOp(t *testing.T) {
	det := &Detector{client: nil}
	res, _ := det.Detect(context.Background(), "http://x.test/")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}
