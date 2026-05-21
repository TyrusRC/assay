package jwtadvanced

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// makeToken builds a JWT-shaped string with the given header and claims.
// The signature segment is whatever the caller wants — empty string for
// alg=none, base64 garbage otherwise.
func makeToken(header map[string]interface{}, claims map[string]interface{}, sig string) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "." + sig
}

// validToken is the baseline a real client would send.
func validToken() string {
	return makeToken(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "alice", "role": "user"},
		"valid-sig",
	)
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(newClient())
	if d.Name() != "jwtadvanced" {
		t.Errorf("Name() = %q, want jwtadvanced", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NilClientIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/", DetectOptions{Token: validToken()})
	if err != nil {
		t.Fatalf("Detect with nil client returned error: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil client, got %+v", res)
	}
}

func TestDetector_EmptyTokenIsNoOp(t *testing.T) {
	d := New(newClient())
	res, err := d.Detect(context.Background(), "https://example.invalid/", DetectOptions{})
	if err != nil {
		t.Fatalf("Detect with empty token returned error: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on empty token, got %+v", res)
	}
}

// vulnerableServer accepts the original token *and* any token with
// alg=none or an empty signature — the textbook misconfigurations.
// Everything else gets 401. This lets us assert that the detector
// fires only on the bad cases.
func vulnerableServer(t *testing.T, original string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(auth, prefix)

		if tok == original {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}

		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Decode header — naive verifiers that accept alg=none branch
		// based on the header value, not the trusted server config.
		hRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var hdr map[string]interface{}
		if json.Unmarshal(hRaw, &hdr) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		alg, _ := hdr["alg"].(string)
		if strings.EqualFold(alg, "none") {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Buggy empty-signature acceptance: a real-world misconfig
		// where signature verification is skipped if no signature was
		// presented.
		if parts[2] == "" {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
	}))
}

func TestDetector_FlagsNoneAlgAcceptance(t *testing.T) {
	tok := validToken()
	srv := vulnerableServer(t, tok)
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DetectOptions{Token: tok})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable; accepted=%v", res.AcceptedForgeries)
	}
	if !containsForgery(res.AcceptedForgeries, "alg=none") {
		t.Errorf("expected alg=none to be flagged; got %v", res.AcceptedForgeries)
	}
	// At least one finding should be critical (none accepted = full forge)
	hasCritical := false
	hasCWE := false
	for _, f := range res.Findings {
		if f.Severity == core.SeverityCritical {
			hasCritical = true
		}
		if contains(f.CWE, "CWE-347") {
			hasCWE = true
		}
	}
	if !hasCritical {
		t.Errorf("expected at least one critical finding, got severities=%v", severities(res.Findings))
	}
	if !hasCWE {
		t.Error("expected CWE-347 mapping on findings")
	}
}

func TestDetector_FlagsEmptySignatureAcceptance(t *testing.T) {
	tok := validToken()
	srv := vulnerableServer(t, tok)
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DetectOptions{Token: tok})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable; accepted=%v", res.AcceptedForgeries)
	}
	if !containsForgery(res.AcceptedForgeries, "empty_signature") {
		t.Errorf("expected empty_signature to be flagged; got %v", res.AcceptedForgeries)
	}
}

// hardenedServer rejects every variant except the original — the
// detector must not fire when the server actually verifies signatures.
func hardenedServer(t *testing.T, original string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+original {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

func TestDetector_NoFinding_OnHardenedServer(t *testing.T) {
	tok := validToken()
	srv := hardenedServer(t, tok)
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DetectOptions{Token: tok})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened server flagged: accepted=%v", res.AcceptedForgeries)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

// TestDetector_BaselineUnauthorized_NoOp covers the case where the
// supplied token doesn't actually authorize the request — we can't
// derive a status-diff signal so the detector should bail rather than
// emit nonsense findings against every forgery.
func TestDetector_BaselineUnauthorized_NoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DetectOptions{Token: validToken()})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no-op when baseline is unauthorized; got %+v", res)
	}
}

func TestDetector_QueryParamDelivery(t *testing.T) {
	tok := validToken()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("token")
		if got == tok {
			w.WriteHeader(http.StatusOK)
			return
		}
		// accept alg=none over query param too
		if parts := strings.Split(got, "."); len(parts) == 3 {
			if h, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
				var hdr map[string]interface{}
				if json.Unmarshal(h, &hdr) == nil {
					if alg, _ := hdr["alg"].(string); strings.EqualFold(alg, "none") {
						w.WriteHeader(http.StatusOK)
						return
					}
				}
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DetectOptions{
		Token:      tok,
		TokenParam: "token",
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected detection via query param; accepted=%v", res.AcceptedForgeries)
	}
}

func containsForgery(list []string, prefix string) bool {
	for _, f := range list {
		if strings.HasPrefix(f, prefix) || f == prefix {
			return true
		}
	}
	return false
}

func contains(list []string, needle string) bool {
	for _, h := range list {
		if h == needle {
			return true
		}
	}
	return false
}

func severities(fs []*core.Finding) []core.Severity {
	out := make([]core.Severity, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Severity)
	}
	return out
}
