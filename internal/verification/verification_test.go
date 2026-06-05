package verification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	httpx "github.com/TyrusRC/assay/internal/http"
)

// writeHTML writes an HTML body and fails the test on a write error, keeping
// the errcheck linter (check-blank) satisfied without bare blank assignments.
func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html")
	if _, err := w.Write([]byte(body)); err != nil {
		panic(err)
	}
}

func newFinding(vulnType, url, param string) *core.Finding {
	f := core.NewFinding(vulnType, core.SeverityHigh)
	f.At(url, param)
	f.Confidence = core.ConfidenceMedium
	return f
}

func TestEngine_VerifyOpenRedirect_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the "next" parameter straight into a redirect, unsanitised.
		next := r.URL.Query().Get("next")
		if next != "" {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Open Redirect", srv.URL+"/?next=x", "next")

	proof, hadVerifier := eng.Verify(context.Background(), f)
	if !hadVerifier {
		t.Fatal("expected a verifier registered for Open Redirect")
	}
	if proof == nil || !proof.Confirmed {
		t.Fatalf("expected confirmed proof, got %+v", proof)
	}
	if f.Confidence != core.ConfidenceConfirmed || !f.Verified {
		t.Fatalf("finding should be upgraded to confirmed/verified, got conf=%s verified=%v", f.Confidence, f.Verified)
	}
}

func TestEngine_VerifyOpenRedirect_NotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Safe: never honors the attacker-controlled destination.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Open Redirect", srv.URL+"/?next=x", "next")

	proof, hadVerifier := eng.Verify(context.Background(), f)
	if !hadVerifier {
		t.Fatal("expected a verifier registered for Open Redirect")
	}
	if proof != nil && proof.Confirmed {
		t.Fatalf("expected not confirmed, got %+v", proof)
	}
	if f.Verified {
		t.Fatal("finding must not be marked verified when unconfirmed")
	}
	if f.Confidence == core.ConfidenceConfirmed {
		t.Fatal("confidence must not be upgraded when unconfirmed")
	}
}

func TestEngine_VerifyReflectedXSS_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Reflects raw, unencoded — angle brackets survive.
		writeHTML(w, "<html><body>results for "+q+"</body></html>")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Cross-Site Scripting (XSS)", srv.URL+"/?q=x", "q")

	proof, hadVerifier := eng.Verify(context.Background(), f)
	if !hadVerifier {
		t.Fatal("expected a verifier registered for XSS")
	}
	if proof == nil || !proof.Confirmed {
		t.Fatalf("expected confirmed proof, got %+v", proof)
	}
	if f.Confidence != core.ConfidenceConfirmed {
		t.Fatalf("expected confirmed confidence, got %s", f.Confidence)
	}
}

func TestEngine_VerifyReflectedXSS_EncodedNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Properly HTML-encodes the reflection: not exploitable.
		safe := strings.NewReplacer("<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(q)
		writeHTML(w, "<html><body>results for "+safe+"</body></html>")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Cross-Site Scripting (XSS)", srv.URL+"/?q=x", "q")

	proof, _ := eng.Verify(context.Background(), f)
	if proof != nil && proof.Confirmed {
		t.Fatalf("encoded reflection must not be confirmed, got %+v", proof)
	}
	if f.Verified {
		t.Fatal("encoded reflection must not mark finding verified")
	}
}

func TestEngine_Verify_NoVerifierForType(t *testing.T) {
	eng := NewEngine(httpx.NewClient())
	f := newFinding("Some Exotic Finding", "https://example.com/", "p")

	proof, hadVerifier := eng.Verify(context.Background(), f)
	if hadVerifier {
		t.Fatal("did not expect a verifier for an unknown type")
	}
	if proof != nil {
		t.Fatal("expected nil proof for unknown type")
	}
}

func TestEngine_VerifyAll_Summary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next := r.URL.Query().Get("next"); next != "" {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	findings := core.Findings{
		newFinding("Open Redirect", srv.URL+"/?next=x", "next"),
		newFinding("Some Exotic Finding", srv.URL+"/", "p"),
	}

	sum := eng.VerifyAll(context.Background(), findings)
	if sum.Attempted != 1 {
		t.Fatalf("expected 1 attempted (only the open redirect has a verifier), got %d", sum.Attempted)
	}
	if sum.Confirmed != 1 {
		t.Fatalf("expected 1 confirmed, got %d", sum.Confirmed)
	}
}
