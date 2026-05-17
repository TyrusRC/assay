package samlinj

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// baseAssertionFixture returns a minimal signed-looking <Assertion> the
// XSW tests can wrap. We don't actually sign it — the mock SP only
// inspects shape, not cryptographic validity.
func baseAssertionFixture() string {
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="signed-a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example/</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#signed-a1"/></ds:SignedInfo><ds:SignatureValue>FAKE</ds:SignatureValue></ds:Signature>
  <saml:Subject><saml:NameID>victim@example.com</saml:NameID></saml:Subject>
</saml:Assertion>`
}

// vulnerableSP simulates a naive SAML SP that:
//   - parses the SAMLResponse,
//   - picks the FIRST Assertion's NameID it sees regardless of which
//     element the signature actually references,
//   - issues a session cookie + 302 if a NameID was extracted.
//
// That is the canonical XSW-vulnerable behavior.
func vulnerableSP(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		encoded := r.Form.Get("SAMLResponse")
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			http.Error(w, "bad base64", http.StatusBadRequest)
			return
		}
		body := string(raw)
		// Naive parse: grab the first NameID it sees (which is what XSW
		// exploits — attacker's Assertion is placed earlier in document
		// order than the signed one).
		idx := strings.Index(body, "<saml:NameID>")
		if idx < 0 {
			http.Error(w, "no nameid", http.StatusBadRequest)
			return
		}
		end := strings.Index(body[idx:], "</saml:NameID>")
		if end < 0 {
			http.Error(w, "malformed nameid", http.StatusBadRequest)
			return
		}
		nameID := body[idx+len("<saml:NameID>") : idx+end]
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok-" + nameID})
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	}))
}

// safeSP rejects every SAMLResponse with 400 — strict validator.
func safeSP(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("signature reference mismatch"))
	}))
}

// base64OracleSP returns distinct status codes based on the truncated
// base64 length — the padding-oracle-like signal #4 looks for.
func base64OracleSP(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		encoded := r.Form.Get("SAMLResponse")
		// Distinct error shapes by length modulo 4 — like a real padding
		// oracle leaking cipher-block alignment.
		switch len(encoded) % 4 {
		case 0:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid padding"))
		case 1, 3:
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte("decryption failed"))
		case 2:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("xml parse error"))
		}
	}))
}

func newXSWDetector() *Detector {
	c := skwshttp.NewClient().WithTimeout(2 * time.Second)
	return New(c)
}

func TestDetectXSWNamespaceStripping_VulnSP(t *testing.T) {
	srv := vulnerableSP(t)
	defer srv.Close()

	det := newXSWDetector()
	finding, err := det.DetectXSWNamespaceStripping(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if err != nil {
		t.Fatalf("DetectXSWNamespaceStripping: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("severity: want Critical, got %s", finding.Severity)
	}
	if finding.Tool != "samlinj-xsw-detector" {
		t.Errorf("tool: want samlinj-xsw-detector, got %s", finding.Tool)
	}
	if !containsAny(finding.WSTG, "WSTG-IDNT-08") {
		t.Errorf("expected WSTG-IDNT-08 in %v", finding.WSTG)
	}
	if !containsAny(finding.Top10, "A07:2025") {
		t.Errorf("expected A07:2025 in %v", finding.Top10)
	}
	if !containsAny(finding.CWE, "CWE-347") {
		t.Errorf("expected CWE-347 in %v", finding.CWE)
	}
}

func TestDetectXSWNamespaceStripping_SafeSP(t *testing.T) {
	srv := safeSP(t)
	defer srv.Close()

	det := newXSWDetector()
	finding, err := det.DetectXSWNamespaceStripping(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if err != nil {
		t.Fatalf("DetectXSWNamespaceStripping: %v", err)
	}
	if finding != nil {
		t.Errorf("expected nil finding on safe SP, got %+v", finding)
	}
}

func TestDetectXSWDuplicateID_VulnSP(t *testing.T) {
	srv := vulnerableSP(t)
	defer srv.Close()

	det := newXSWDetector()
	finding, err := det.DetectXSWDuplicateID(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if err != nil {
		t.Fatalf("DetectXSWDuplicateID: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("severity: want Critical, got %s", finding.Severity)
	}
	if !strings.Contains(strings.ToLower(finding.Title), "duplicate") {
		t.Errorf("title should mention duplicate-id, got %q", finding.Title)
	}
}

func TestDetectXSWDuplicateID_SafeSP(t *testing.T) {
	srv := safeSP(t)
	defer srv.Close()

	det := newXSWDetector()
	finding, _ := det.DetectXSWDuplicateID(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if finding != nil {
		t.Errorf("expected nil on safe SP, got %+v", finding)
	}
}

func TestDetectXSWSOAPReorder_VulnSP(t *testing.T) {
	srv := vulnerableSP(t)
	defer srv.Close()

	det := newXSWDetector()
	finding, err := det.DetectXSWSOAPReorder(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if err != nil {
		t.Fatalf("DetectXSWSOAPReorder: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("severity: want Critical, got %s", finding.Severity)
	}
	if !strings.Contains(strings.ToLower(finding.Title), "soap") &&
		!strings.Contains(strings.ToLower(finding.Title), "reorder") {
		t.Errorf("title should mention soap/reorder, got %q", finding.Title)
	}
}

func TestDetectXSWSOAPReorder_SafeSP(t *testing.T) {
	srv := safeSP(t)
	defer srv.Close()

	det := newXSWDetector()
	finding, _ := det.DetectXSWSOAPReorder(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if finding != nil {
		t.Errorf("expected nil on safe SP, got %+v", finding)
	}
}

func TestDetectXSWBase64Oracle_DiscriminatingSP(t *testing.T) {
	srv := base64OracleSP(t)
	defer srv.Close()

	det := newXSWDetector()
	finding, err := det.DetectXSWBase64Oracle(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if err != nil {
		t.Fatalf("DetectXSWBase64Oracle: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding for discriminating responses")
	}
	if finding.Severity != core.SeverityMedium {
		t.Errorf("severity: want Medium, got %s", finding.Severity)
	}
	if finding.Tool != "samlinj-xsw-detector" {
		t.Errorf("tool: want samlinj-xsw-detector, got %s", finding.Tool)
	}
}

func TestDetectXSWBase64Oracle_UniformSP(t *testing.T) {
	// SP returns identical 400 for every length — no oracle.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid"))
	}))
	defer srv.Close()

	det := newXSWDetector()
	finding, _ := det.DetectXSWBase64Oracle(context.Background(), srv.URL+"/saml/acs", baseAssertionFixture())
	if finding != nil {
		t.Errorf("expected nil on uniform SP, got %+v", finding)
	}
}

func TestDetectXSW_NilClientNoOp(t *testing.T) {
	det := &Detector{client: nil}
	if f, _ := det.DetectXSWNamespaceStripping(context.Background(), "http://x/", baseAssertionFixture()); f != nil {
		t.Errorf("namespace-stripping: expected nil")
	}
	if f, _ := det.DetectXSWDuplicateID(context.Background(), "http://x/", baseAssertionFixture()); f != nil {
		t.Errorf("duplicate-id: expected nil")
	}
	if f, _ := det.DetectXSWSOAPReorder(context.Background(), "http://x/", baseAssertionFixture()); f != nil {
		t.Errorf("soap-reorder: expected nil")
	}
	if f, _ := det.DetectXSWBase64Oracle(context.Background(), "http://x/", baseAssertionFixture()); f != nil {
		t.Errorf("base64-oracle: expected nil")
	}
}

func TestDetectXSW_InvalidURL(t *testing.T) {
	det := newXSWDetector()
	// Unreachable target; should return nil, no panic. We pick a URL
	// that's syntactically valid but the http client refuses (bad scheme).
	bad := "://not-a-url"
	if _, err := url.Parse(bad); err == nil {
		t.Skip("url.Parse accepted invalid URL, can't test")
	}
	if f, _ := det.DetectXSWNamespaceStripping(context.Background(), bad, baseAssertionFixture()); f != nil {
		t.Errorf("expected nil on bad URL")
	}
}

// containsAny reports whether haystack contains target.
func containsAny(haystack []string, target string) bool {
	for _, h := range haystack {
		if h == target {
			return true
		}
	}
	return false
}
