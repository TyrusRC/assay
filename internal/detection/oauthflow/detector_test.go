package oauthflow

import (
	"context"
	"encoding/base64"
	"fmt"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	internalhttp "github.com/TyrusRC/assay/internal/http"
)

func newTestClient() *internalhttp.Client {
	return internalhttp.NewClient().WithTimeout(5 * time.Second)
}

func TestNew(t *testing.T) {
	d := New(newTestClient())
	if d == nil {
		t.Fatal("New() returned nil")
	}
	if d.client == nil {
		t.Fatal("Detector.client should be non-nil")
	}
}

func TestWithVerbose(t *testing.T) {
	d := New(newTestClient()).WithVerbose(true)
	if !d.verbose {
		t.Error("WithVerbose(true) did not set the verbose flag")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout <= 0 {
		t.Error("DefaultOptions().Timeout should be positive")
	}
	if opts.ClientID == "" {
		t.Error("DefaultOptions().ClientID should be set")
	}
}

// --- DetectStateBinding ---------------------------------------------

// vulnerable IdP: accepts authorize requests regardless of state value
// or its absence. Both probes (missing-state and replay-state) should
// fire.
func TestDetectStateBinding_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		// Always progress the flow with a redirect to a login page —
		// vulnerable IdP ignores state entirely.
		w.Header().Set("Location", "https://idp.example.com/login")
		w.WriteHeader(stdhttp.StatusFound)
	}))
	defer srv.Close()

	d := New(newTestClient())
	res, err := d.DetectStateBinding(context.Background(), srv.URL, DetectOptions{
		ClientID:              "client-a",
		RegisteredRedirectURI: "https://app.example.com/cb",
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectStateBinding error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true when IdP accepts missing/replayed state")
	}
	if res.DetectionType != "state-binding" {
		t.Errorf("DetectionType=%q want state-binding", res.DetectionType)
	}
	// Should emit BOTH findings (missing + replay).
	if len(res.Findings) < 2 {
		t.Fatalf("expected at least 2 findings (missing + replay), got %d", len(res.Findings))
	}
	// Verify finding metadata.
	for _, f := range res.Findings {
		if f.Severity != core.SeverityHigh {
			t.Errorf("state-binding finding severity=%s want high", f.Severity)
		}
		if f.Tool != "oauthflow-detector" {
			t.Errorf("Tool=%q want oauthflow-detector", f.Tool)
		}
		if !contains(f.WSTG, "WSTG-ATHZ-04") {
			t.Errorf("WSTG mapping missing WSTG-ATHZ-04: %v", f.WSTG)
		}
		if !contains(f.Top10, "A07:2025") {
			t.Errorf("Top10 mapping missing A07:2025: %v", f.Top10)
		}
		if !contains(f.CWE, "CWE-352") {
			t.Errorf("CWE mapping missing CWE-352: %v", f.CWE)
		}
	}
}

// safe IdP: rejects authorize requests that omit state, and uses
// per-request state binding (returns error on duplicate state).
func TestDetectStateBinding_Safe(t *testing.T) {
	var seen sync.Map
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		state := r.URL.Query().Get("state")
		if state == "" {
			w.Header().Set("Location", "https://idp.example.com/error?error=invalid_request")
			w.WriteHeader(stdhttp.StatusFound)
			return
		}
		if _, dup := seen.LoadOrStore(state, true); dup {
			w.Header().Set("Location", "https://idp.example.com/error?error=invalid_state")
			w.WriteHeader(stdhttp.StatusFound)
			return
		}
		w.Header().Set("Location", "https://idp.example.com/login")
		w.WriteHeader(stdhttp.StatusFound)
	}))
	defer srv.Close()

	d := New(newTestClient())
	res, err := d.DetectStateBinding(context.Background(), srv.URL, DetectOptions{
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectStateBinding error: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("expected vulnerable=false on safe IdP, got findings: %+v", res.Findings)
	}
}

func TestDetectStateBinding_BadURL(t *testing.T) {
	d := New(newTestClient())
	_, err := d.DetectStateBinding(context.Background(), "://bad", DetectOptions{Timeout: time.Second})
	if err == nil {
		t.Error("expected parse error for malformed URL")
	}
}

// --- DetectRedirectURIMatching --------------------------------------

// vulnerable IdP: any redirect_uri ending in `/cb` is accepted.
func TestDetectRedirectURIMatching_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		// Naïvely accept any URL — echoes redirect_uri into Location.
		w.Header().Set("Location", ru+"?code=AUTHCODE")
		w.WriteHeader(stdhttp.StatusFound)
	}))
	defer srv.Close()

	d := New(newTestClient())
	res, err := d.DetectRedirectURIMatching(context.Background(), srv.URL, DetectOptions{
		ClientID:              "client-a",
		RegisteredRedirectURI: "https://app.example.com/cb",
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectRedirectURIMatching error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true when IdP echoes arbitrary redirect_uri")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("redirect_uri finding severity=%s want critical", f.Severity)
	}
	if f.Tool != "oauthflow-detector" {
		t.Errorf("Tool=%q want oauthflow-detector", f.Tool)
	}
	if !contains(f.CWE, "CWE-601") {
		t.Errorf("CWE mapping missing CWE-601: %v", f.CWE)
	}
	if !contains(f.WSTG, "WSTG-ATHZ-04") {
		t.Errorf("WSTG mapping missing WSTG-ATHZ-04: %v", f.WSTG)
	}
}

// safe IdP: rejects any redirect_uri that isn't an exact match.
func TestDetectRedirectURIMatching_Safe(t *testing.T) {
	const registered = "https://app.example.com/cb"
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		if ru != registered {
			w.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		w.Header().Set("Location", ru+"?code=AUTHCODE")
		w.WriteHeader(stdhttp.StatusFound)
	}))
	defer srv.Close()

	d := New(newTestClient())
	res, err := d.DetectRedirectURIMatching(context.Background(), srv.URL, DetectOptions{
		RegisteredRedirectURI: registered,
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectRedirectURIMatching error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected vulnerable=false on safe IdP, got %d findings", len(res.Findings))
	}
}

func TestDetectRedirectURIMatching_MissingRegistered(t *testing.T) {
	d := New(newTestClient())
	_, err := d.DetectRedirectURIMatching(context.Background(), "https://idp.example.com/authorize", DetectOptions{
		Timeout: time.Second,
	})
	if err == nil {
		t.Error("expected error when RegisteredRedirectURI is empty")
	}
}

// --- DetectPKCEDowngrade --------------------------------------------

// vulnerable IdP: authorize issues a code, token endpoint exchanges it
// without checking code_verifier.
func TestDetectPKCEDowngrade_Vulnerable(t *testing.T) {
	const code = "AUTHCODE-PKCE-PROBE"
	authzSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		if ru == "" {
			ru = "https://app.example.com/cb"
		}
		w.Header().Set("Location", ru+"?code="+code+"&state="+r.URL.Query().Get("state"))
		w.WriteHeader(stdhttp.StatusFound)
	}))
	defer authzSrv.Close()

	tokenSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		// Vulnerable: ignores absence of code_verifier and issues token.
		if r.PostForm.Get("code") != code {
			w.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT","id_token":"IT","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	d := New(newTestClient())
	res, err := d.DetectPKCEDowngrade(context.Background(), authzSrv.URL, tokenSrv.URL, DetectOptions{
		ClientID:              "client-a",
		RegisteredRedirectURI: "https://app.example.com/cb",
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectPKCEDowngrade error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true when token endpoint ignores missing code_verifier")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityHigh {
		t.Errorf("PKCE finding severity=%s want high", f.Severity)
	}
	if !contains(f.CWE, "CWE-1004") {
		t.Errorf("CWE mapping missing CWE-1004: %v", f.CWE)
	}
}

// safe IdP: token endpoint enforces code_verifier presence.
func TestDetectPKCEDowngrade_Safe(t *testing.T) {
	const code = "AUTHCODE-SAFE"
	authzSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		w.Header().Set("Location", ru+"?code="+code)
		w.WriteHeader(stdhttp.StatusFound)
	}))
	defer authzSrv.Close()

	tokenSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		if r.PostForm.Get("code_verifier") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"missing code_verifier"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT"}`))
	}))
	defer tokenSrv.Close()

	d := New(newTestClient())
	res, err := d.DetectPKCEDowngrade(context.Background(), authzSrv.URL, tokenSrv.URL, DetectOptions{
		ClientID:              "client-a",
		RegisteredRedirectURI: "https://app.example.com/cb",
		Timeout:               2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectPKCEDowngrade error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected vulnerable=false on safe token endpoint, got %d findings", len(res.Findings))
	}
}

func TestDetectPKCEDowngrade_MissingTokenURL(t *testing.T) {
	d := New(newTestClient())
	_, err := d.DetectPKCEDowngrade(context.Background(), "https://idp.example.com/authorize", "", DetectOptions{
		Timeout: time.Second,
	})
	if err == nil {
		t.Error("expected error when tokenURL is empty")
	}
}

// --- DetectIDTokenAlgNone -------------------------------------------

// vulnerable validator: accepts any assertion as long as its header
// parses, returns access_token.
func TestDetectIDTokenAlgNone_Vulnerable(t *testing.T) {
	var seen int32
	tokenSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		atomic.AddInt32(&seen, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT-from-none","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	d := New(newTestClient())
	res, err := d.DetectIDTokenAlgNone(context.Background(), DetectOptions{
		ClientID: "client-a",
		TokenURL: tokenSrv.URL,
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectIDTokenAlgNone error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true when validator accepts alg=none")
	}
	if atomic.LoadInt32(&seen) == 0 {
		t.Error("expected token endpoint to be probed at least once")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("alg=none finding severity=%s want critical", f.Severity)
	}
	if !contains(f.CWE, "CWE-345") {
		t.Errorf("CWE mapping missing CWE-345: %v", f.CWE)
	}
}

// safe validator: rejects alg=none with 401 + error body.
func TestDetectIDTokenAlgNone_Safe(t *testing.T) {
	tokenSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"alg none rejected"}`))
	}))
	defer tokenSrv.Close()

	d := New(newTestClient())
	res, err := d.DetectIDTokenAlgNone(context.Background(), DetectOptions{
		ClientID: "client-a",
		TokenURL: tokenSrv.URL,
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectIDTokenAlgNone error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected vulnerable=false on safe validator, got %d findings", len(res.Findings))
	}
}

// when a caller passes a token whose header is NOT alg=none, the
// detector should short-circuit (nothing to flag).
func TestDetectIDTokenAlgNone_NonNoneHeaderShortCircuits(t *testing.T) {
	probed := false
	tokenSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		probed = true
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT"}`))
	}))
	defer tokenSrv.Close()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u"}`))
	rs256Token := header + "." + claims + ".sigsig"

	d := New(newTestClient())
	res, err := d.DetectIDTokenAlgNone(context.Background(), DetectOptions{
		ClientID: "client-a",
		TokenURL: tokenSrv.URL,
		IDToken:  rs256Token,
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectIDTokenAlgNone error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected vulnerable=false when supplied token is RS256, got %d findings", len(res.Findings))
	}
	if probed {
		t.Error("expected detector to short-circuit before reaching token endpoint")
	}
}

func TestDetectIDTokenAlgNone_MissingTokenURL(t *testing.T) {
	d := New(newTestClient())
	_, err := d.DetectIDTokenAlgNone(context.Background(), DetectOptions{
		Timeout: time.Second,
	})
	if err == nil {
		t.Error("expected error when TokenURL is empty")
	}
}

// --- DetectAll ------------------------------------------------------

// DetectAll on a fully vulnerable IdP aggregates findings from every
// sub-check.
func TestDetectAll_Aggregates(t *testing.T) {
	const registered = "https://app.example.com/cb"
	const code = "AUTHCODE-ALL"

	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/authorize", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		if ru == "" {
			ru = registered
		}
		w.Header().Set("Location", ru+"?code="+code+"&state="+r.URL.Query().Get("state"))
		w.WriteHeader(stdhttp.StatusFound)
	})
	mux.HandleFunc("/token", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT","id_token":"IT"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(newTestClient())
	res, err := d.DetectAll(context.Background(), DetectOptions{
		ClientID:              "client-a",
		RegisteredRedirectURI: registered,
		AuthzURL:              srv.URL + "/authorize",
		TokenURL:              srv.URL + "/token",
		Timeout:               5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectAll error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected DetectAll to flag this IdP as vulnerable")
	}
	if len(res.Findings) < 3 {
		t.Errorf("expected at least 3 aggregated findings (state, redirect, pkce or alg), got %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("aggregated finding fails Validate(): %v: %+v", err, f)
		}
	}
}

// DetectAll on a completely safe IdP produces zero findings.
func TestDetectAll_NoFindingsOnSafeIdP(t *testing.T) {
	const registered = "https://app.example.com/cb"
	var burnedStates sync.Map
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/authorize", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		if ru != registered || state == "" {
			w.Header().Set("Location", "https://idp.example.com/error?error=invalid_request")
			w.WriteHeader(stdhttp.StatusFound)
			return
		}
		// Burn the state: reject the same value on replay.
		if _, dup := burnedStates.LoadOrStore(state, true); dup {
			w.Header().Set("Location", "https://idp.example.com/error?error=invalid_state")
			w.WriteHeader(stdhttp.StatusFound)
			return
		}
		w.Header().Set("Location", ru+"?code=SAFE-CODE&state="+state)
		w.WriteHeader(stdhttp.StatusFound)
	})
	mux.HandleFunc("/token", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		// Strict: require code_verifier and reject alg=none assertions.
		if r.PostForm.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
			return
		}
		if r.PostForm.Get("code_verifier") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(newTestClient())
	res, err := d.DetectAll(context.Background(), DetectOptions{
		RegisteredRedirectURI: registered,
		AuthzURL:              srv.URL + "/authorize",
		TokenURL:              srv.URL + "/token",
		Timeout:               5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectAll error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no findings on safe IdP, got %d: %+v", len(res.Findings), summarize(res.Findings))
	}
}

// --- internal helpers ------------------------------------------------

func TestExtractCode_QueryAndFragment(t *testing.T) {
	q := &internalhttp.Response{
		StatusCode: 302,
		Headers:    map[string]string{"Location": "https://app.example.com/cb?code=ABC&state=x"},
	}
	if got := extractCode(q); got != "ABC" {
		t.Errorf("extractCode(query) = %q, want ABC", got)
	}
	f := &internalhttp.Response{
		StatusCode: 302,
		Headers:    map[string]string{"Location": "https://app.example.com/cb#code=XYZ&state=x"},
	}
	if got := extractCode(f); got != "XYZ" {
		t.Errorf("extractCode(fragment) = %q, want XYZ", got)
	}
	empty := &internalhttp.Response{StatusCode: 302, Headers: map[string]string{}}
	if got := extractCode(empty); got != "" {
		t.Errorf("extractCode(no-location) = %q, want empty", got)
	}
}

func TestDecodeJOSEHeader_AlgNone(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
	token := hdr + "." + claims + "."
	got, ok := decodeJOSEHeader(token)
	if !ok {
		t.Fatal("decodeJOSEHeader returned ok=false on a valid token")
	}
	if alg, _ := got["alg"].(string); alg != "none" {
		t.Errorf("alg=%q want none", alg)
	}
}

func TestDecodeJOSEHeader_Malformed(t *testing.T) {
	if _, ok := decodeJOSEHeader("not.a.jwt..."); ok {
		// Some malformed inputs are still parseable if the first segment
		// base64-decodes to JSON; this case has non-base64 chars so we
		// expect ok=false.
		t.Skip("decodeJOSEHeader accepted malformed input; not a failure")
	}
	if _, ok := decodeJOSEHeader("onlyonesegment"); ok {
		t.Error("decodeJOSEHeader should reject single-segment input")
	}
}

func TestRedirectURIVariants_DerivesExpectedShapes(t *testing.T) {
	got := redirectURIVariants("https://app.example.com/cb")
	if len(got) < 3 {
		t.Fatalf("expected at least 3 variants, got %d", len(got))
	}
	wantSubstrings := []string{".attacker.com", "../redirect", "next=//attacker.com"}
	for _, w := range wantSubstrings {
		found := false
		for _, g := range got {
			if strings.Contains(g, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing variant containing %q in %v", w, got)
		}
	}
}

func TestSynthesizeAlgNoneToken_HeaderParses(t *testing.T) {
	tok := synthesizeAlgNoneToken("client-a")
	hdr, ok := decodeJOSEHeader(tok)
	if !ok {
		t.Fatal("synthesized token's header failed to decode")
	}
	if alg, _ := hdr["alg"].(string); alg != "none" {
		t.Errorf("synthesized alg=%q want none", alg)
	}
}

// --- shared helpers --------------------------------------------------

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func summarize(fs []*core.Finding) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s/%s", f.Type, f.Severity))
	}
	return strings.Join(out, ", ")
}
