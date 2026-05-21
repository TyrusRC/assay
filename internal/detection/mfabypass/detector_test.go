package mfabypass

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	internalhttp "github.com/TyrusRC/assay/internal/http"
)

// loginCreds is the minimal login body the test servers accept.
type loginCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	testUser = "alice"
	testPass = "s3cret"
	// Cookie names used by the test servers.
	preMFACookie  = "pre_mfa_session"
	mfaDoneCookie = "mfa_verified"
)

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v interface{}) {
	_ = json.NewDecoder(r.Body).Decode(v)
}

// hasCookie returns the value of the named cookie or "" if missing.
func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// ---------- New / options ----------

func TestNew(t *testing.T) {
	c := internalhttp.NewClient()
	d := New(c)
	if d == nil {
		t.Fatal("New() returned nil")
	}
	if d.client != c {
		t.Error("client not stored")
	}
}

func TestDetectOptions_TimeoutCarried(t *testing.T) {
	opts := DetectOptions{Timeout: 0}
	if opts.Timeout != 0 {
		t.Errorf("Timeout = %v, want 0", opts.Timeout)
	}
	opts.Timeout = 5 * time.Second
	if opts.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", opts.Timeout)
	}
}

// ---------- DetectMFAStepSkip ----------

// vulnerableStepSkipServer: the partial-session cookie returned by /login
// is incorrectly honored by the protected endpoint.
func vulnerableStepSkipServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial-XYZ", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE: protected endpoint accepts the pre-MFA cookie.
		if cookieValue(r, preMFACookie) != "" {
			writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no auth"})
	})
	return httptest.NewServer(mux)
}

// safeStepSkipServer: protected endpoint only honors a fully-authenticated
// (post-MFA) cookie.
func safeStepSkipServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial-XYZ", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if cookieValue(r, mfaDoneCookie) == "true" {
			writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "mfa required"})
	})
	return httptest.NewServer(mux)
}

func TestDetectMFAStepSkip_Vulnerable(t *testing.T) {
	srv := vulnerableStepSkipServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFAStepSkip(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		ProtectedURL: srv.URL + "/me",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectMFAStepSkip: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Type != typeStepSkip {
		t.Errorf("type = %q, want %q", f.Type, typeStepSkip)
	}
	if f.Severity != core.SeverityCritical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
	if f.Tool != toolName {
		t.Errorf("tool = %q, want %q", f.Tool, toolName)
	}
	if len(f.WSTG) == 0 || len(f.CWE) == 0 || len(f.Top10) == 0 {
		t.Error("expected OWASP mappings populated")
	}
}

func TestDetectMFAStepSkip_Safe(t *testing.T) {
	srv := safeStepSkipServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFAStepSkip(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		ProtectedURL: srv.URL + "/me",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectMFAStepSkip: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("did not expect vulnerable result, got %d findings", len(res.Findings))
	}
}

func TestDetectMFAStepSkip_LoginFails(t *testing.T) {
	srv := vulnerableStepSkipServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	_, err := d.DetectMFAStepSkip(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		ProtectedURL: srv.URL + "/me",
		Username:     "wrong",
		Password:     "wrong",
	})
	if err == nil {
		t.Error("expected error when login fails")
	}
}

// ---------- DetectMFANullValue ----------

// vulnerableNullValueServer accepts empty / zero / null OTP submissions.
func vulnerableNullValueServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		// Buggy validation: accept anything when otp is empty or "0" or null.
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		// `raw["otp"]` may be missing, nil, "", "0", or a real OTP.
		v, present := raw["otp"]
		if !present || v == nil {
			writeJSON(w, http.StatusOK, map[string]string{"verified": "true"})
			return
		}
		if s, ok := v.(string); ok && (s == "" || s == "0") {
			writeJSON(w, http.StatusOK, map[string]string{"verified": "true"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad otp"})
	})
	return httptest.NewServer(mux)
}

// safeNullValueServer rejects any OTP except a fixed legitimate value.
func safeNullValueServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		v, ok := raw["otp"].(string)
		if !ok || len(v) != 6 || v == "" || v == "000000" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad otp"})
			return
		}
		if v != "123456" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad otp"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"verified": "true"})
	})
	return httptest.NewServer(mux)
}

func TestDetectMFANullValue_Vulnerable(t *testing.T) {
	srv := vulnerableNullValueServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFANullValue(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		MFASubmitURL: srv.URL + "/mfa",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectMFANullValue: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	f := res.Findings[0]
	if f.Type != typeNullValue {
		t.Errorf("type = %q, want %q", f.Type, typeNullValue)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
}

func TestDetectMFANullValue_Safe(t *testing.T) {
	srv := safeNullValueServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFANullValue(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		MFASubmitURL: srv.URL + "/mfa",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectMFANullValue: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("did not expect vulnerable result, got %d findings", len(res.Findings))
	}
}

// ---------- DetectMFABruteForce ----------

// noLimitServer always responds 401 to bad OTPs; never emits 429 or
// lockout language. This is the brute-forceable scenario.
func noLimitServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad otp"})
	})
	return httptest.NewServer(mux)
}

// rateLimitedServer emits a 429 after the 5th failure.
func rateLimitedServer() *httptest.Server {
	var n int32
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt32(&n, 1)
		if i > 5 {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad otp"})
	})
	return httptest.NewServer(mux)
}

// lockoutServer flips to a "locked" 401 body after 5 attempts.
func lockoutServer() *httptest.Server {
	var n int32
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt32(&n, 1)
		if i > 5 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "account locked"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad otp"})
	})
	return httptest.NewServer(mux)
}

func TestDetectMFABruteForce_Vulnerable(t *testing.T) {
	srv := noLimitServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFABruteForce(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		MFASubmitURL: srv.URL + "/mfa",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectMFABruteForce: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	f := res.Findings[0]
	if f.Type != typeBruteForce {
		t.Errorf("type = %q, want %q", f.Type, typeBruteForce)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	// Confirm CWE-307 is wired up.
	foundCWE := false
	for _, c := range f.CWE {
		if c == "CWE-307" {
			foundCWE = true
		}
	}
	if !foundCWE {
		t.Errorf("expected CWE-307 in finding, got %v", f.CWE)
	}
}

func TestDetectMFABruteForce_RateLimited_Safe(t *testing.T) {
	srv := rateLimitedServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFABruteForce(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		MFASubmitURL: srv.URL + "/mfa",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectMFABruteForce: %v", err)
	}
	if res.Vulnerable {
		t.Error("did not expect vulnerable result; rate limit was emitted")
	}
}

func TestDetectMFABruteForce_Lockout_Safe(t *testing.T) {
	srv := lockoutServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFABruteForce(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		MFASubmitURL: srv.URL + "/mfa",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectMFABruteForce: %v", err)
	}
	if res.Vulnerable {
		t.Error("did not expect vulnerable result; lockout was emitted")
	}
}

// ---------- DetectMFAResponseManipulation ----------

// vulnerableFlipServer issues a `mfa_verified=false` cookie on /mfa and
// then trusts whatever the client sends back.
func vulnerableFlipServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		// Issue a false verification cookie regardless of input.
		http.SetCookie(w, &http.Cookie{Name: mfaDoneCookie, Value: "false", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"verified": "false"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE: trust the client-supplied verification cookie.
		if cookieValue(r, mfaDoneCookie) == "true" {
			writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no mfa"})
	})
	return httptest.NewServer(mux)
}

// safeFlipServer issues the cookie but the protected resource derives
// verification from a server-side store, not the cookie value.
func safeFlipServer() *httptest.Server {
	var (
		mu       sync.Mutex
		verified bool
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: mfaDoneCookie, Value: "false", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"verified": "false"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := verified
		mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no mfa"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
	})
	return httptest.NewServer(mux)
}

func TestDetectMFAResponseManipulation_Vulnerable(t *testing.T) {
	srv := vulnerableFlipServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFAResponseManipulation(context.Background(), DetectOptions{
		LoginURL:            srv.URL + "/login",
		MFASubmitURL:        srv.URL + "/mfa",
		ProtectedURL:        srv.URL + "/me",
		Username:            testUser,
		Password:            testPass,
		ResponseFlipPattern: mfaDoneCookie,
	})
	if err != nil {
		t.Fatalf("DetectMFAResponseManipulation: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	f := res.Findings[0]
	if f.Type != typeRespManipulate {
		t.Errorf("type = %q, want %q", f.Type, typeRespManipulate)
	}
	if f.Severity != core.SeverityCritical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
}

func TestDetectMFAResponseManipulation_Safe(t *testing.T) {
	srv := safeFlipServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFAResponseManipulation(context.Background(), DetectOptions{
		LoginURL:            srv.URL + "/login",
		MFASubmitURL:        srv.URL + "/mfa",
		ProtectedURL:        srv.URL + "/me",
		Username:            testUser,
		Password:            testPass,
		ResponseFlipPattern: mfaDoneCookie,
	})
	if err != nil {
		t.Fatalf("DetectMFAResponseManipulation: %v", err)
	}
	if res.Vulnerable {
		t.Error("did not expect vulnerable result; server ignores client cookie value")
	}
}

func TestDetectMFAResponseManipulation_NoPattern_NoOp(t *testing.T) {
	srv := vulnerableFlipServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectMFAResponseManipulation(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		MFASubmitURL: srv.URL + "/mfa",
		ProtectedURL: srv.URL + "/me",
		Username:     testUser,
		Password:     testPass,
		// ResponseFlipPattern intentionally empty.
	})
	if err != nil {
		t.Fatalf("DetectMFAResponseManipulation: %v", err)
	}
	if res.Vulnerable {
		t.Error("did not expect vulnerable result when ResponseFlipPattern is empty")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(res.Findings))
	}
}

// ---------- DetectAll ----------

// TestDetectAll_AggregatesFindings composes a server that is vulnerable to
// every check and verifies that DetectAll produces one finding per type.
func TestDetectAll_AggregatesFindings(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decodeJSON(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, nil)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: preMFACookie, Value: "partial", Path: "/"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_required"})
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		// Accept any OTP (vulnerable to null-value) AND set a flippable
		// verification cookie (vulnerable to response manipulation). No
		// rate limiting (vulnerable to brute-force). However, this same
		// handler is hit by the null-value, brute-force, AND
		// response-manipulation phases — so it must:
		//   - accept null/empty/zero with 200 (for null-value),
		//   - return 401 for other invalid OTPs (so brute-force never sees a 429),
		//   - set mfa_verified=false (for response manipulation).
		http.SetCookie(w, &http.Cookie{Name: mfaDoneCookie, Value: "false", Path: "/"})
		var raw map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&raw)
		v, present := raw["otp"]
		if !present || v == nil {
			writeJSON(w, http.StatusOK, map[string]string{"verified": "false"})
			return
		}
		if s, ok := v.(string); ok && (s == "" || s == "0") {
			writeJSON(w, http.StatusOK, map[string]string{"verified": "false"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad otp"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to step-skip: the pre-MFA cookie alone is enough.
		// Also vulnerable to response manipulation: a true verification
		// cookie also unlocks it.
		if cookieValue(r, preMFACookie) != "" || cookieValue(r, mfaDoneCookie) == "true" {
			writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectAll(context.Background(), DetectOptions{
		LoginURL:            srv.URL + "/login",
		MFASubmitURL:        srv.URL + "/mfa",
		ProtectedURL:        srv.URL + "/me",
		Username:            testUser,
		Password:            testPass,
		ResponseFlipPattern: mfaDoneCookie,
	})
	if err != nil {
		t.Fatalf("DetectAll: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result from DetectAll")
	}
	types := map[string]bool{}
	for _, f := range res.Findings {
		types[f.Type] = true
	}
	for _, want := range []string{
		typeStepSkip,
		typeNullValue,
		typeBruteForce,
		typeRespManipulate,
	} {
		if !types[want] {
			t.Errorf("DetectAll missing finding type %q (got %v)", want, types)
		}
	}
}

// ---------- Context cancellation ----------

func TestDetectMFAStepSkip_ContextCancelled(t *testing.T) {
	srv := vulnerableStepSkipServer()
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := New(internalhttp.NewClient())
	_, err := d.DetectMFAStepSkip(ctx, DetectOptions{
		LoginURL:     srv.URL + "/login",
		ProtectedURL: srv.URL + "/me",
		Username:     testUser,
		Password:     testPass,
	})
	if err == nil {
		t.Error("expected error on cancelled context")
	}
}

// ---------- helper edge cases ----------

func TestFlipVerifiedCookie_Flips(t *testing.T) {
	got, ok := flipVerifiedCookie("mfa_verified=false; Path=/", "mfa_verified")
	if !ok {
		t.Fatal("expected to flip cookie")
	}
	if !strings.Contains(got, "mfa_verified=true") {
		t.Errorf("got %q, want it to contain mfa_verified=true", got)
	}
}

func TestFlipVerifiedCookie_NoMatch(t *testing.T) {
	_, ok := flipVerifiedCookie("other=1; Path=/", "mfa_verified")
	if ok {
		t.Error("expected no flip when pattern does not match")
	}
}

func TestFlipVerifiedCookie_AlreadyTrue(t *testing.T) {
	_, ok := flipVerifiedCookie("mfa_verified=true; Path=/", "mfa_verified")
	if ok {
		t.Error("expected no flip when value is not false/0")
	}
}

func TestIsLockoutResponse(t *testing.T) {
	if !isLockoutResponse("Account locked") {
		t.Error("expected locked to be a lockout response")
	}
	if !isLockoutResponse("Too Many Attempts") {
		t.Error("expected too-many to be a lockout response")
	}
	if isLockoutResponse(`{"error":"bad otp"}`) {
		t.Error("did not expect bad-otp to be a lockout response")
	}
}

// Sanity-check that the bruteForceAttempts constant is the documented 20.
func TestBruteForceAttemptsConst(t *testing.T) {
	if bruteForceAttempts != 20 {
		t.Errorf("bruteForceAttempts = %d, want 20", bruteForceAttempts)
	}
}

// Ensure helpers compile / are referenced (avoid unused-import lint noise
// on testing.T parameter-less helpers).
var _ = fmt.Sprintf
