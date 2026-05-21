package sessionlifecycle

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

// refreshBody is the minimal refresh body.
type refreshBody struct {
	RefreshToken string `json:"refresh_token"`
}

const (
	testUser = "alice"
	testPass = "s3cret"
)

// ---------- helpers ----------

func decodeJSON(t *testing.T, body string, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(strings.NewReader(body)).Decode(v); err != nil {
		t.Fatalf("decode json: %v\nbody=%s", err, body)
	}
}

// writeJSON writes a JSON response. Errors are intentionally ignored for tests.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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

// ---------- DetectRefreshRotation ----------

// vulnerableNoRotationServer issues fixed access+refresh tokens and never
// rotates them. Expected result: High severity (neither rotates).
func vulnerableNoRotationServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  "A-fixed",
			"refresh_token": "R-fixed",
		})
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		var b refreshBody
		decode(r, &b)
		// returns the same tokens, ignoring the input
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  "A-fixed",
			"refresh_token": "R-fixed",
		})
	})
	return httptest.NewServer(mux)
}

// partialRotationServer rotates the access token but not the refresh token.
// Expected: Medium severity (refresh-token reuse).
func partialRotationServer() *httptest.Server {
	mux := http.NewServeMux()
	var n int32
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  fmt.Sprintf("A-%d", atomic.AddInt32(&n, 1)),
			"refresh_token": "R-static",
		})
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		var b refreshBody
		decode(r, &b)
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  fmt.Sprintf("A-%d", atomic.AddInt32(&n, 1)),
			"refresh_token": "R-static", // not rotated
		})
	})
	return httptest.NewServer(mux)
}

// safeRotationServer rotates both tokens on each refresh.
func safeRotationServer() *httptest.Server {
	mux := http.NewServeMux()
	var n int32
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		i := atomic.AddInt32(&n, 1)
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  fmt.Sprintf("A-login-%d", i),
			"refresh_token": fmt.Sprintf("R-login-%d", i),
		})
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		var b refreshBody
		decode(r, &b)
		i := atomic.AddInt32(&n, 1)
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  fmt.Sprintf("A-ref-%d", i),
			"refresh_token": fmt.Sprintf("R-ref-%d", i),
		})
	})
	return httptest.NewServer(mux)
}

func decode(r *http.Request, v interface{}) {
	_ = json.NewDecoder(r.Body).Decode(v)
}

func TestDetectRefreshRotation_NoRotation_High(t *testing.T) {
	srv := vulnerableNoRotationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectRefreshRotation(context.Background(), DetectOptions{
		LoginURL:   srv.URL + "/login",
		RefreshURL: srv.URL + "/refresh",
		Username:   testUser,
		Password:   testPass,
	})
	if err != nil {
		t.Fatalf("DetectRefreshRotation: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Type != "Refresh Token Not Rotated" {
		t.Errorf("type = %q, want %q", f.Type, "Refresh Token Not Rotated")
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want %s", f.Severity, core.SeverityHigh)
	}
	if f.Tool != "sessionlifecycle-detector" {
		t.Errorf("tool = %q, want sessionlifecycle-detector", f.Tool)
	}
	if len(f.WSTG) == 0 || len(f.CWE) == 0 || len(f.Top10) == 0 {
		t.Error("expected OWASP mappings")
	}
}

func TestDetectRefreshRotation_RefreshOnlyReuse_Medium(t *testing.T) {
	srv := partialRotationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectRefreshRotation(context.Background(), DetectOptions{
		LoginURL:   srv.URL + "/login",
		RefreshURL: srv.URL + "/refresh",
		Username:   testUser,
		Password:   testPass,
	})
	if err != nil {
		t.Fatalf("DetectRefreshRotation: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	if res.Findings[0].Severity != core.SeverityMedium {
		t.Errorf("severity = %s, want medium", res.Findings[0].Severity)
	}
}

func TestDetectRefreshRotation_Safe(t *testing.T) {
	srv := safeRotationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectRefreshRotation(context.Background(), DetectOptions{
		LoginURL:   srv.URL + "/login",
		RefreshURL: srv.URL + "/refresh",
		Username:   testUser,
		Password:   testPass,
	})
	if err != nil {
		t.Fatalf("DetectRefreshRotation: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("did not expect vulnerable result, got %d findings", len(res.Findings))
	}
}

func TestDetectRefreshRotation_LoginFails(t *testing.T) {
	srv := vulnerableNoRotationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	_, err := d.DetectRefreshRotation(context.Background(), DetectOptions{
		LoginURL:   srv.URL + "/login",
		RefreshURL: srv.URL + "/refresh",
		Username:   "wrong",
		Password:   "wrong",
	})
	if err == nil {
		t.Error("expected error when login fails")
	}
}

// ---------- DetectStaleTokenAfterLogout ----------

// vulnerableLogoutServer leaves the access token valid after /logout.
func vulnerableLogoutServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  "live-token-vuln",
			"refresh_token": "live-refresh",
		})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// Pretend to log out but never invalidate.
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer live-token-vuln" {
			writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no auth"})
	})
	return httptest.NewServer(mux)
}

// safeLogoutServer revokes the token on /logout.
func safeLogoutServer() *httptest.Server {
	var (
		mu      sync.Mutex
		revoked = map[string]bool{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  "live-token-safe",
			"refresh_token": "live-refresh",
		})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		revoked[tok] = true
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		dead := revoked[tok]
		mu.Unlock()
		if dead || tok == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "revoked"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
	})
	return httptest.NewServer(mux)
}

func TestDetectStaleTokenAfterLogout_Vulnerable(t *testing.T) {
	srv := vulnerableLogoutServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectStaleTokenAfterLogout(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		LogoutURL:    srv.URL + "/logout",
		ProtectedURL: srv.URL + "/me",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectStaleTokenAfterLogout: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	f := res.Findings[0]
	if f.Type != "Session Not Invalidated After Logout" {
		t.Errorf("type = %q", f.Type)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
}

func TestDetectStaleTokenAfterLogout_Safe(t *testing.T) {
	srv := safeLogoutServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectStaleTokenAfterLogout(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		LogoutURL:    srv.URL + "/logout",
		ProtectedURL: srv.URL + "/me",
		Username:     testUser,
		Password:     testPass,
	})
	if err != nil {
		t.Fatalf("DetectStaleTokenAfterLogout: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("did not expect vulnerable result")
	}
}

// ---------- DetectConcurrentSessions ----------

// concurrentBothValidServer always honors any issued token (vulnerable when
// single-session is required).
func concurrentBothValidServer() *httptest.Server {
	var n int32
	var (
		mu     sync.Mutex
		issued = map[string]bool{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		tok := fmt.Sprintf("tok-%d", atomic.AddInt32(&n, 1))
		mu.Lock()
		issued[tok] = true
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  tok,
			"refresh_token": "r-" + tok,
		})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		ok := issued[tok]
		mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
	})
	return httptest.NewServer(mux)
}

// singleSessionServer invalidates the previous token on a new login.
func singleSessionServer() *httptest.Server {
	var n int32
	var (
		mu     sync.Mutex
		active = map[string]bool{} // username -> token
	)
	currentToken := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		tok := fmt.Sprintf("tok-%d", atomic.AddInt32(&n, 1))
		mu.Lock()
		// invalidate previous
		if currentToken != "" {
			active[currentToken] = false
		}
		currentToken = tok
		active[tok] = true
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  tok,
			"refresh_token": "r-" + tok,
		})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		ok := active[tok]
		mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "expired"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
	})
	return httptest.NewServer(mux)
}

func TestDetectConcurrentSessions_SingleRequired_Vulnerable(t *testing.T) {
	srv := concurrentBothValidServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectConcurrentSessions(context.Background(), DetectOptions{
		LoginURL:              srv.URL + "/login",
		ProtectedURL:          srv.URL + "/me",
		Username:              testUser,
		Password:              testPass,
		SingleSessionRequired: true,
	})
	if err != nil {
		t.Fatalf("DetectConcurrentSessions: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	f := res.Findings[0]
	if f.Type != "Concurrent Sessions Permitted" {
		t.Errorf("type = %q", f.Type)
	}
	if f.Severity != core.SeverityLow {
		t.Errorf("severity = %s, want low", f.Severity)
	}
}

func TestDetectConcurrentSessions_SingleRequired_Safe(t *testing.T) {
	srv := singleSessionServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectConcurrentSessions(context.Background(), DetectOptions{
		LoginURL:              srv.URL + "/login",
		ProtectedURL:          srv.URL + "/me",
		Username:              testUser,
		Password:              testPass,
		SingleSessionRequired: true,
	})
	if err != nil {
		t.Fatalf("DetectConcurrentSessions: %v", err)
	}
	if res.Vulnerable {
		t.Error("did not expect vulnerable result; first session was invalidated")
	}
}

func TestDetectConcurrentSessions_MultiAllowed_NoFinding(t *testing.T) {
	srv := concurrentBothValidServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectConcurrentSessions(context.Background(), DetectOptions{
		LoginURL:              srv.URL + "/login",
		ProtectedURL:          srv.URL + "/me",
		Username:              testUser,
		Password:              testPass,
		SingleSessionRequired: false,
	})
	if err != nil {
		t.Fatalf("DetectConcurrentSessions: %v", err)
	}
	if res.Vulnerable {
		t.Error("did not expect vulnerable when SingleSessionRequired=false")
	}
}

// ---------- DetectAll ----------

func TestDetectAll_AggregatesFindings(t *testing.T) {
	// Compose a fully-vulnerable server that exercises all three checks.
	var n int32
	var (
		mu     sync.Mutex
		issued = map[string]bool{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var c loginCreds
		decode(r, &c)
		if c.Username != testUser || c.Password != testPass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
			return
		}
		// Hand out a fixed token + fixed refresh => triggers refresh-rotation
		// finding (High) and concurrent-session finding (Low).
		tok := fmt.Sprintf("tok-%d", atomic.AddInt32(&n, 1))
		mu.Lock()
		issued[tok] = true
		issued["live-fixed"] = true
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  "live-fixed",
			"refresh_token": "R-fixed",
		})
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  "live-fixed",
			"refresh_token": "R-fixed",
		})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		ok := issued[tok]
		mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"user": testUser})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectAll(context.Background(), DetectOptions{
		LoginURL:              srv.URL + "/login",
		RefreshURL:            srv.URL + "/refresh",
		LogoutURL:             srv.URL + "/logout",
		ProtectedURL:          srv.URL + "/me",
		Username:              testUser,
		Password:              testPass,
		SingleSessionRequired: true,
	})
	if err != nil {
		t.Fatalf("DetectAll: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result from DetectAll")
	}
	// Expect three findings of distinct types.
	types := map[string]bool{}
	for _, f := range res.Findings {
		types[f.Type] = true
	}
	for _, want := range []string{
		"Refresh Token Not Rotated",
		"Session Not Invalidated After Logout",
		"Concurrent Sessions Permitted",
	} {
		if !types[want] {
			t.Errorf("DetectAll missing finding type %q (got %v)", want, types)
		}
	}
}

// ---------- Context cancellation ----------

func TestDetectRefreshRotation_ContextCancelled(t *testing.T) {
	srv := vulnerableNoRotationServer()
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := New(internalhttp.NewClient())
	_, err := d.DetectRefreshRotation(ctx, DetectOptions{
		LoginURL:   srv.URL + "/login",
		RefreshURL: srv.URL + "/refresh",
		Username:   testUser,
		Password:   testPass,
	})
	if err == nil {
		t.Error("expected error on cancelled context")
	}
}

// ---------- option carrying ----------

func TestDetectOptions_TimeoutCarried(t *testing.T) {
	// Smoke test: zero-value Timeout is acceptable in DetectOptions.
	opts := DetectOptions{Timeout: 0}
	if opts.Timeout != 0 {
		t.Errorf("Timeout = %v, want 0", opts.Timeout)
	}
	// Non-zero timeout also accepted.
	opts.Timeout = 5 * time.Second
	if opts.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", opts.Timeout)
	}
}

// ensure decodeJSON helper compiles
var _ = decodeJSON
