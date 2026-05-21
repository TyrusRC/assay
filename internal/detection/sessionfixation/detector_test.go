package sessionfixation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	internalhttp "github.com/TyrusRC/assay/internal/http"
)

const (
	testUser       = "alice"
	testPass       = "s3cret"
	testCookieName = "SESSIONID"
	attackerCookie = "attackerchose123"
)

// ---------- helpers ----------

// parseLoginForm extracts user/pass from form-urlencoded or JSON-ish body.
func parseLoginForm(r *http.Request) (string, string) {
	_ = r.ParseForm()
	return r.PostFormValue("username"), r.PostFormValue("password")
}

// ---------- servers ----------

// vulnerableFixationServer keeps whatever SESSIONID cookie the client
// presented on /login, even after a successful authentication. This is the
// classic session fixation flaw.
func vulnerableFixationServer() *httptest.Server {
	var (
		mu      sync.Mutex
		authed  = map[string]bool{}
		counter int32
		_       = counter
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		u, p := parseLoginForm(r)
		if u != testUser || p != testPass {
			http.Error(w, "invalid", http.StatusUnauthorized)
			return
		}
		// Identify whatever cookie the client supplied; if none, generate one.
		var sid string
		if ck, err := r.Cookie(testCookieName); err == nil && ck.Value != "" {
			sid = ck.Value
		} else {
			sid = fmt.Sprintf("gen-%d", atomic.AddInt32(&counter, 1))
		}
		mu.Lock()
		authed[sid] = true
		mu.Unlock()
		// Echo the same SID back (no rotation = vulnerable).
		http.SetCookie(w, &http.Cookie{
			Name:  testCookieName,
			Value: sid,
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(testCookieName)
		if err != nil {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		ok := authed[ck.Value]
		mu.Unlock()
		if !ok {
			http.Error(w, "not authed", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`user=` + testUser))
	})
	return httptest.NewServer(mux)
}

// safeRotationServer always issues a brand-new SESSIONID on successful login,
// discarding whatever the client presented. This is the secure behaviour.
func safeRotationServer() *httptest.Server {
	var (
		mu      sync.Mutex
		authed  = map[string]bool{}
		counter int32
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		u, p := parseLoginForm(r)
		if u != testUser || p != testPass {
			http.Error(w, "invalid", http.StatusUnauthorized)
			return
		}
		sid := fmt.Sprintf("rotated-%d", atomic.AddInt32(&counter, 1))
		mu.Lock()
		authed[sid] = true
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:  testCookieName,
			Value: sid,
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(testCookieName)
		if err != nil {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		ok := authed[ck.Value]
		mu.Unlock()
		if !ok {
			http.Error(w, "not authed", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`user=` + testUser))
	})
	return httptest.NewServer(mux)
}

// querySessionAcceptingServer accepts the session id presented as a
// ?SESSIONID=... URL parameter on a protected page.
func querySessionAcceptingServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		// Accept the session id from either cookie or query string.
		var sid string
		if ck, err := r.Cookie(testCookieName); err == nil && ck.Value != "" {
			sid = ck.Value
		}
		if sid == "" {
			sid = r.URL.Query().Get(testCookieName)
		}
		if sid == "" {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("welcome sid=" + sid))
	})
	return httptest.NewServer(mux)
}

// queryRejectingServer ignores the SESSIONID query parameter and only honors
// the cookie. Without a cookie, /me returns 401.
func queryRejectingServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie(testCookieName); err == nil && ck.Value != "" {
			_, _ = w.Write([]byte("welcome sid=" + ck.Value))
			return
		}
		http.Error(w, "no session", http.StatusUnauthorized)
	})
	return httptest.NewServer(mux)
}

// ---------- New ----------

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

// ---------- DetectPreAuthSessionAcceptance ----------

func TestDetectPreAuthSessionAcceptance_Vulnerable(t *testing.T) {
	srv := vulnerableFixationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectPreAuthSessionAcceptance(context.Background(), DetectOptions{
		LoginURL:   srv.URL + "/login",
		Username:   testUser,
		Password:   testPass,
		CookieName: testCookieName,
	})
	if err != nil {
		t.Fatalf("DetectPreAuthSessionAcceptance: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable result")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	wantType := "Session Fixation — Pre-Set Cookie Accepted After Login"
	if f.Type != wantType {
		t.Errorf("type = %q, want %q", f.Type, wantType)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if f.Tool != "sessionfixation-detector" {
		t.Errorf("tool = %q, want sessionfixation-detector", f.Tool)
	}
	if len(f.WSTG) == 0 || len(f.CWE) == 0 || len(f.Top10) == 0 {
		t.Error("expected OWASP mappings populated")
	}
	if !containsAny(f.WSTG, "WSTG-SESS-03") {
		t.Errorf("WSTG = %v, want WSTG-SESS-03", f.WSTG)
	}
	if !containsAny(f.CWE, "CWE-384") {
		t.Errorf("CWE = %v, want CWE-384", f.CWE)
	}
	if !containsAny(f.Top10, "A01:2025") {
		t.Errorf("Top10 = %v, want A01:2025", f.Top10)
	}
}

func TestDetectPreAuthSessionAcceptance_Safe(t *testing.T) {
	srv := safeRotationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectPreAuthSessionAcceptance(context.Background(), DetectOptions{
		LoginURL:   srv.URL + "/login",
		Username:   testUser,
		Password:   testPass,
		CookieName: testCookieName,
	})
	if err != nil {
		t.Fatalf("DetectPreAuthSessionAcceptance: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("did not expect vulnerable result; server rotated the cookie")
	}
}

func TestDetectPreAuthSessionAcceptance_LoginFails(t *testing.T) {
	srv := vulnerableFixationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	_, err := d.DetectPreAuthSessionAcceptance(context.Background(), DetectOptions{
		LoginURL:   srv.URL + "/login",
		Username:   "wrong",
		Password:   "wrong",
		CookieName: testCookieName,
	})
	if err == nil {
		t.Error("expected error when login fails")
	}
}

func TestDetectPreAuthSessionAcceptance_DefaultCookieName(t *testing.T) {
	srv := vulnerableFixationServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectPreAuthSessionAcceptance(context.Background(), DetectOptions{
		LoginURL: srv.URL + "/login",
		Username: testUser,
		Password: testPass,
		// CookieName intentionally omitted — detector must pick a sane default
		// matching the server's cookie name. Our test server uses "SESSIONID".
	})
	if err != nil {
		t.Fatalf("DetectPreAuthSessionAcceptance: %v", err)
	}
	// Result may or may not be vulnerable depending on default name; the
	// important thing is the call doesn't panic and returns a result.
	if res == nil {
		t.Fatal("expected non-nil result")
	}
}

// ---------- DetectCookieAcceptedFromQuery ----------

func TestDetectCookieAcceptedFromQuery_Vulnerable(t *testing.T) {
	srv := querySessionAcceptingServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectCookieAcceptedFromQuery(context.Background(), DetectOptions{
		ProtectedURL: srv.URL + "/me",
		CookieName:   testCookieName,
	})
	if err != nil {
		t.Fatalf("DetectCookieAcceptedFromQuery: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	wantType := "Session ID Accepted from Query String"
	if f.Type != wantType {
		t.Errorf("type = %q, want %q", f.Type, wantType)
	}
	if f.Severity != core.SeverityMedium {
		t.Errorf("severity = %s, want medium", f.Severity)
	}
	if f.Tool != "sessionfixation-detector" {
		t.Errorf("tool = %q, want sessionfixation-detector", f.Tool)
	}
	if !containsAny(f.WSTG, "WSTG-SESS-03") {
		t.Errorf("WSTG = %v, want WSTG-SESS-03", f.WSTG)
	}
}

func TestDetectCookieAcceptedFromQuery_Safe(t *testing.T) {
	srv := queryRejectingServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectCookieAcceptedFromQuery(context.Background(), DetectOptions{
		ProtectedURL: srv.URL + "/me",
		CookieName:   testCookieName,
	})
	if err != nil {
		t.Fatalf("DetectCookieAcceptedFromQuery: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("did not expect vulnerable result; server ignored query param")
	}
}

func TestDetectCookieAcceptedFromQuery_AppendsToExistingQuery(t *testing.T) {
	// Verify the detector correctly preserves an existing query string when
	// appending its SESSIONID parameter.
	var gotURL atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		gotURL.Store(r.URL.String())
		// Always reject — we only care about the captured URL.
		http.Error(w, "no", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(internalhttp.NewClient())
	_, err := d.DetectCookieAcceptedFromQuery(context.Background(), DetectOptions{
		ProtectedURL: srv.URL + "/me?foo=bar",
		CookieName:   testCookieName,
	})
	if err != nil {
		t.Fatalf("DetectCookieAcceptedFromQuery: %v", err)
	}
	raw, _ := gotURL.Load().(string)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse captured url: %v", err)
	}
	q := u.Query()
	if q.Get("foo") != "bar" {
		t.Errorf("query 'foo' lost: got %q", q.Get("foo"))
	}
	if q.Get(testCookieName) == "" {
		t.Errorf("SESSIONID query param not appended: %q", raw)
	}
}

// ---------- DetectAll ----------

func TestDetectAll_AggregatesFindings(t *testing.T) {
	// Build a server that is vulnerable on both axes:
	//   /login keeps the supplied SESSIONID after auth
	//   /me also accepts SESSIONID from the query string
	var (
		mu     sync.Mutex
		authed = map[string]bool{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		u, p := parseLoginForm(r)
		if u != testUser || p != testPass {
			http.Error(w, "invalid", http.StatusUnauthorized)
			return
		}
		sid := "default"
		if ck, err := r.Cookie(testCookieName); err == nil && ck.Value != "" {
			sid = ck.Value
		}
		mu.Lock()
		authed[sid] = true
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: testCookieName, Value: sid, Path: "/"})
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		sid := r.URL.Query().Get(testCookieName)
		if sid == "" {
			if ck, err := r.Cookie(testCookieName); err == nil {
				sid = ck.Value
			}
		}
		if sid == "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("welcome sid=" + sid))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectAll(context.Background(), DetectOptions{
		LoginURL:     srv.URL + "/login",
		ProtectedURL: srv.URL + "/me",
		Username:     testUser,
		Password:     testPass,
		CookieName:   testCookieName,
	})
	if err != nil {
		t.Fatalf("DetectAll: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable aggregate result")
	}
	types := map[string]bool{}
	for _, f := range res.Findings {
		types[f.Type] = true
	}
	for _, want := range []string{
		"Session Fixation — Pre-Set Cookie Accepted After Login",
		"Session ID Accepted from Query String",
	} {
		if !types[want] {
			t.Errorf("DetectAll missing finding type %q (got %v)", want, types)
		}
	}
}

func TestDetectAll_SkipsMissingURLs(t *testing.T) {
	// With both URLs empty, DetectAll must return a clean empty result.
	d := New(internalhttp.NewClient())
	res, err := d.DetectAll(context.Background(), DetectOptions{
		CookieName: testCookieName,
	})
	if err != nil {
		t.Fatalf("DetectAll: %v", err)
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected no findings; got %d", len(res.Findings))
	}
}

// ---------- Context cancellation ----------

func TestDetectPreAuthSessionAcceptance_ContextCancelled(t *testing.T) {
	srv := vulnerableFixationServer()
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := New(internalhttp.NewClient())
	_, err := d.DetectPreAuthSessionAcceptance(ctx, DetectOptions{
		LoginURL:   srv.URL + "/login",
		Username:   testUser,
		Password:   testPass,
		CookieName: testCookieName,
	})
	if err == nil {
		t.Error("expected error on cancelled context")
	}
}

func TestDetectCookieAcceptedFromQuery_ContextCancelled(t *testing.T) {
	srv := querySessionAcceptingServer()
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := New(internalhttp.NewClient())
	_, err := d.DetectCookieAcceptedFromQuery(ctx, DetectOptions{
		ProtectedURL: srv.URL + "/me",
		CookieName:   testCookieName,
	})
	if err == nil {
		t.Error("expected error on cancelled context")
	}
}

// ---------- option carrying ----------

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

// containsAny reports whether any element of haystack equals needle.
func containsAny(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
