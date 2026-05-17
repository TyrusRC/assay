package csrf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// --- Test helpers ----------------------------------------------------------

// sessionTokenStore is a tiny in-memory map of session-id -> issued CSRF token.
// Used by the per-session mock server to bind tokens to a cookie value.
type sessionTokenStore struct {
	mu     sync.Mutex
	tokens map[string]string // session-id -> active csrf token
}

func newSessionTokenStore() *sessionTokenStore {
	return &sessionTokenStore{tokens: make(map[string]string)}
}

func (s *sessionTokenStore) issue(sessionID, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[sessionID] = token
}

func (s *sessionTokenStore) accepts(sessionID, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	want, ok := s.tokens[sessionID]
	if !ok {
		return false
	}
	return want == token
}

// extractToken pulls a `csrf_token=<value>` substring out of either form-encoded
// body or JSON body. The mock servers all accept either shape.
func extractToken(body string) string {
	body = strings.TrimSpace(body)
	// JSON form: {"csrf_token":"abc..."}
	if i := strings.Index(body, `"csrf_token"`); i >= 0 {
		rest := body[i+len(`"csrf_token"`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			rest = rest[j+1:]
			if k := strings.Index(rest, `"`); k >= 0 {
				return rest[:k]
			}
		}
	}
	// form-encoded: csrf_token=abc
	if i := strings.Index(body, "csrf_token="); i >= 0 {
		rest := body[i+len("csrf_token="):]
		if j := strings.IndexAny(rest, "&\n\r"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

// --- DetectStateReuseAcrossSteps ------------------------------------------

// TestDetectStateReuseAcrossSteps_FlagsSharedToken builds a 3-step wizard
// where the SAME token is accepted at every step (no rotation). We expect a
// single Medium finding.
func TestDetectStateReuseAcrossSteps_FlagsSharedToken(t *testing.T) {
	const sharedToken = "shared-wizard-token-abc"

	mux := http.NewServeMux()
	mux.HandleFunc("/wizard/step1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"csrf_token":"%s","step":1}`, sharedToken)
	})
	// Step2 and Step3 BOTH accept the original token from step1.
	for _, p := range []string{"/wizard/step2", "/wizard/step3"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			body := readBody(r)
			if extractToken(body) == sharedToken {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectStateReuseAcrossSteps(context.Background(), MultiStepOptions{
		Step1URL: srv.URL + "/wizard/step1",
		Step2URL: srv.URL + "/wizard/step2",
		Step3URL: srv.URL + "/wizard/step3",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectStateReuseAcrossSteps: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for shared wizard token, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "CSRF Token Reused Across Wizard Steps" {
		t.Errorf("unexpected type: %q", f.Type)
	}
	if f.Severity != "medium" {
		t.Errorf("expected medium severity, got %q", f.Severity)
	}
	if f.Tool != "csrf-multistep-detector" {
		t.Errorf("expected csrf-multistep-detector tool, got %q", f.Tool)
	}
	if !containsAll(f.WSTG, "WSTG-SESS-05") || !containsAll(f.CWE, "CWE-352") {
		t.Errorf("missing OWASP / CWE mapping: %+v / %+v", f.WSTG, f.CWE)
	}
}

// TestDetectStateReuseAcrossSteps_NoFindingWhenRotated builds a wizard
// where each step rotates the token; passing an old token to a later step
// is rejected. No finding expected.
func TestDetectStateReuseAcrossSteps_NoFindingWhenRotated(t *testing.T) {
	var (
		mu     sync.Mutex
		issued = map[string]bool{}
		seq    int
	)
	nextToken := func() string {
		mu.Lock()
		defer mu.Unlock()
		seq++
		tok := fmt.Sprintf("tok-%d", seq)
		issued[tok] = true
		return tok
	}
	consume := func(tok string) bool {
		mu.Lock()
		defer mu.Unlock()
		if !issued[tok] {
			return false
		}
		delete(issued, tok) // single-use: rotation enforced
		return true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/wizard/step1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"csrf_token":"%s","step":1}`, nextToken())
	})
	for _, p := range []string{"/wizard/step2", "/wizard/step3"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			tok := extractToken(readBody(r))
			if !consume(tok) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"csrf_token":"%s","ok":true}`, nextToken())
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectStateReuseAcrossSteps(context.Background(), MultiStepOptions{
		Step1URL: srv.URL + "/wizard/step1",
		Step2URL: srv.URL + "/wizard/step2",
		Step3URL: srv.URL + "/wizard/step3",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectStateReuseAcrossSteps: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when token rotates per step, got %d", len(res.Findings))
	}
}

// --- DetectTokenIssuedNRequestsPrior --------------------------------------

// TestDetectTokenIssuedNRequestsPrior_FlagsNoReplayWindow validates the
// "stale token still works" finding when the server never rotates and the
// token has unbounded replay validity.
func TestDetectTokenIssuedNRequestsPrior_FlagsNoReplayWindow(t *testing.T) {
	const staticToken = "static-forever-token"
	mux := http.NewServeMux()
	mux.HandleFunc("/issue", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"csrf_token":"%s"}`, staticToken)
	})
	mux.HandleFunc("/noop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("noop"))
	})
	mux.HandleFunc("/action", func(w http.ResponseWriter, r *http.Request) {
		if extractToken(readBody(r)) == staticToken {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	noops := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		noops = append(noops, srv.URL+"/noop")
	}

	det := New(skwshttp.NewClient())
	res, err := det.DetectTokenIssuedNRequestsPrior(context.Background(), MultiStepOptions{
		Step1URL:      srv.URL + "/issue",
		ActionURL:     srv.URL + "/action",
		UnrelatedURLs: noops,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectTokenIssuedNRequestsPrior: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for stale-token reuse, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "CSRF Token Has No Replay Window Limit" {
		t.Errorf("unexpected type: %q", f.Type)
	}
	if f.Severity != "medium" {
		t.Errorf("expected medium severity, got %q", f.Severity)
	}
	if !containsAll(f.WSTG, "WSTG-SESS-05") || !containsAll(f.CWE, "CWE-352") {
		t.Errorf("missing mappings: %+v / %+v", f.WSTG, f.CWE)
	}
}

// TestDetectTokenIssuedNRequestsPrior_NoFindingWhenRotated covers a server
// that issues a new token on every /issue hit and invalidates old ones.
// Even with N unrelated noops in between, replay should fail and no finding emitted.
func TestDetectTokenIssuedNRequestsPrior_NoFindingWhenRotated(t *testing.T) {
	var (
		mu      sync.Mutex
		current string
	)
	rotate := func() string {
		mu.Lock()
		defer mu.Unlock()
		current = fmt.Sprintf("tok-%d", time.Now().UnixNano())
		return current
	}
	check := func(tok string) bool {
		mu.Lock()
		defer mu.Unlock()
		ok := tok != "" && tok == current
		current = "" // single-use
		return ok
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/issue", func(w http.ResponseWriter, _ *http.Request) {
		tok := rotate()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"csrf_token":"%s"}`, tok)
	})
	// noop also rotates the active token to simulate per-request rotation.
	mux.HandleFunc("/noop", func(w http.ResponseWriter, _ *http.Request) {
		rotate()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("noop"))
	})
	mux.HandleFunc("/action", func(w http.ResponseWriter, r *http.Request) {
		if check(extractToken(readBody(r))) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	noops := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		noops = append(noops, srv.URL+"/noop")
	}

	det := New(skwshttp.NewClient())
	res, err := det.DetectTokenIssuedNRequestsPrior(context.Background(), MultiStepOptions{
		Step1URL:      srv.URL + "/issue",
		ActionURL:     srv.URL + "/action",
		UnrelatedURLs: noops,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectTokenIssuedNRequestsPrior: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when token rotates, got %d", len(res.Findings))
	}
}

// --- DetectCrossSessionTokenAcceptance ------------------------------------

// TestDetectCrossSessionTokenAcceptance_FlagsUnboundToken issues a token to
// session A and submits it from session B. A vulnerable server accepts because
// it never binds the token to a session — expect a Critical finding.
func TestDetectCrossSessionTokenAcceptance_FlagsUnboundToken(t *testing.T) {
	var (
		mu     sync.Mutex
		valid  = map[string]bool{}
		serial int
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		serial++
		sess := fmt.Sprintf("sess-%d", serial)
		tok := fmt.Sprintf("ut-%d", serial)
		valid[tok] = true
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: sess, Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"csrf_token":"%s"}`, tok)
		_ = r
	})
	mux.HandleFunc("/action", func(w http.ResponseWriter, r *http.Request) {
		// Accept ANY known token regardless of which session cookie carries it.
		tok := extractToken(readBody(r))
		mu.Lock()
		ok := valid[tok]
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectCrossSessionTokenAcceptance(context.Background(), MultiStepOptions{
		Step1URL:  srv.URL + "/login",
		ActionURL: srv.URL + "/action",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectCrossSessionTokenAcceptance: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for cross-session token, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "CSRF Token Not Bound to Session" {
		t.Errorf("unexpected type: %q", f.Type)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical severity, got %q", f.Severity)
	}
	if !containsAll(f.CWE, "CWE-352", "CWE-613") {
		t.Errorf("expected CWE-352 + CWE-613, got %+v", f.CWE)
	}
}

// TestDetectCrossSessionTokenAcceptance_NoFindingWhenBound covers a properly
// implemented server that binds the token to a session cookie. Submitting
// session A's token from session B's cookie should be rejected.
func TestDetectCrossSessionTokenAcceptance_NoFindingWhenBound(t *testing.T) {
	store := newSessionTokenStore()
	var serial int
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		serial++
		sess := fmt.Sprintf("sess-%d", serial)
		tok := fmt.Sprintf("bnd-%d", serial)
		mu.Unlock()
		store.issue(sess, tok)
		http.SetCookie(w, &http.Cookie{Name: "session", Value: sess, Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"csrf_token":"%s"}`, tok)
	})
	mux.HandleFunc("/action", func(w http.ResponseWriter, r *http.Request) {
		sessCookie, err := r.Cookie("session")
		if err != nil || sessCookie.Value == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		tok := extractToken(readBody(r))
		if !store.accepts(sessCookie.Value, tok) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectCrossSessionTokenAcceptance(context.Background(), MultiStepOptions{
		Step1URL:  srv.URL + "/login",
		ActionURL: srv.URL + "/action",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectCrossSessionTokenAcceptance: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when token is session-bound, got %d", len(res.Findings))
	}
}

// --- Robustness / no-op edge cases ----------------------------------------

func TestMultiStep_NilClientNoOp(t *testing.T) {
	det := &Detector{client: nil}
	ctx := context.Background()
	opts := MultiStepOptions{Step1URL: "http://x.test/a", Step2URL: "http://x.test/b", Step3URL: "http://x.test/c", ActionURL: "http://x.test/x"}
	if r, err := det.DetectStateReuseAcrossSteps(ctx, opts); err != nil || len(r.Findings) != 0 {
		t.Errorf("nil client: reuse should no-op, got %v / %d", err, len(r.Findings))
	}
	if r, err := det.DetectTokenIssuedNRequestsPrior(ctx, opts); err != nil || len(r.Findings) != 0 {
		t.Errorf("nil client: stale-replay should no-op, got %v / %d", err, len(r.Findings))
	}
	if r, err := det.DetectCrossSessionTokenAcceptance(ctx, opts); err != nil || len(r.Findings) != 0 {
		t.Errorf("nil client: cross-session should no-op, got %v / %d", err, len(r.Findings))
	}
}

func TestMultiStep_EmptyOptionsNoOp(t *testing.T) {
	det := New(skwshttp.NewClient())
	ctx := context.Background()
	if r, err := det.DetectStateReuseAcrossSteps(ctx, MultiStepOptions{}); err != nil || len(r.Findings) != 0 {
		t.Errorf("empty opts: reuse should no-op, got %v / %d", err, len(r.Findings))
	}
	if r, err := det.DetectTokenIssuedNRequestsPrior(ctx, MultiStepOptions{}); err != nil || len(r.Findings) != 0 {
		t.Errorf("empty opts: stale-replay should no-op, got %v / %d", err, len(r.Findings))
	}
	if r, err := det.DetectCrossSessionTokenAcceptance(ctx, MultiStepOptions{}); err != nil || len(r.Findings) != 0 {
		t.Errorf("empty opts: cross-session should no-op, got %v / %d", err, len(r.Findings))
	}
}

// --- shared test helpers --------------------------------------------------

func readBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	buf := make([]byte, 64*1024)
	n, _ := r.Body.Read(buf)
	return string(buf[:n])
}

func containsAll(haystack []string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for _, h := range haystack {
			if h == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
