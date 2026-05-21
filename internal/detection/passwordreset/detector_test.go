package passwordreset

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	internalhttp "github.com/TyrusRC/assay/internal/http"
)

// -----------------------------------------------------------------------------
// Host-header poisoning sub-check
// -----------------------------------------------------------------------------

// TestDetectHostHeaderPoisoning_Vulnerable verifies that a server which
// builds the reset URL from the user-supplied Host header is flagged.
// This is the password-reset email hijack pattern.
func TestDetectHostHeaderPoisoning_Vulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable behavior: trust whichever host the client claimed.
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"reset_link":"https://%s/reset?token=abc123"}`, host)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectHostHeaderPoisoning(context.Background(), server.URL, DetectOptions{
		UserA:   "alice@example.com",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectHostHeaderPoisoning: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatalf("expected vulnerability, got Vulnerable=%v findings=%d", res.Vulnerable, len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "Password Reset Host Header Poisoning" {
		t.Errorf("unexpected Type: %q", f.Type)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("expected High severity, got %q", f.Severity)
	}
	if f.Tool != "passwordreset-detector" {
		t.Errorf("expected tool=passwordreset-detector, got %q", f.Tool)
	}
	if !containsAny(f.WSTG, "WSTG-ATHN-09") {
		t.Errorf("expected WSTG-ATHN-09 mapping, got %v", f.WSTG)
	}
	if !containsAny(f.CWE, "CWE-640") {
		t.Errorf("expected CWE-640 mapping, got %v", f.CWE)
	}
}

// TestDetectHostHeaderPoisoning_Safe verifies that a hardened server
// (canonical host hard-coded in response) is NOT flagged.
func TestDetectHostHeaderPoisoning_Safe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"reset_link":"https://canonical.example.com/reset?token=abc"}`)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectHostHeaderPoisoning(context.Background(), server.URL, DetectOptions{
		UserA: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("DetectHostHeaderPoisoning: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("expected no findings on hardened server, got %d: %+v", len(res.Findings), res.Findings)
	}
}

// -----------------------------------------------------------------------------
// Cross-user token acceptance sub-check
// -----------------------------------------------------------------------------

// TestDetectCrossUserToken_Vulnerable verifies that a server which
// accepts user A's token to change user B's password is flagged.
func TestDetectCrossUserToken_Vulnerable(t *testing.T) {
	// State: A's token was issued; the server doesn't bind it to the user.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "request"):
			// Issue a reset token (echoed in the response).
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"token":"reset-token-A-12345"}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "confirm"):
			// Vulnerable: accept any token for any user.
			body, _ := readBody(r)
			if strings.Contains(body, "reset-token-A-12345") {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"status":"password updated"}`)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"invalid token"}`)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectCrossUserToken(context.Background(), server.URL, DetectOptions{
		UserA:   "alice@example.com",
		UserB:   "bob@example.com",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectCrossUserToken: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatalf("expected vulnerability, got Vulnerable=%v findings=%d", res.Vulnerable, len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "Cross-User Reset Token Accepted" {
		t.Errorf("unexpected Type: %q", f.Type)
	}
	if f.Severity != core.SeverityCritical {
		t.Errorf("expected Critical severity, got %q", f.Severity)
	}
}

// TestDetectCrossUserToken_Safe verifies that a server which rejects
// the cross-user submission is NOT flagged.
func TestDetectCrossUserToken_Safe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "request"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"token":"reset-token-A-12345"}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "confirm"):
			body, _ := readBody(r)
			// Safe: only accept when token matches the requested user.
			if strings.Contains(body, "alice@example.com") && strings.Contains(body, "reset-token-A-12345") {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":"token does not belong to user"}`)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectCrossUserToken(context.Background(), server.URL, DetectOptions{
		UserA: "alice@example.com",
		UserB: "bob@example.com",
	})
	if err != nil {
		t.Fatalf("DetectCrossUserToken: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("expected no findings, got %d: %+v", len(res.Findings), res.Findings)
	}
}

// -----------------------------------------------------------------------------
// Token-replay sub-check
// -----------------------------------------------------------------------------

// TestDetectTokenReplay_Vulnerable verifies that a server which accepts
// the same reset token twice is flagged.
func TestDetectTokenReplay_Vulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "request"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"token":"replay-token-9999"}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "confirm"):
			body, _ := readBody(r)
			if strings.Contains(body, "replay-token-9999") {
				// Vulnerable: always succeed for this token, even on replay.
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"status":"password updated"}`)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectTokenReplay(context.Background(), server.URL, DetectOptions{
		UserA:   "alice@example.com",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectTokenReplay: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatalf("expected vulnerability, got Vulnerable=%v findings=%d", res.Vulnerable, len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "Reset Token Replay" {
		t.Errorf("unexpected Type: %q", f.Type)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("expected High severity, got %q", f.Severity)
	}
	if !containsAny(f.CWE, "CWE-294") {
		t.Errorf("expected CWE-294 mapping, got %v", f.CWE)
	}
}

// TestDetectTokenReplay_Safe verifies that a server which invalidates
// the token after first use is NOT flagged.
func TestDetectTokenReplay_Safe(t *testing.T) {
	var (
		mu   sync.Mutex
		used bool
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "request"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"token":"safe-token-7777"}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "confirm"):
			body, _ := readBody(r)
			if !strings.Contains(body, "safe-token-7777") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if used {
				w.WriteHeader(http.StatusGone)
				_, _ = fmt.Fprint(w, `{"error":"token already used"}`)
				return
			}
			used = true
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"status":"password updated"}`)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectTokenReplay(context.Background(), server.URL, DetectOptions{
		UserA: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("DetectTokenReplay: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("expected no findings on hardened server, got %d: %+v", len(res.Findings), res.Findings)
	}
}

// -----------------------------------------------------------------------------
// Aggregator
// -----------------------------------------------------------------------------

// TestDetectAll_AggregatesAllChecks runs the aggregator against a server
// that is vulnerable to all three flaws and confirms each sub-check
// emits at least one finding.
func TestDetectAll_AggregatesAllChecks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to all three: trust Host, accept any token for any
		// user, never invalidate tokens.
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "request"):
			host := r.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = r.Host
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"token":"tok-all","reset_link":"https://%s/reset?token=tok-all"}`, host)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "confirm"):
			body, _ := readBody(r)
			if strings.Contains(body, "tok-all") {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"status":"password updated"}`)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	results, err := d.DetectAll(context.Background(), server.URL, DetectOptions{
		UserA: "alice@example.com",
		UserB: "bob@example.com",
	})
	if err != nil {
		t.Fatalf("DetectAll: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 sub-results, got %d", len(results))
	}
	types := map[string]bool{}
	for _, r := range results {
		if !r.Vulnerable || len(r.Findings) == 0 {
			t.Errorf("expected vulnerable result for %q, got %+v", r.DetectionType, r)
			continue
		}
		for _, f := range r.Findings {
			types[f.Type] = true
		}
	}
	want := []string{
		"Password Reset Host Header Poisoning",
		"Cross-User Reset Token Accepted",
		"Reset Token Replay",
	}
	for _, w := range want {
		if !types[w] {
			t.Errorf("aggregator missing finding type %q (got %v)", w, mapKeys(types))
		}
	}
}

// TestDetectAll_HardenedServer confirms a fully-hardened server emits
// zero findings across all three sub-checks.
func TestDetectAll_HardenedServer(t *testing.T) {
	var (
		mu   sync.Mutex
		used bool
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "request"):
			// Canonical link only; no echo of Host header.
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"token":"hard-tok","reset_link":"https://canonical.example.com/reset?token=hard-tok"}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "confirm"):
			body, _ := readBody(r)
			// Require the token to be bound to alice and only once.
			if !strings.Contains(body, "hard-tok") || !strings.Contains(body, "alice@example.com") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if used {
				w.WriteHeader(http.StatusGone)
				return
			}
			used = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	results, err := d.DetectAll(context.Background(), server.URL, DetectOptions{
		UserA: "alice@example.com",
		UserB: "bob@example.com",
	})
	if err != nil {
		t.Fatalf("DetectAll: %v", err)
	}
	for _, r := range results {
		if r.Vulnerable {
			t.Errorf("expected no findings for %q on hardened server, got %d", r.DetectionType, len(r.Findings))
		}
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func readBody(r *http.Request) (string, error) {
	defer r.Body.Close()
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	return string(buf[:n]), nil
}

func containsAny(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// guard against unused imports in case the test file is edited later
var _ = json.Marshal
