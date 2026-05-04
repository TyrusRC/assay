package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestAuthState_HasAuth(t *testing.T) {
	cases := []struct {
		name string
		a    AuthState
		want bool
	}{
		{"empty", AuthState{}, false},
		{"only cookies", AuthState{Cookies: "x=1"}, true},
		{"whitespace cookies", AuthState{Cookies: "  "}, false},
		{"only header", AuthState{Headers: map[string]string{"Authorization": "Bearer t"}}, true},
		{"empty key header", AuthState{Headers: map[string]string{"": "v"}}, false},
		{"empty value header", AuthState{Headers: map[string]string{"Authorization": ""}}, false},
		{"both", AuthState{Cookies: "s=1", Headers: map[string]string{"X-Auth": "t"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.HasAuth(); got != tc.want {
				t.Fatalf("HasAuth() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildAuthClient_AppliesAuthAndInheritsTransport(t *testing.T) {
	// httptest server that echoes every Cookie + Authorization header it
	// receives, so we can assert the built client carries them.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Cookie", r.Header.Get("Cookie"))
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	base := internalhttp.NewClient().WithUserAgent("UA/1.0")
	c := buildAuthClient(base, AuthState{
		Cookies: "session=alice",
		Headers: map[string]string{"Authorization": "Bearer alice-token"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Get(ctx, srv.URL)
	if err != nil {
		t.Fatalf("client GET failed: %v", err)
	}
	if got := resp.Headers["X-Echo-Cookie"]; !strings.Contains(got, "session=alice") {
		t.Errorf("Cookie not forwarded: %q", got)
	}
	if got := resp.Headers["X-Echo-Auth"]; got != "Bearer alice-token" {
		t.Errorf("Authorization not forwarded: %q", got)
	}
}

func TestBuildAuthClient_NilBaseDoesNotPanic(t *testing.T) {
	c := buildAuthClient(nil, AuthState{Cookies: "s=1"})
	if c == nil {
		t.Fatal("buildAuthClient returned nil")
	}
}

// TestCrossIdentityIDOR_WiringFiresOnRealLeak exercises the orchestration
// path end-to-end: a httptest server that returns user-A's private
// resource regardless of which identity asks (the canonical BOLA bug).
// We assert the scanner-side wiring emits a finding when both AuthA
// and AuthB are configured.
func TestCrossIdentityIDOR_WiringFiresOnRealLeak(t *testing.T) {
	// Server returns Alice's private dashboard for any authenticated
	// request, regardless of who's authenticated. Classic BOLA.
	private := `<!doctype html><html><body>
<h1>Alice's Private Account Dashboard</h1>
<dl>
<dt>Email</dt><dd>alice@example.com</dd>
<dt>Phone</dt><dd>+1 555 123 4567</dd>
<dt>Account</dt><dd>1234567890123456</dd>
</dl>
<p>Recent transactions, balance, settings, etc.</p>
</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Require *some* auth to keep the test honest about
		// "authenticated cross-identity".
		if r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(private))
	}))
	defer srv.Close()

	cfg := DefaultInternalConfig()
	cfg.RequestTimeout = 5 * time.Second
	cfg.AuthA = AuthState{Headers: map[string]string{"Authorization": "Bearer alice"}}
	cfg.AuthB = AuthState{Headers: map[string]string{"Authorization": "Bearer bob"}}
	cfg.IDORTargetURL = srv.URL + "/account"

	is, err := NewInternalScanner(cfg)
	if err != nil {
		t.Fatalf("NewInternalScanner: %v", err)
	}
	defer is.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	findings := is.testCrossIdentityIDOR(ctx, srv.URL+"/account")
	if len(findings) == 0 {
		t.Fatal("expected cross-identity IDOR finding, got none")
	}
	f := findings[0]
	if f.Tool != "idor-detector" {
		t.Errorf("Tool = %q, want idor-detector", f.Tool)
	}
	if !strings.Contains(strings.ToLower(f.Description), "cross-identity") &&
		!strings.Contains(strings.ToLower(f.Description), "two-identity") {
		t.Errorf("Description should mention cross/two-identity probe: %q", f.Description)
	}
}

func TestCrossIdentityIDOR_SkipsWithoutBothAuth(t *testing.T) {
	cfg := DefaultInternalConfig()
	cfg.AuthA = AuthState{Headers: map[string]string{"Authorization": "Bearer alice"}}
	// AuthB intentionally empty.

	is, err := NewInternalScanner(cfg)
	if err != nil {
		t.Fatalf("NewInternalScanner: %v", err)
	}
	defer is.Close()

	findings := is.testCrossIdentityIDOR(context.Background(), "https://example.invalid/x")
	if len(findings) != 0 {
		t.Fatalf("expected probe to skip without both auth states, got %d findings", len(findings))
	}
}

func TestCrossIdentityIDOR_PrefersIDORTargetURLOverScanTarget(t *testing.T) {
	// Server fires only on /private — if the orchestrator falls back to
	// the scan target instead of using IDORTargetURL, we'll get nothing.
	private := strings.Repeat("alice-private-payload-", 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/private" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(private))
	}))
	defer srv.Close()

	cfg := DefaultInternalConfig()
	cfg.RequestTimeout = 5 * time.Second
	cfg.AuthA = AuthState{Cookies: "s=alice"}
	cfg.AuthB = AuthState{Cookies: "s=bob"}
	cfg.IDORTargetURL = srv.URL + "/private"

	is, err := NewInternalScanner(cfg)
	if err != nil {
		t.Fatalf("NewInternalScanner: %v", err)
	}
	defer is.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Pass a different "scan target" — the override must win.
	findings := is.testCrossIdentityIDOR(ctx, srv.URL+"/")
	if len(findings) == 0 {
		t.Fatal("override URL ignored: probe didn't reach /private")
	}
}
