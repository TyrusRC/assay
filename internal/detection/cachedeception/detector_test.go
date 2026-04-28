package cachedeception

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

const privateBody = `<!doctype html><html><body>
<h1>Account dashboard</h1>
<p>Welcome back, alice@example.com</p>
<p>Balance: $4,231.07</p>
<p>Last login: 2026-04-28 09:14:01 from 203.0.113.7</p>
<p>API key: sk-live-9f8d6a2b3c4e1f0a</p>
</body></html>`

// vulnerableApp simulates an app where /account.css and /account/foo.css
// reach the same handler as /account, returning the authenticated body.
// This is the application-side precondition for cache deception (Omer Gil).
type vulnerableApp struct {
	cookieName  string
	cacheable   bool
	requireAuth bool
}

func (v *vulnerableApp) handle(w http.ResponseWriter, r *http.Request) {
	// The app strips known cacheable extensions before routing — this is
	// the bug. /account, /account.css, /account/foo.css all hit the
	// dashboard handler.
	path := strings.TrimSuffix(r.URL.Path, "/")
	if !strings.HasPrefix(path, "/account") {
		http.NotFound(w, r)
		return
	}

	authed := false
	if v.requireAuth {
		c, _ := r.Cookie(v.cookieName)
		if c != nil && c.Value == "alice-session" {
			authed = true
		}
	} else {
		authed = true
	}

	if !authed {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login required"))
		return
	}

	if v.cacheable {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("X-Cache", "MISS")
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(privateBody))
}

// TestDetect_FindsDeceptiveExtensionMatch is the canonical positive case.
// The app returns the authenticated body at /account.css; with cacheable
// headers the finding should grade to High.
func TestDetect_FindsDeceptiveExtensionMatch(t *testing.T) {
	app := &vulnerableApp{cookieName: "session", cacheable: true, requireAuth: true}
	srv := httptest.NewServer(http.HandlerFunc(app.handle))
	defer srv.Close()

	client := internalhttp.NewClient().
		WithFollowRedirects(false).
		WithCookies("session=alice-session")
	d := New(client)

	opts := DefaultOptions()
	opts.MaxProbes = 30

	res, err := d.Detect(context.Background(), srv.URL+"/account", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected cache deception finding; got %+v", res.Findings)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Look for an append-extension finding among the results — that's the
	// strongest signal and should always be reported when the bug is real.
	gotExt := false
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "append-extension") {
			gotExt = true
			if f.Severity != core.SeverityHigh && f.Severity != core.SeverityCritical {
				t.Errorf("with cacheable headers, severity should be High or Critical; got %s", f.Severity)
			}
		}
	}
	if !gotExt {
		t.Errorf("expected an append-extension finding; findings: %+v", res.Findings)
	}
}

// TestDetect_NoFinding_OnHardenedApp pins the FP guard. A correctly-routed
// app — one that 404s on /account.css — must produce zero findings.
func TestDetect_NoFinding_OnHardenedApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strict routing: only /account exactly returns the dashboard.
		if r.URL.Path != "/account" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(privateBody))
	}))
	defer srv.Close()

	client := internalhttp.NewClient().
		WithFollowRedirects(false).
		WithCookies("session=alice-session")
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("hardened app must not trip; got %+v", res.Findings)
	}
}

// TestDetect_ConfirmedByUnauthReplay is the key promotion path. The
// stand-in cache here is the test server itself: it serves the same body
// whether or not the request carries an auth cookie. (A real cache layer
// would do this for the SECOND request; we collapse the two by making
// the "cache" the test server's choice not to require auth on the
// deceptive paths. The detector should still mark the finding Critical.)
func TestDetect_ConfirmedByUnauthReplay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		if !strings.HasPrefix(path, "/account") {
			http.NotFound(w, r)
			return
		}
		// Bug: serves private body to anyone who hits /account.css,
		// regardless of cookies.
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(privateBody))
	}))
	defer srv.Close()

	client := internalhttp.NewClient().
		WithFollowRedirects(false).
		WithCookies("session=alice-session")
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	hasCritical := false
	for _, f := range res.Findings {
		if f.Severity == core.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Errorf("unauth replay confirmation should produce at least one Critical finding; got %+v", res.Findings)
	}
}

// TestDetect_BodySimilarity_ToleratesPerRequestNonces confirms that
// per-request differences (timestamps, request IDs) do not prevent the
// detector from matching the authed and deceptive bodies as the "same"
// page. We embed a unique counter in each response so byte-equality
// fails but Jaccard overlap stays well above the 0.85 threshold.
func TestDetect_BodySimilarity_ToleratesPerRequestNonces(t *testing.T) {
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		if !strings.HasPrefix(path, "/account") {
			http.NotFound(w, r)
			return
		}
		n := atomic.AddInt64(&counter, 1)
		// Response varies per-request via a token, but the bulk of the
		// body is constant — exactly the per-request-nonce pattern.
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(privateBody + "\n<!-- request-id=" + itoa(n) + " -->"))
	}))
	defer srv.Close()

	client := internalhttp.NewClient().
		WithFollowRedirects(false).
		WithCookies("session=alice-session")
	d := New(client)

	res, err := d.Detect(context.Background(), srv.URL+"/account", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("similarity-tolerant matcher should still flag this; got %+v", res.Findings)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// --- analyzer-level unit tests ---

func TestLooksCacheable(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"public + max-age", map[string]string{"Cache-Control": "public, max-age=300"}, true},
		{"max-age positive only", map[string]string{"Cache-Control": "max-age=600"}, true},
		{"vendor X-Cache", map[string]string{"X-Cache": "HIT"}, true},
		{"vendor CF-Cache-Status", map[string]string{"CF-Cache-Status": "MISS"}, true},
		{"Age header alone", map[string]string{"Age": "120"}, true},
		{"no-store kills it", map[string]string{"Cache-Control": "public, max-age=600, no-store"}, false},
		{"private kills it", map[string]string{"Cache-Control": "private, max-age=300"}, false},
		{"empty headers", map[string]string{}, false},
		{"max-age=0", map[string]string{"Cache-Control": "max-age=0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksCacheable(tc.headers); got != tc.want {
				t.Errorf("looksCacheable(%v) = %v, want %v", tc.headers, got, tc.want)
			}
		})
	}
}

func TestBodySimilar(t *testing.T) {
	a := privateBody
	b := privateBody + "\n<!-- nonce -->"
	if !bodySimilar(a, b) {
		t.Error("nearly-identical bodies should match")
	}
	if bodySimilar(privateBody, "<html><body><h1>Login</h1></body></html>") {
		t.Error("login page must NOT match dashboard page")
	}
	if bodySimilar("", privateBody) {
		t.Error("empty body must not match anything")
	}
}

func TestGenerateProbeURLs_InterleavesStrategies(t *testing.T) {
	probes := generateProbeURLs("https://example.com/account", nil, nil, 12)
	if len(probes) != 12 {
		t.Fatalf("got %d probes, want 12", len(probes))
	}
	// First five should be one per strategy (the interleaving guarantee).
	seen := map[ProbeStrategy]bool{}
	for _, p := range probes[:5] {
		seen[p.Strategy] = true
	}
	if len(seen) != 5 {
		t.Errorf("first 5 probes should cover all 5 strategies; got %v", seen)
	}
}

func TestGenerateProbeURLs_PreservesQueryString(t *testing.T) {
	probes := generateProbeURLs("https://example.com/account?id=42", nil, nil, 5)
	for _, p := range probes {
		u, err := url.Parse(p.URL)
		if err != nil {
			t.Fatalf("probe URL %q failed to parse: %v", p.URL, err)
		}
		if u.RawQuery != "id=42" {
			t.Errorf("probe %q lost query string; got %q", p.URL, u.RawQuery)
		}
	}
}

func TestGenerateProbeURLs_BadInput(t *testing.T) {
	if got := generateProbeURLs(":://not a url", nil, nil, 5); got != nil {
		t.Errorf("bad URL should return nil, got %+v", got)
	}
}

func TestHasPositiveMaxAge(t *testing.T) {
	cases := map[string]bool{
		"max-age=300":            true,
		"max-age=1":              true,
		"max-age=0":              false,
		"max-age=":               false,
		"public, max-age=600":    true,
		"public, max-age=600, ":  true,
		"max-age=abc":            false,
		"":                       false,
		"public, no-store":       false,
		"public":                 false,
	}
	for cc, want := range cases {
		t.Run(cc, func(t *testing.T) {
			if got := hasPositiveMaxAge(cc); got != want {
				t.Errorf("hasPositiveMaxAge(%q) = %v, want %v", cc, got, want)
			}
		})
	}
}
