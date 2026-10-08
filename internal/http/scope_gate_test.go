package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/TyrusRC/assay/internal/scope"
)

func TestClient_Do_ScopeGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := mustHost(t, srv.URL)
	sc, err := scope.New([]string{host}, nil, []string{`/logout`}, false)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient().WithScope(sc)

	// In-scope request proceeds.
	if _, err := c.Get(context.Background(), srv.URL+"/ok"); err != nil {
		t.Errorf("in-scope request failed: %v", err)
	}
	// Out-of-scope host is blocked before any socket is opened.
	if _, err := c.Get(context.Background(), "https://evil.example/x"); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("out-of-scope host: got %v, want ErrOutOfScope", err)
	}
	// Excluded path on an in-scope host is blocked.
	if _, err := c.Get(context.Background(), srv.URL+"/logout"); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("excluded path: got %v, want ErrOutOfScope", err)
	}
}

func TestClient_UnscopedClone_BypassesGate(t *testing.T) {
	// A scoped client blocks an off-scope host; its Clone().WithScope(nil) — the
	// infra client used by cloud/subtakeover/depconfusion — reaches it, while
	// still sharing the parent's throttle.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	sc, _ := scope.New([]string{"only.example"}, nil, nil, false)
	scoped := NewClient().WithScope(sc)
	if _, err := scoped.Get(context.Background(), srv.URL); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("scoped client should block the off-scope test server, got %v", err)
	}

	infra := scoped.Clone().WithScope(nil)
	if _, err := infra.Get(context.Background(), srv.URL); err != nil {
		t.Errorf("unscoped clone should reach the off-scope host, got %v", err)
	}
}

func TestClient_Do_NoScopeAllowsAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	// A client with no scope keeps the previous allow-all behavior.
	if _, err := NewClient().Get(context.Background(), srv.URL+"/anything"); err != nil {
		t.Errorf("no-scope client should allow any request, got %v", err)
	}
}

func TestClient_CheckRedirect_BlocksOutOfScope(t *testing.T) {
	// The redirect target points off-host; the scope must stop the client from
	// following it, returning the 3xx instead.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/stolen", http.StatusFound)
	}))
	defer srv.Close()

	host := mustHost(t, srv.URL)
	sc, _ := scope.New([]string{host}, nil, nil, false)
	c := NewClient().WithScope(sc)

	resp, err := c.Get(context.Background(), srv.URL+"/go")
	if err != nil {
		t.Fatalf("request errored instead of returning the 3xx: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected the 302 to be returned unfollowed, got %d", resp.StatusCode)
	}
}

func TestClient_CookieSource_OverridesStatic(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Cookie")
	}))
	defer srv.Close()

	live := "session=fresh"
	c := NewClient().WithCookies("session=stale").WithCookieSource(func() string { return live })
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if sent := <-got; sent != "session=fresh" {
		t.Errorf("Cookie header = %q, want the live source value session=fresh", sent)
	}

	// An empty live value falls back to the static cookie.
	live = ""
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if sent := <-got; sent != "session=stale" {
		t.Errorf("empty live source should fall back to static cookie, got %q", sent)
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}
