package cachedeception

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/TyrusRC/assay/internal/http"
)

// TestDetect_CDNSessionSemicolon covers an app where Akamai-style
// path-parameter truncation reaches the authenticated handler — the
// cache appliance keys on /account but the app routes
// /account;jsessionid=poison to the same handler.
func TestDetect_CDNSessionSemicolon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Strip everything after the first ';' — backend behavior.
		if i := strings.Index(path, ";"); i >= 0 {
			path = path[:i]
		}
		if path != "/account" {
			http.NotFound(w, r)
			return
		}
		c, _ := r.Cookie("session")
		if c == nil || c.Value != "alice-session" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(privateBody))
	}))
	defer srv.Close()

	client := internalhttp.NewClient().
		WithFollowRedirects(false).
		WithCookies("session=alice-session")
	d := New(client)

	opts := DefaultOptions()
	opts.MaxProbes = 50

	res, err := d.Detect(context.Background(), srv.URL+"/account", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected CDN session-semicolon finding; got %+v", res.Findings)
	}
	got := false
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "cdn-session-semicolon") {
			got = true
			break
		}
	}
	if !got {
		t.Errorf("expected a cdn-session-semicolon finding; findings: %+v", res.Findings)
	}
}

// TestDetect_CDNQueryStrip covers an app where the backend uses a
// query parameter the CDN strips from the cache key. The strategy
// is opt-in (off by default — needs a Cache-Control guardrail), so
// the test explicitly enables it.
func TestDetect_CDNQueryStrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account" {
			http.NotFound(w, r)
			return
		}
		c, _ := r.Cookie("session")
		if c == nil || c.Value != "alice-session" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(privateBody))
	}))
	defer srv.Close()

	client := internalhttp.NewClient().
		WithFollowRedirects(false).
		WithCookies("session=alice-session")
	d := New(client)

	opts := DefaultOptions()
	opts.MaxProbes = 50
	opts.Strategies = []ProbeStrategy{StrategyCDNQueryStrip}

	res, err := d.Detect(context.Background(), srv.URL+"/account", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	got := false
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "cdn-query-strip") {
			got = true
			break
		}
	}
	if !got {
		t.Errorf("expected a cdn-query-strip finding; findings: %+v", res.Findings)
	}
}

// TestDetect_HardenedAgainstCDNStrategies ensures the new strategies
// don't false-positive on an app that strictly routes by path only.
func TestDetect_HardenedAgainstCDNStrategies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account" {
			http.NotFound(w, r)
			return
		}
		// Strict semicolon-safe: if path was truncated, the literal
		// would have been /account;jsessionid=... which won't match
		// /account exactly. So just check Path is exactly /account.
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(privateBody))
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
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "cdn-session-semicolon") ||
			strings.Contains(f.Evidence, "cdn-query-strip") {
			t.Errorf("hardened app flagged with CDN strategy: %s", f.Evidence)
		}
	}
}
