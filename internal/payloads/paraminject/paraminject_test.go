package paraminject

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFetch_ReturnsBodyAndResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Tag", "hi")
		_, _ = w.Write([]byte("hello world"))
	}))
	defer srv.Close()
	body, resp, err := Fetch(context.Background(), srv.Client(), srv.URL, 1024)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if body != "hello world" {
		t.Errorf("unexpected body %q", body)
	}
	if resp.Header.Get("X-Tag") != "hi" {
		t.Errorf("missing X-Tag header in response")
	}
}

func TestFetch_CapsBodyLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 10000)))
	}))
	defer srv.Close()
	body, _, err := Fetch(context.Background(), srv.Client(), srv.URL, 100)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(body) != 100 {
		t.Errorf("expected body capped at 100, got %d", len(body))
	}
}

func TestFetch_DefaultBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 200000)))
	}))
	defer srv.Close()
	body, _, err := Fetch(context.Background(), srv.Client(), srv.URL, 0)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Default cap is 64 KiB.
	if len(body) != 64<<10 {
		t.Errorf("expected default cap 64KiB, got %d bytes", len(body))
	}
}

func TestFetch_RequestError(t *testing.T) {
	_, _, err := Fetch(context.Background(), http.DefaultClient, "://broken", 1024)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestInjectParam_SetsValue(t *testing.T) {
	u, _ := url.Parse("https://x.tld/p?a=1&b=2")
	got := InjectParam(u, "b", "EVIL")
	if !strings.Contains(got, "b=EVIL") {
		t.Errorf("expected b=EVIL in %q", got)
	}
	if !strings.Contains(got, "a=1") {
		t.Errorf("expected a=1 preserved, got %q", got)
	}
}

func TestInjectParam_DoesNotMutateOriginal(t *testing.T) {
	u, _ := url.Parse("https://x.tld/?a=baseline")
	_ = InjectParam(u, "a", "EVIL")
	if u.Query().Get("a") != "baseline" {
		t.Errorf("InjectParam mutated original URL")
	}
}

func TestContainsAny(t *testing.T) {
	if !ContainsAny("foo bar baz", []string{"qux", "bar"}) {
		t.Error("expected true when one pattern matches")
	}
	if ContainsAny("foo bar baz", []string{"qux", "quux"}) {
		t.Error("expected false when no pattern matches")
	}
	if ContainsAny("anything", nil) {
		t.Error("expected false for nil pattern slice")
	}
}

func TestFirstNewMatch(t *testing.T) {
	patterns := []string{"alpha", "beta", "gamma"}
	if got := FirstNewMatch("a beta b", "a", patterns); got != "beta" {
		t.Errorf("expected beta, got %q", got)
	}
	if got := FirstNewMatch("a beta b", "beta", patterns); got != "" {
		t.Errorf("expected empty when pattern already in baseline, got %q", got)
	}
	if got := FirstNewMatch("no matches", "", patterns); got != "" {
		t.Errorf("expected empty when nothing matches, got %q", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("short string should pass through, got %q", got)
	}
	if got := Truncate(strings.Repeat("x", 100), 10); got != strings.Repeat("x", 10)+"…" {
		t.Errorf("unexpected truncate output %q", got)
	}
	if got := Truncate("anything", 0); got != "" {
		t.Errorf("zero limit should return empty string, got %q", got)
	}
}

func TestTruncate_HandlesMultibyteRunes(t *testing.T) {
	// 5 multibyte runes (€ is 3 bytes). Truncate(2) must cut at 2 runes,
	// not 2 bytes, so the result stays UTF-8 valid.
	got := Truncate("€€€€€", 2)
	if got != "€€…" {
		t.Errorf("expected '€€…', got %q", got)
	}
}
