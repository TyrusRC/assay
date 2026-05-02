package tokenentropy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsLowEntropyCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Repeating-character session id — entropy is well below the
		// floor (1 bit/char for "aaaaaaaaaaaaaaaa").
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: strings.Repeat("a", 24)})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected low-entropy finding for sessionid")
	}
	if res.Findings[0].Parameter != "sessionid" {
		t.Errorf("expected finding on sessionid, got %q", res.Findings[0].Parameter)
	}
}

func TestDetect_FlagsSequentialIDCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "100000000000123"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/")
	if len(res.Findings) == 0 {
		t.Fatal("expected sequential-id finding")
	}
}

func TestDetect_NoFindingOnHighEntropyCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 32-byte base64url-shaped session id with full alphabet
		// diversity — entropy ~5.3 bits/char.
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "fJ8aRQv-mZ7XYx0bC1dN3T9K4HsP_qWp"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on high-entropy cookie, got %d", len(res.Findings))
	}
}

func TestDetect_FlagsLowEntropyEmbeddedCSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form><input name="csrf_token" value="aaaaaaaaaaaaaaaaaaaaaa"/></form>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/")
	if len(res.Findings) == 0 {
		t.Fatal("expected finding on low-entropy embedded csrf_token")
	}
	if !strings.Contains(strings.ToLower(res.Findings[0].Parameter), "csrf") {
		t.Errorf("expected csrf parameter, got %q", res.Findings[0].Parameter)
	}
}

func TestShannonEntropy_AllSameCharIsZero(t *testing.T) {
	if h := shannonEntropy("aaaaaa"); h != 0 {
		t.Errorf("entropy of all-same string should be 0, got %v", h)
	}
}
