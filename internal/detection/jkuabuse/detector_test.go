package jkuabuse

import (
	"context"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func newClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second)
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(newClient())
	if d.Name() != "jkuabuse" {
		t.Errorf("Name() = %q, want jkuabuse", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NoToken_NoOp(t *testing.T) {
	d := New(newClient())
	opts := DefaultOptions()
	res, err := d.Detect(context.Background(), "https://example.invalid/api", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res == nil || res.Vulnerable {
		t.Errorf("expected no-op without a token, got %+v", res)
	}
}

func TestDetector_NoCallback_NoOp(t *testing.T) {
	d := New(newClient())
	opts := DefaultOptions()
	opts.Token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"
	res, err := d.Detect(context.Background(), "https://example.invalid/api", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res == nil || res.Vulnerable {
		t.Errorf("expected no-op without callback URL, got %+v", res)
	}
}

// fakeCallback records whether HasInteraction has been queried with a
// given ID and returns true when the test handler actually visited
// the JKU URL.
type fakeCallback struct {
	mu      sync.Mutex
	visited map[string]bool
}

func (f *fakeCallback) markVisited(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.visited == nil {
		f.visited = map[string]bool{}
	}
	f.visited[id] = true
}

func (f *fakeCallback) HasInteraction(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.visited[id]
}

// TestDetector_TargetFetchesJKU_Flags covers a target that trusts the
// JKU header in a JWT and tries to fetch attacker-controlled JWKS. The
// fetch is the bug — the detector reports without needing the server
// to also accept the forged signature.
func TestDetector_TargetFetchesJKU_Flags(t *testing.T) {
	// "Attacker" JWKS server records visits.
	cb := &fakeCallback{}
	jwksSrv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		cb.markVisited(idFromPath(r.URL.Path))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksSrv.Close()

	// "Target" server: when it receives a JWT with a jku header, it
	// fetches the URL (simulating a buggy library that trusts jku).
	targetSrv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			nethttp.Error(w, "no token", nethttp.StatusUnauthorized)
			return
		}
		header, _ := decodeFirstSegment(strings.TrimPrefix(auth, "Bearer "))
		if u := extractJKU(header); u != "" {
			resp, err := nethttp.Get(u)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		nethttp.Error(w, "invalid signature", nethttp.StatusUnauthorized)
	}))
	defer targetSrv.Close()

	d := New(newClient())
	opts := DefaultOptions()
	opts.Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1MSJ9.sig"
	opts.CallbackURL = jwksSrv.URL
	opts.Callback = cb
	opts.PollDelay = 200 * time.Millisecond

	res, err := d.Detect(context.Background(), targetSrv.URL, opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected jku fetch finding; got %+v", res)
	}
}

// TestDetector_TargetIgnoresJKU_NoFinding covers a target that does
// not fetch the URL in the jku header.
func TestDetector_TargetIgnoresJKU_NoFinding(t *testing.T) {
	cb := &fakeCallback{}
	jwksSrv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		cb.markVisited(idFromPath(r.URL.Path))
		w.WriteHeader(200)
	}))
	defer jwksSrv.Close()

	targetSrv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		nethttp.Error(w, "invalid signature", nethttp.StatusUnauthorized)
	}))
	defer targetSrv.Close()

	d := New(newClient())
	opts := DefaultOptions()
	opts.Token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"
	opts.CallbackURL = jwksSrv.URL
	opts.Callback = cb
	opts.PollDelay = 100 * time.Millisecond

	res, err := d.Detect(context.Background(), targetSrv.URL, opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened target flagged: %+v", res)
	}
}

func idFromPath(p string) string {
	// strip leading slash; if empty, return a sentinel — the detector
	// uses the full CallbackURL host+path as the ID so the test
	// recorder doesn't need to mirror that exactly.
	if len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	if p == "" {
		return "root"
	}
	return p
}
