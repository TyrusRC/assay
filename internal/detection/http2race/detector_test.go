package http2race

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	if d.Name() != "http2race" {
		t.Errorf("Name() = %q, want http2race", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NilClientIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/redeem", DefaultOptions())
	if err != nil {
		t.Fatalf("nil client: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil client, got %+v", res)
	}
}

// TestDetector_RacyCounter_Flags covers a state-change endpoint whose
// guard ("already redeemed") is read, then there's a wide compute
// window, then it's set — a textbook TOCTOU. The reads and writes are
// individually mutex-protected (so `go test -race` is satisfied) but
// the *algorithm* is racy: multiple goroutines observe the same
// pre-change state and each proceeds as if they were first.
func TestDetector_RacyCounter_Flags(t *testing.T) {
	var (
		mu       sync.Mutex
		redeemed bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		current := redeemed
		mu.Unlock()
		time.Sleep(40 * time.Millisecond)
		if current {
			http.Error(w, "already", http.StatusConflict)
			return
		}
		mu.Lock()
		redeemed = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("redeemed"))
	}))
	defer srv.Close()

	d := New(newClient())
	opts := DefaultOptions()
	opts.Concurrency = 12
	opts.Method = "POST"
	res, err := d.Detect(context.Background(), srv.URL+"/redeem", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected race finding; got %+v", res)
	}
}

// TestDetector_AtomicCounter_NoFinding covers the same endpoint when
// the read/write is properly serialized. Exactly one of N concurrent
// requests succeeds; the rest return 409.
func TestDetector_AtomicCounter_NoFinding(t *testing.T) {
	var mu sync.Mutex
	var redeemed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if redeemed {
			http.Error(w, "already", http.StatusConflict)
			return
		}
		redeemed = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("redeemed"))
	}))
	defer srv.Close()

	d := New(newClient())
	opts := DefaultOptions()
	opts.Concurrency = 12
	opts.Method = "POST"
	res, err := d.Detect(context.Background(), srv.URL+"/redeem", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened server flagged: %+v", res)
	}
}

// TestDetector_IdempotentEndpoint_NoFinding covers a "GET-like" POST
// that always returns 200 regardless of how many times it's called.
// The post-burst probe also returns 200, which suppresses the race
// flag (the endpoint is harmless to call many times).
func TestDetector_IdempotentEndpoint_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(newClient())
	opts := DefaultOptions()
	opts.Concurrency = 8
	opts.Method = "POST"
	res, err := d.Detect(context.Background(), srv.URL+"/idempotent", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("idempotent endpoint flagged: %+v", res)
	}
}

// TestDetector_ServerError_NoFinding covers a server that 5xx's: we
// shouldn't claim a race finding off error responses.
func TestDetector_ServerError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/redeem", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("5xx flagged as race: %+v", res)
	}
}
