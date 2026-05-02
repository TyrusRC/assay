package racecond

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// startH2Server creates an httptest server with h2 ALPN configured. Go's
// httptest.NewTLSServer enables h1 by default; we must explicitly call
// http2.ConfigureServer to advertise "h2" via NextProtos.
func startH2Server(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	if err := http2.ConfigureServer(srv.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	srv.StartTLS()
	return srv
}

// TestH2_SinglePacket_VulnerableWallet: the canonical positive case for
// the H/2 path. Same wallet model as the H/1 test, exercised over h2 with
// single-packet sync.
func TestH2_SinglePacket_VulnerableWallet(t *testing.T) {
	wallet := newWallet(false, 80*time.Millisecond)
	srv := startH2Server(t, http.HandlerFunc(wallet.handle))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false).WithInsecure(true)
	d := New(client)

	opts := DefaultOptions()
	opts.SyncMode = SyncH2SinglePacket
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.PreSyncDelay = 30 * time.Millisecond

	res, err := d.Detect(context.Background(), srv.URL+"?idkey=irrelevant", "idkey", "POST", opts)
	if err != nil {
		t.Fatalf("Detect (h2): %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected H/2 single-packet sync to detect race; got %+v", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Evidence, "multi-success") {
		t.Errorf("expected multi-success signal; evidence: %s", res.Findings[0].Evidence)
	}
}

// TestH2_NoFinding_OnLockedWallet pins the FP guard for the H/2 path. A
// properly-locked wallet must not trip even when probed via h2 single-
// packet sync.
func TestH2_NoFinding_OnLockedWallet(t *testing.T) {
	wallet := newWallet(true, 0)
	srv := startH2Server(t, http.HandlerFunc(wallet.handle))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false).WithInsecure(true)
	d := New(client)

	opts := DefaultOptions()
	opts.SyncMode = SyncH2SinglePacket
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.PreSyncDelay = 30 * time.Millisecond

	res, err := d.Detect(context.Background(), srv.URL+"?idkey=irrelevant", "idkey", "POST", opts)
	if err != nil {
		t.Fatalf("Detect (h2): %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("locked wallet must not trip on H/2; got %+v", res.Findings)
	}
}

// TestH2_FallsBackToH1_OnH1OnlyServer verifies that selecting
// SyncH2SinglePacket against an h1-only TLS server transparently falls
// back to the H/1 last-byte primitive instead of failing.
func TestH2_FallsBackToH1_OnH1OnlyServer(t *testing.T) {
	wallet := newWallet(false, 80*time.Millisecond)
	srv := httptest.NewTLSServer(http.HandlerFunc(wallet.handle)) // no http2.ConfigureServer
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false).WithInsecure(true)
	d := New(client)

	opts := DefaultOptions()
	opts.SyncMode = SyncH2SinglePacket
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.PreSyncDelay = 30 * time.Millisecond

	res, err := d.Detect(context.Background(), srv.URL+"?idkey=irrelevant", "idkey", "POST", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected race finding via h1 fallback; got %+v", res.Findings)
	}
}

// TestErrH2NotNegotiated_IsSentinel verifies the sentinel error is wired
// up so callers can do errors.Is checks.
func TestErrH2NotNegotiated_IsSentinel(t *testing.T) {
	wrapped := fmt.Errorf("oops: %w", errH2NotNegotiated)
	if !errors.Is(wrapped, errH2NotNegotiated) {
		t.Error("errH2NotNegotiated must be checkable via errors.Is even when wrapped")
	}
}

// TestBuildStreamIDs verifies stream IDs are odd and ascending — H/2 spec
// requires client-initiated streams to use odd IDs starting at 1.
func TestBuildStreamIDs(t *testing.T) {
	ids := buildStreamIDs(5)
	want := []uint32{1, 3, 5, 7, 9}
	if len(ids) != len(want) {
		t.Fatalf("got %d ids, want %d", len(ids), len(want))
	}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("ids[%d] = %d, want %d", i, id, want[i])
		}
	}
}

// TestShouldDropHeader pins the connection-specific header blocklist so a
// future contributor can't accidentally let a banned header through and
// trip a server's h2-strict mode (RFC 7540 §8.1.2.2).
func TestShouldDropHeader(t *testing.T) {
	cases := map[string]bool{
		":method":          true,
		":authority":       true,
		"host":             true,
		"connection":       true,
		"transfer-encoding": true,
		"upgrade":          true,
		"keep-alive":       true,
		"proxy-connection": true,
		"te":               true,
		"content-type":     false,
		"x-custom":         false,
		"authorization":    false,
	}
	for h, want := range cases {
		if got := shouldDropHeader(h); got != want {
			t.Errorf("shouldDropHeader(%q) = %v, want %v", h, got, want)
		}
	}
}

// raceProneServerMu protects against a known data-race in the test
// helpers — the wallet's mu already guards its state, but go test -race
// also flags shared concurrent access patterns inside test code.
var raceProneServerMu sync.Mutex
