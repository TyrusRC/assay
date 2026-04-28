package racecond

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}
	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

func TestDetector_Name(t *testing.T) {
	if New(internalhttp.NewClient()).Name() != "racecond" {
		t.Errorf("Name() should be 'racecond'")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.ConcurrentRequests <= 0 {
		t.Error("ConcurrentRequests should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
	if opts.SyncMode == "" {
		t.Error("SyncMode should default to a non-empty value")
	}
	if opts.BaselineRequests <= 0 {
		t.Error("BaselineRequests should be positive")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	if !New(client).WithVerbose(true).verbose {
		t.Error("WithVerbose(true) did not set the flag")
	}
	if New(client).WithVerbose(false).verbose {
		t.Error("WithVerbose(false) should leave the flag false")
	}
}

// idempotentWallet simulates a payment endpoint with idempotency keys.
// "Debit once per key" is the contract; the bug is that the check-then-
// debit is non-atomic, so a burst of requests with a *fresh* key can all
// pass the check before the first one commits.
//
// The detector helpfully sends one fixed payload during the baseline
// ("skws_race_baseline") and a different one during the burst
// ("skws_race_burst"), so we route on the param value to get distinct
// idempotency keys for each phase. That way the baseline establishes
// "what a clean response looks like" without exhausting the resource the
// burst will race for.
type idempotentWallet struct {
	mu         sync.Mutex
	debited    map[string]bool
	balance    int64
	raceWindow time.Duration
	locked     bool
}

func newWallet(locked bool, raceWindow time.Duration) *idempotentWallet {
	return &idempotentWallet{
		debited:    map[string]bool{},
		balance:    10_000,
		raceWindow: raceWindow,
		locked:     locked,
	}
}

func (w *idempotentWallet) handle(rw http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("idkey")
	if key == "" {
		_ = r.ParseForm()
		key = r.PostForm.Get("idkey")
	}

	if w.locked {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.debited[key] {
			rw.WriteHeader(http.StatusConflict)
			fmt.Fprint(rw, "already debited")
			return
		}
		w.debited[key] = true
		w.balance -= 100
		rw.WriteHeader(http.StatusOK)
		fmt.Fprint(rw, "debited 100")
		return
	}

	// Vulnerable path: check held under lock, then released, then debit
	// taken under lock. The window between the check and the debit is the
	// race window. Body intentionally constant so the analyzer's body-hash
	// bucketing groups multi-success responses together.
	w.mu.Lock()
	seen := w.debited[key]
	w.mu.Unlock()
	if seen {
		rw.WriteHeader(http.StatusConflict)
		fmt.Fprint(rw, "already debited")
		return
	}
	time.Sleep(w.raceWindow)
	w.mu.Lock()
	w.debited[key] = true
	w.balance -= 100
	w.mu.Unlock()
	rw.WriteHeader(http.StatusOK)
	fmt.Fprint(rw, "debited 100")
}

// TestDetect_MultiSuccess_OnVulnerableWallet: the canonical positive case.
// Sequential baseline produces 1×200 + 2×409 (debit then "already").
// Burst with race vulnerability produces N×200 (multiple debits committed
// against the same idempotency key) — multi-success signal fires.
func TestDetect_MultiSuccess_OnVulnerableWallet(t *testing.T) {
	wallet := newWallet(false, 80*time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(wallet.handle))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	opts := DefaultOptions()
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.PreSyncDelay = 30 * time.Millisecond

	res, err := d.Detect(context.Background(), srv.URL+"?idkey=irrelevant", "idkey", "POST", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected race-condition finding on vulnerable wallet")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityMedium {
		t.Errorf("unconfirmed race should be Medium, got %s", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Description), "unconfirmed") {
		t.Errorf("description should note the finding is unconfirmed; got %q", f.Description)
	}
	if !strings.Contains(f.Evidence, "multi-success") {
		t.Errorf("expected multi-success signal; evidence: %s", f.Evidence)
	}
}

// TestDetect_NoFinding_OnLockedWallet: the FP-guard. A properly-locked
// wallet returns 1×200 + 5×409 under burst — baseline pattern matches,
// nothing should fire.
func TestDetect_NoFinding_OnLockedWallet(t *testing.T) {
	wallet := newWallet(true, 0)
	srv := httptest.NewServer(http.HandlerFunc(wallet.handle))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	opts := DefaultOptions()
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.PreSyncDelay = 30 * time.Millisecond

	res, err := d.Detect(context.Background(), srv.URL+"?idkey=irrelevant", "idkey", "POST", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("locked wallet should NOT trip; got %+v", res.Findings)
	}
}

// TestDetect_NoFinding_WhenBaselineAlreadyVaries: the most important FP
// guard. If the response naturally varies per request (timestamps,
// request IDs, paginated counters, load-balancer affinity), the burst
// will also vary — but that's not a race, it's just normal variance.
// The differential analyzer must not flag it.
func TestDetect_NoFinding_WhenBaselineAlreadyVaries(t *testing.T) {
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "request-id: %d\nfetched at %d", n, time.Now().UnixNano())
	}))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	opts := DefaultOptions()
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.PreSyncDelay = 30 * time.Millisecond

	res, err := d.Detect(context.Background(), srv.URL+"?a=1", "a", "GET", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("naturally-varying endpoint must not flag as race; got %+v", res.Findings)
	}
}

// TestDetectWithVerifier_Promotes: when a verifier callback confirms a
// double-effect (e.g. balance moved twice), the finding is promoted to
// Critical+Confirmed.
func TestDetectWithVerifier_Promotes(t *testing.T) {
	wallet := newWallet(false, 80*time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(wallet.handle))
	defer srv.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)

	opts := DefaultOptions()
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.PreSyncDelay = 30 * time.Millisecond

	verify := func(ctx context.Context) (bool, string, error) {
		wallet.mu.Lock()
		bal := wallet.balance
		wallet.mu.Unlock()
		// One legitimate baseline debit + one expected burst-winner = 9800.
		// Anything below that proves the race fired (multiple debits).
		if bal < 9_800 {
			return true, fmt.Sprintf("wallet balance dropped to %d, indicating %d unintended debits", bal, (10_000-bal)/100-2), nil
		}
		return false, fmt.Sprintf("balance %d shows no double-debit", bal), nil
	}

	res, err := d.DetectWithVerifier(context.Background(), srv.URL+"?idkey=irrelevant", "idkey", "POST", opts, verify)
	if err != nil {
		t.Fatalf("DetectWithVerifier: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable result")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("confirmed race must be Critical, got %s", f.Severity)
	}
	if !strings.Contains(f.Description, "Verified") {
		t.Errorf("description should mention 'Verified'; got %q", f.Description)
	}
}

// TestDetect_ServerDown: a target that refuses connections returns an
// error and produces no findings.
func TestDetect_ServerDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	url := srv.URL
	srv.Close()

	d := New(internalhttp.NewClient().WithFollowRedirects(false))
	opts := DefaultOptions()
	opts.ConcurrentRequests = 4
	opts.BaselineRequests = 1
	opts.Timeout = 2 * time.Second

	res, err := d.Detect(context.Background(), url+"?a=1", "a", "POST", opts)
	if err == nil {
		t.Error("expected error when server is down")
	}
	if res == nil {
		t.Fatal("result should not be nil even on error")
	}
}

// TestDetect_ContextCancellation: a pre-cancelled context terminates
// quickly without findings.
func TestDetect_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New(internalhttp.NewClient().WithFollowRedirects(false))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := DefaultOptions()
	opts.ConcurrentRequests = 4
	opts.BaselineRequests = 1

	_, _ = d.Detect(ctx, srv.URL+"?a=1", "a", "POST", opts)
	// Either error or no-finding result is acceptable; test must not hang.
}

// TestParallelMode_StillSupported: the legacy SyncParallel mode is
// retained as a fallback. Confirm it executes end-to-end against a
// vulnerable target and at least produces a result without erroring.
func TestParallelMode_StillSupported(t *testing.T) {
	wallet := newWallet(false, 50*time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(wallet.handle))
	defer srv.Close()

	d := New(internalhttp.NewClient().WithFollowRedirects(false))
	opts := DefaultOptions()
	opts.SyncMode = SyncParallel
	opts.ConcurrentRequests = 6
	opts.BaselineRequests = 3
	opts.Timeout = 5 * time.Second

	res, err := d.Detect(context.Background(), srv.URL+"?idkey=irrelevant", "idkey", "POST", opts)
	if err != nil {
		t.Fatalf("parallel-mode Detect: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	// Parallel mode is best-effort; we don't require it to flag, just to run.
}

// --- analyzer-level unit tests ---

func TestAnalyze_NoSignal_OnEmpty(t *testing.T) {
	if analyzeBaselineDiff(nil, nil) != nil {
		t.Error("empty inputs should produce no signal")
	}
	if analyzeBaselineDiff([]recordedResponse{{StatusCode: 200, BodyHash: "a"}}, nil) != nil {
		t.Error("empty burst should produce no signal")
	}
}

// TestAnalyze_NoCollisionErrorSignal: previously the analyzer fired a
// "collision-error" when burst contained a 4xx that baseline didn't, but
// that produced FPs against every properly-locked limit-of-N resource
// (coupons, rate limits, optimistic concurrency control). The signal was
// removed; this test pins the new behavior so a future contributor can't
// reintroduce it without flipping the test red first.
func TestAnalyze_NoCollisionErrorSignal(t *testing.T) {
	baseline := []recordedResponse{
		{StatusCode: 200, BodyHash: "ok1"},
		{StatusCode: 200, BodyHash: "ok2"},
	}
	burst := []recordedResponse{
		{StatusCode: 200, BodyHash: "ok1"},
		{StatusCode: 409, BodyHash: "conflict"},
	}
	if sig := analyzeBaselineDiff(baseline, burst); sig != nil {
		t.Fatalf("burst-only 4xx must not signal — that's a properly-locked endpoint, not a race; got %+v", sig)
	}
}

func TestAnalyze_MultiSuccess(t *testing.T) {
	baseline := []recordedResponse{
		{StatusCode: 200, BodyHash: "first-win"},
		{StatusCode: 409, BodyHash: "already"},
		{StatusCode: 409, BodyHash: "already"},
	}
	burst := []recordedResponse{
		{StatusCode: 200, BodyHash: "first-win"},
		{StatusCode: 200, BodyHash: "first-win"},
		{StatusCode: 409, BodyHash: "already"},
	}
	sig := analyzeBaselineDiff(baseline, burst)
	if sig == nil || sig.Kind != "multi-success" {
		t.Fatalf("expected multi-success, got %+v", sig)
	}
}

func TestAnalyze_DuplicateState(t *testing.T) {
	baseline := []recordedResponse{
		{StatusCode: 200, BodyHash: "v1"},
		{StatusCode: 200, BodyHash: "v2"},
		{StatusCode: 200, BodyHash: "v3"},
	}
	burst := []recordedResponse{
		{StatusCode: 200, BodyHash: "v4"},
		{StatusCode: 200, BodyHash: "v4"}, // two reqs saw the same pre-update state
	}
	sig := analyzeBaselineDiff(baseline, burst)
	if sig == nil || sig.Kind != "duplicate-state" {
		t.Fatalf("expected duplicate-state, got %+v", sig)
	}
}

func TestAnalyze_NoSignal_OnNaturalVariance(t *testing.T) {
	// Baseline naturally varies; burst varies in the same way. No race.
	baseline := []recordedResponse{
		{StatusCode: 200, BodyHash: "v1"},
		{StatusCode: 200, BodyHash: "v2"},
		{StatusCode: 200, BodyHash: "v3"},
	}
	burst := []recordedResponse{
		{StatusCode: 200, BodyHash: "v4"},
		{StatusCode: 200, BodyHash: "v5"},
		{StatusCode: 200, BodyHash: "v6"},
	}
	if sig := analyzeBaselineDiff(baseline, burst); sig != nil {
		t.Errorf("naturally-varying endpoint should not signal; got %+v", sig)
	}
}

// TestBuildRawRequest_SplitsLastByte verifies that the raw HTTP/1.1
// builder produces a (prefix, finalByte) pair such that prefix+finalByte
// is the complete request, and finalByte is exactly one byte.
func TestBuildRawRequest_SplitsLastByte(t *testing.T) {
	u := mustParseURL(t, "https://example.com/api/redeem")
	prefix, final := buildRawRequest(u, "POST", "coupon=SAVE50", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if len(final) != 1 {
		t.Fatalf("final byte should be exactly 1 byte, got %d", len(final))
	}
	if !strings.HasPrefix(string(prefix), "POST /api/redeem HTTP/1.1\r\n") {
		t.Errorf("request line malformed; first 32 bytes: %q", string(prefix[:min(32, len(prefix))]))
	}
	full := string(prefix) + string(final)
	if !strings.HasSuffix(full, "coupon=SAVE50") {
		t.Errorf("body must reassemble; got tail %q", full[max(0, len(full)-20):])
	}
}

func TestBuildRawRequest_EmptyBody_SplitsHeader(t *testing.T) {
	u := mustParseURL(t, "http://example.com/")
	prefix, final := buildRawRequest(u, "GET", "", nil)
	if len(final) != 1 {
		t.Fatalf("with empty body the builder should split the last header byte; got len(final)=%d", len(final))
	}
	full := string(prefix) + string(final)
	if !strings.HasSuffix(full, "\r\n\r\n") {
		t.Errorf("reassembled request must end with header terminator; got %q", full[max(0, len(full)-8):])
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
