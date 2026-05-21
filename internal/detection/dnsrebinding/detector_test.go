package dnsrebinding

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	internalhttp "github.com/TyrusRC/assay/internal/http"
)

// fakeResolver is a test-only Resolver that returns pre-canned answers.
// Sequential answers are returned in order, allowing tests to simulate
// a host whose A-records change between resolutions.
type fakeResolver struct {
	mu        sync.Mutex
	answers   map[string][][]net.IPAddr
	calls     map[string]int
	err       error
	lookupErr map[string]error
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		answers:   make(map[string][][]net.IPAddr),
		calls:     make(map[string]int),
		lookupErr: make(map[string]error),
	}
}

func (f *fakeResolver) setAnswers(host string, rounds ...[]net.IPAddr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host] = rounds
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if err, ok := f.lookupErr[host]; ok {
		return nil, err
	}
	rounds, ok := f.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	idx := f.calls[host]
	f.calls[host]++
	if idx >= len(rounds) {
		idx = len(rounds) - 1
	}
	return rounds[idx], nil
}

func mustIPAddr(ip string) net.IPAddr {
	return net.IPAddr{IP: net.ParseIP(ip)}
}

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)
	if d == nil {
		t.Fatal("New() returned nil")
	}
	if d.client != client {
		t.Error("New() did not assign client")
	}
	if d.resolver == nil {
		t.Error("New() did not assign default resolver")
	}
}

func TestWithResolver(t *testing.T) {
	client := internalhttp.NewClient()
	fr := newFakeResolver()
	d := New(client).WithResolver(fr)
	if d.resolver != fr {
		t.Error("WithResolver did not override resolver")
	}
}

func TestDetectShortTTLMultiIP_MixedScope(t *testing.T) {
	fr := newFakeResolver()
	// Round 1 = public IP, round 2 = private IP (mixed scope across two
	// resolutions within the window).
	fr.setAnswers("rebind.example.com",
		[]net.IPAddr{mustIPAddr("203.0.113.5")},
		[]net.IPAddr{mustIPAddr("127.0.0.1")},
	)

	d := New(internalhttp.NewClient()).WithResolver(fr)
	res, err := d.DetectShortTTLMultiIP(context.Background(), "http://rebind.example.com/x")
	if err != nil {
		t.Fatalf("DetectShortTTLMultiIP returned error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected Vulnerable=true, got false (findings=%d)", len(res.Findings))
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityMedium {
		t.Errorf("expected severity medium, got %s", f.Severity)
	}
	if !strings.Contains(f.Type, "DNS Rebinding") {
		t.Errorf("unexpected finding type: %s", f.Type)
	}
	if f.Tool != "dnsrebinding-detector" {
		t.Errorf("expected tool=dnsrebinding-detector, got %s", f.Tool)
	}
	if len(f.WSTG) == 0 || f.WSTG[0] != "WSTG-INPV-19" {
		t.Errorf("missing WSTG mapping: %+v", f.WSTG)
	}
	if len(f.Top10) == 0 || f.Top10[0] != "A01:2025" {
		t.Errorf("missing Top10 mapping: %+v", f.Top10)
	}
	if len(f.CWE) < 2 {
		t.Errorf("expected at least 2 CWE entries (918, 350), got: %+v", f.CWE)
	}
}

func TestDetectShortTTLMultiIP_MixedInSingleRound(t *testing.T) {
	fr := newFakeResolver()
	// Single round returns both a public and a private IP — classic
	// multi-IP record indicative of rebinding setup.
	fr.setAnswers("multi.example.com",
		[]net.IPAddr{mustIPAddr("203.0.113.5"), mustIPAddr("10.0.0.1")},
	)
	d := New(internalhttp.NewClient()).WithResolver(fr)
	res, err := d.DetectShortTTLMultiIP(context.Background(), "http://multi.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected mixed-scope multi-IP record to be flagged")
	}
}

func TestDetectShortTTLMultiIP_StablePublicOnly(t *testing.T) {
	fr := newFakeResolver()
	fr.setAnswers("stable.example.com",
		[]net.IPAddr{mustIPAddr("203.0.113.5")},
		[]net.IPAddr{mustIPAddr("203.0.113.5")},
	)
	d := New(internalhttp.NewClient()).WithResolver(fr)
	res, err := d.DetectShortTTLMultiIP(context.Background(), "http://stable.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("stable public host should not be flagged, got %+v", res.Findings)
	}
}

func TestDetectShortTTLMultiIP_LookupError(t *testing.T) {
	fr := newFakeResolver()
	fr.err = errors.New("dns down")
	d := New(internalhttp.NewClient()).WithResolver(fr)
	res, err := d.DetectShortTTLMultiIP(context.Background(), "http://err.example.com")
	if err == nil {
		t.Fatal("expected error from DNS failure")
	}
	if res == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if res.Vulnerable {
		t.Error("Vulnerable should be false on DNS failure")
	}
}

func TestDetectShortTTLMultiIP_BadURL(t *testing.T) {
	d := New(internalhttp.NewClient()).WithResolver(newFakeResolver())
	_, err := d.DetectShortTTLMultiIP(context.Background(), "::not a url::")
	if err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestDetectAllowlistBypass_ServerFetchesRebindHost(t *testing.T) {
	// Server returns 200+body when it successfully fetched the URL, 500
	// otherwise. The "baseline" bogus hostname should fail; rebinding
	// hostnames succeed.
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("url")
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		// Reject the baseline bogus host outright.
		if strings.Contains(u.Host, "definitely-not-a-real-host") {
			http.Error(w, "bad", http.StatusInternalServerError)
			return
		}
		// Accept rebinding-friendly hostnames.
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fetched: " + u.Host))
	}))
	defer server.Close()

	d := New(internalhttp.NewClient()).WithResolver(newFakeResolver())
	opts := DefaultOptions()
	opts.SSRFParam = "url"

	res, err := d.DetectAllowlistBypass(context.Background(), server.URL+"?url=https://example.com", "url", opts)
	if err != nil {
		t.Fatalf("DetectAllowlistBypass error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected Vulnerable=true (hits=%d findings=%d)", atomic.LoadInt32(&hits), len(res.Findings))
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Type, "Allowlist Bypass") {
		t.Errorf("unexpected finding type: %s", f.Type)
	}
	if f.Parameter != "url" {
		t.Errorf("expected parameter=url, got %s", f.Parameter)
	}
}

func TestDetectAllowlistBypass_NoBypass(t *testing.T) {
	// Server rejects every fetch — no allowlist bypass possible.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	d := New(internalhttp.NewClient()).WithResolver(newFakeResolver())
	opts := DefaultOptions()
	opts.SSRFParam = "url"

	res, err := d.DetectAllowlistBypass(context.Background(), server.URL+"?url=https://example.com", "url", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false, got findings: %+v", res.Findings)
	}
}

func TestDetectAllowlistBypass_TOCTOUInformational(t *testing.T) {
	// Server rejects everything so no Critical Allowlist-Bypass finding
	// fires. With RebindingTestHost empty we expect a single Informational
	// note acknowledging the TOCTOU probe cannot be conducted.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	d := New(internalhttp.NewClient()).WithResolver(newFakeResolver())
	opts := DefaultOptions()
	opts.SSRFParam = "url"
	opts.EmitInformational = true

	res, err := d.DetectAllowlistBypass(context.Background(), server.URL+"?url=https://example.com", "url", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundInfo := false
	for _, f := range res.Findings {
		if f.Severity == core.SeverityInfo {
			foundInfo = true
			break
		}
	}
	if !foundInfo {
		t.Error("expected an Informational TOCTOU note when RebindingTestHost empty")
	}
}

func TestDetectAllowlistBypass_TOCTOUWithRebindingHost(t *testing.T) {
	// Server consistently fetches the configured rebinding host. We
	// expect a High-severity TOCTOU finding because the server bypassed
	// any rebinding-window mitigation.
	rebindHost := "make-everything-ok.example"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("url")
		u, err := url.Parse(raw)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		// Accept the rebinding host and the standard bypass hosts,
		// reject the bogus baseline.
		if strings.Contains(u.Host, "definitely-not-a-real-host") {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fetched: " + u.Host))
	}))
	defer server.Close()

	d := New(internalhttp.NewClient()).WithResolver(newFakeResolver())
	opts := DefaultOptions()
	opts.SSRFParam = "url"
	opts.RebindingTestHost = rebindHost

	res, err := d.DetectAllowlistBypass(context.Background(), server.URL+"?url=https://example.com", "url", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sawHigh := false
	for _, f := range res.Findings {
		if f.Severity == core.SeverityHigh && strings.Contains(f.Description, rebindHost) {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Errorf("expected High TOCTOU finding mentioning rebinding host; got: %+v", res.Findings)
	}
}

func TestDetectAllowlistBypass_MissingParam(t *testing.T) {
	d := New(internalhttp.NewClient()).WithResolver(newFakeResolver())
	opts := DefaultOptions()
	opts.SSRFParam = ""
	_, err := d.DetectAllowlistBypass(context.Background(), "http://example.com/x", "", opts)
	if err == nil {
		t.Fatal("expected error when SSRFParam is empty")
	}
}

func TestDetectAll_AggregatesFindings(t *testing.T) {
	fr := newFakeResolver()
	// Make the URL host trigger short-TTL flagging.
	fr.setAnswers("vuln.example.com",
		[]net.IPAddr{mustIPAddr("203.0.113.5")},
		[]net.IPAddr{mustIPAddr("127.0.0.1")},
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("url")
		u, _ := url.Parse(raw)
		if u != nil && strings.Contains(u.Host, "definitely-not-a-real-host") {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// We need the target host to be "vuln.example.com" so the resolver
	// short-TTL check runs against the canned host, but we still need to
	// actually hit the test server for the allowlist-bypass leg. Use the
	// server URL as the request target but rely on the resolver shim for
	// the LookupIPAddr call.
	target := strings.Replace(server.URL, "127.0.0.1", "vuln.example.com", 1)
	fr.setAnswers(extractHost(target),
		[]net.IPAddr{mustIPAddr("203.0.113.5")},
		[]net.IPAddr{mustIPAddr("127.0.0.1")},
	)

	d := New(internalhttp.NewClient()).WithResolver(fr)
	opts := DefaultOptions()
	opts.SSRFParam = "url"
	// Skip the bypass leg's network round-trip — we just want to make
	// sure DetectAll surfaces the short-TTL finding without panicking.
	opts.Timeout = 5 * time.Second

	res, err := d.DetectAll(context.Background(), server.URL+"?url=https://example.com", "url", opts)
	if err != nil {
		t.Fatalf("DetectAll error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("DetectAll: expected Vulnerable=true")
	}
}

// helper for the test above
func extractHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	return h
}
