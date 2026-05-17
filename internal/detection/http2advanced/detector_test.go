package http2advanced

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startH2Server returns a TLS httptest.Server with HTTP/2 enabled and a
// minimal handler that echoes the inbound x-test header (if present). The
// echo is used by the HPACK-pollution probe.
func startH2Server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("x-test"); v != "" {
			w.Header().Set("x-test-echo", v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestNew_DefaultDetector(t *testing.T) {
	d := New("https://example.test/")
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
	if d.Target != "https://example.test/" {
		t.Errorf("expected Target to be set, got %q", d.Target)
	}
}

func TestDetectSettingsFlood_HTTPSchemeNoOp(t *testing.T) {
	d := New("http://example.test/")
	res, err := d.DetectSettingsFlood(context.Background(), DetectOptions{Target: "http://example.test/"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false for http scheme, got true")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on http URL, got %d", len(res.Findings))
	}
	if res.DetectionType != "settings-flood" {
		t.Errorf("expected DetectionType=settings-flood, got %q", res.DetectionType)
	}
}

func TestDetectSettingsFlood_BadURLNoOp(t *testing.T) {
	d := New("%%bad")
	res, err := d.DetectSettingsFlood(context.Background(), DetectOptions{Target: "%%bad"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on bad URL, got %+v", res)
	}
}

func TestDetectSettingsFlood_UnreachableNoOp(t *testing.T) {
	d := New("https://0.0.0.0:1/")
	res, err := d.DetectSettingsFlood(context.Background(), DetectOptions{
		Target:  "https://0.0.0.0:1/",
		Timeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected nil error on unreachable, got %v", err)
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result, got %+v", res)
	}
}

func TestDetectSettingsFlood_AgainstRealH2(t *testing.T) {
	srv := startH2Server(t)

	d := New(srv.URL)
	d.InsecureSkipVerify = true
	res, err := d.DetectSettingsFlood(context.Background(), DetectOptions{
		Target:  srv.URL,
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectSettingsFlood error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.DetectionType != "settings-flood" {
		t.Errorf("expected DetectionType=settings-flood, got %q", res.DetectionType)
	}
	// Real net/http H/2 server accepts many SETTINGS without GOAWAY rate-limit,
	// so this probe normally surfaces a finding. We don't assert vulnerable=true
	// (Go's H/2 server behaviour may evolve and shut down with PROTOCOL_ERROR);
	// we only require: (a) no panic, (b) if Vulnerable=true then Findings>=1,
	// (c) DetectionType is set.
	if res.Vulnerable && len(res.Findings) == 0 {
		t.Errorf("Vulnerable=true but no findings emitted")
	}
	for _, f := range res.Findings {
		if f.Tool != "http2advanced-detector" {
			t.Errorf("expected Tool=http2advanced-detector, got %q", f.Tool)
		}
		if f.Severity == "" {
			t.Errorf("expected non-empty severity, got finding=%+v", f)
		}
		if !containsAny(f.CWE, "CWE-400", "CWE-770") {
			t.Errorf("expected CWE-400 or CWE-770, got %v", f.CWE)
		}
		if !containsAny(f.Top10, "A05:2025") {
			t.Errorf("expected A05:2025 in Top10, got %v", f.Top10)
		}
	}
}

func TestDetectHPACKPollution_HTTPSchemeNoOp(t *testing.T) {
	d := New("http://example.test/")
	res, err := d.DetectHPACKPollution(context.Background(), DetectOptions{Target: "http://example.test/"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on http, got %+v", res)
	}
	if res.DetectionType != "hpack-pollution" {
		t.Errorf("expected DetectionType=hpack-pollution, got %q", res.DetectionType)
	}
}

func TestDetectHPACKPollution_AgainstRealH2NoLeak(t *testing.T) {
	srv := startH2Server(t)

	d := New(srv.URL)
	d.InsecureSkipVerify = true
	res, err := d.DetectHPACKPollution(context.Background(), DetectOptions{
		Target:  srv.URL,
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectHPACKPollution error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	// stdlib net/http H/2 implementation does NOT leak HPACK state across
	// streams — so this probe MUST return Vulnerable=false against a real
	// well-behaved server.
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false against stdlib H/2 server, got true; findings=%+v", res.Findings)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings against stdlib H/2 server, got %d", len(res.Findings))
	}
}

func TestDetectFlowControlExhaustion_DestructiveGate(t *testing.T) {
	// Without AllowDestructive, the probe must be a quiet no-op even
	// against a real server — that's the safety contract.
	srv := startH2Server(t)

	d := New(srv.URL)
	d.InsecureSkipVerify = true
	res, err := d.DetectFlowControlExhaustion(context.Background(), DetectOptions{
		Target:           srv.URL,
		AllowDestructive: false,
		Timeout:          3 * time.Second,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result when AllowDestructive=false, got %+v", res)
	}
	if res.DetectionType != "flowcontrol-exhaustion" {
		t.Errorf("expected DetectionType=flowcontrol-exhaustion, got %q", res.DetectionType)
	}
}

func TestDetectFlowControlExhaustion_DestructiveAllowed(t *testing.T) {
	srv := startH2Server(t)

	d := New(srv.URL)
	d.InsecureSkipVerify = true
	res, err := d.DetectFlowControlExhaustion(context.Background(), DetectOptions{
		Target:           srv.URL,
		AllowDestructive: true,
		Timeout:          3 * time.Second,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.DetectionType != "flowcontrol-exhaustion" {
		t.Errorf("expected DetectionType=flowcontrol-exhaustion, got %q", res.DetectionType)
	}
	// Either Vulnerable or not — we just require coherence between flag
	// and findings list.
	if res.Vulnerable && len(res.Findings) == 0 {
		t.Errorf("Vulnerable=true but no findings emitted")
	}
	for _, f := range res.Findings {
		if f.Tool != "http2advanced-detector" {
			t.Errorf("expected Tool=http2advanced-detector, got %q", f.Tool)
		}
		if string(f.Severity) != "high" {
			t.Errorf("expected severity=high for flow-control exhaustion, got %q", f.Severity)
		}
	}
}

func TestDetectAll_HTTPSchemeNoOp(t *testing.T) {
	d := New("http://example.test/")
	res, err := d.DetectAll(context.Background(), DetectOptions{Target: "http://example.test/"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on http, got %+v", res)
	}
	if res.DetectionType != "all" {
		t.Errorf("expected DetectionType=all, got %q", res.DetectionType)
	}
}

func TestDetectAll_AgainstRealH2(t *testing.T) {
	srv := startH2Server(t)

	d := New(srv.URL)
	d.InsecureSkipVerify = true
	res, err := d.DetectAll(context.Background(), DetectOptions{
		Target:           srv.URL,
		AllowDestructive: true,
		Timeout:          3 * time.Second,
	})
	if err != nil {
		t.Fatalf("DetectAll error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.DetectionType != "all" {
		t.Errorf("expected DetectionType=all, got %q", res.DetectionType)
	}
	// HPACK probe should never trip stdlib H/2 — so findings, if any, must
	// be from settings-flood or flow-control, not hpack-pollution.
	for _, f := range res.Findings {
		if strings.Contains(strings.ToLower(f.Type), "hpack") {
			t.Errorf("unexpected HPACK pollution finding against stdlib H/2: %+v", f)
		}
	}
}

// TLS config sanity: ensure the detector advertises ALPN h2.
func TestDetector_TLSConfigAdvertisesH2(t *testing.T) {
	d := New("https://example.test/")
	cfg := d.tlsConfig("example.test")
	found := false
	for _, p := range cfg.NextProtos {
		if p == "h2" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected NextProtos to contain h2, got %v", cfg.NextProtos)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion=TLS1.2, got %v", cfg.MinVersion)
	}
}

func containsAny(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}
	return false
}
