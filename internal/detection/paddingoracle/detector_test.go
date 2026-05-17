package paddingoracle

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// makeCiphertext returns a 32-byte (two AES-block) deterministic
// ciphertext-shaped blob with a known last byte. The contents are not
// actually encrypted — the test servers only care about the last byte
// of the decoded payload to simulate padding-oracle behavior.
func makeCiphertext() []byte {
	ct := make([]byte, 32)
	for i := range ct {
		ct[i] = byte(i)
	}
	// Last byte = 31 (the "correct" padding byte the vulnerable mock
	// will accept).
	return ct
}

// vulnerableHandler simulates a CBC padding-oracle endpoint: it
// returns 200 when the submitted token's last decoded byte equals
// the original last byte (correct padding) and 500 otherwise.
func vulnerableHandler(originalLast byte, encoding string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("session")
		raw, err := decodeFor(tok, encoding)
		if err != nil || len(raw) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("decode-error"))
			return
		}
		if raw[len(raw)-1] == originalLast {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome back"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Padding error: bad block"))
	}
}

// safeHandler returns a constant-time, constant-shape 500 regardless
// of payload — the canonical "patched" behavior.
func safeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
	}
}

func decodeFor(s, encoding string) ([]byte, error) {
	if encoding == "hex" {
		return hex.DecodeString(s)
	}
	// Tolerate URL-safe variants the way real apps do.
	if strings.ContainsAny(s, "-_") {
		return base64.URLEncoding.DecodeString(s)
	}
	return base64.StdEncoding.DecodeString(s)
}

func TestNewReturnsDetector(t *testing.T) {
	t.Parallel()
	d := New(skwshttp.NewClient())
	if d == nil {
		t.Fatal("New returned nil")
	}
}

func TestDetectFromToken_NilClient(t *testing.T) {
	t.Parallel()
	d := New(nil)
	res, err := d.DetectFromToken(context.Background(), "http://example.invalid", "session", "AAAA", DetectOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.Vulnerable {
		t.Fatal("expected Vulnerable=false on nil client")
	}
}

func TestDetectFromToken_EmptyToken(t *testing.T) {
	t.Parallel()
	d := New(skwshttp.NewClient())
	res, err := d.DetectFromToken(context.Background(), "http://example.invalid", "session", "", DetectOptions{})
	if err == nil {
		t.Fatal("expected error on empty token")
	}
	if res != nil && res.Vulnerable {
		t.Fatal("must not flag on empty token")
	}
}

func TestDetectFromToken_InvalidEncoding(t *testing.T) {
	t.Parallel()
	d := New(skwshttp.NewClient())
	_, err := d.DetectFromToken(context.Background(), "http://example.invalid", "session", "AAAA", DetectOptions{Encoding: "rot13"})
	if err == nil {
		t.Fatal("expected error on unsupported encoding")
	}
}

func TestDetectFromToken_BadBase64(t *testing.T) {
	t.Parallel()
	d := New(skwshttp.NewClient())
	_, err := d.DetectFromToken(context.Background(), "http://example.invalid", "session", "!!!not-base64!!!", DetectOptions{Encoding: "base64"})
	if err == nil {
		t.Fatal("expected error decoding invalid base64")
	}
}

func TestDetectFromToken_SafeServer_QuickProbe(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	ct := makeCiphertext()
	tok := base64.StdEncoding.EncodeToString(ct)

	d := New(skwshttp.NewClient().WithFollowRedirects(false))
	res, err := d.DetectFromToken(context.Background(), srv.URL+"/?session=ORIG", "session", tok, DetectOptions{
		Encoding:  "base64",
		MaxProbes: 16,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected result")
	}
	if res.Vulnerable {
		t.Fatalf("safe server must not flag: buckets=%d", res.DistinctBuckets)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("safe server must emit zero findings, got %d", len(res.Findings))
	}
}

func TestDetectFromToken_VulnerableServer_QuickProbe(t *testing.T) {
	t.Parallel()
	ct := makeCiphertext()
	original := ct[len(ct)-1]

	srv := httptest.NewServer(vulnerableHandler(original, "base64"))
	defer srv.Close()

	tok := base64.StdEncoding.EncodeToString(ct)

	d := New(skwshttp.NewClient().WithFollowRedirects(false))
	// MaxProbes=32 is enough — we choose probe values that span at
	// least one "good padding" byte (the original) and many "bad
	// padding" bytes.
	res, err := d.DetectFromToken(context.Background(), srv.URL+"/?session=ORIG", "session", tok, DetectOptions{
		Encoding:  "base64",
		MaxProbes: 32,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected result")
	}
	if !res.Vulnerable {
		t.Fatalf("vulnerable server must flag: buckets=%d findings=%d", res.DistinctBuckets, len(res.Findings))
	}
	if res.DistinctBuckets < 2 {
		t.Fatalf("expected >=2 distinct buckets, got %d", res.DistinctBuckets)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Type != "Padding Oracle" {
		t.Fatalf("unexpected finding type: %q", f.Type)
	}
	if f.Tool != "paddingoracle-detector" {
		t.Fatalf("unexpected tool: %q", f.Tool)
	}
	if f.Parameter != "session" {
		t.Fatalf("unexpected parameter: %q", f.Parameter)
	}
	// OWASP mapping.
	if !contains(f.WSTG, "WSTG-CRYP-02") {
		t.Fatalf("missing WSTG-CRYP-02: %v", f.WSTG)
	}
	if !contains(f.Top10, "A04:2025") {
		t.Fatalf("missing A04:2025: %v", f.Top10)
	}
	if !contains(f.CWE, "CWE-209") || !contains(f.CWE, "CWE-327") {
		t.Fatalf("missing required CWE: %v", f.CWE)
	}
	if string(f.Severity) != "critical" {
		t.Fatalf("expected critical severity, got %q", f.Severity)
	}
}

func TestDetectFromToken_HexEncoding(t *testing.T) {
	t.Parallel()
	ct := makeCiphertext()
	original := ct[len(ct)-1]

	srv := httptest.NewServer(vulnerableHandler(original, "hex"))
	defer srv.Close()

	tok := hex.EncodeToString(ct)
	d := New(skwshttp.NewClient().WithFollowRedirects(false))
	res, err := d.DetectFromToken(context.Background(), srv.URL+"/?session=ORIG", "session", tok, DetectOptions{
		Encoding:  "hex",
		MaxProbes: 32,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("vulnerable hex-encoded oracle must flag")
	}
}

func TestDetectFromToken_MaxProbesCappedAt256(t *testing.T) {
	t.Parallel()
	ct := makeCiphertext()
	original := ct[len(ct)-1]
	srv := httptest.NewServer(vulnerableHandler(original, "base64"))
	defer srv.Close()
	tok := base64.StdEncoding.EncodeToString(ct)

	d := New(skwshttp.NewClient().WithFollowRedirects(false))
	// Request 5000 probes; implementation must cap at 256.
	res, err := d.DetectFromToken(context.Background(), srv.URL+"/?session=ORIG", "session", tok, DetectOptions{
		Encoding:  "base64",
		MaxProbes: 5000,
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected result")
	}
	// We can't directly read the probe count, but the result should still
	// be Vulnerable and not have errored (which would happen if cap was
	// missed and the request rate exhausted httptest).
	if !res.Vulnerable {
		t.Fatal("expected vulnerable verdict at the probe cap")
	}
}

func TestDetectFromToken_FullProbe_Vulnerable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full 256-probe test in -short mode")
	}
	t.Parallel()
	ct := makeCiphertext()
	original := ct[len(ct)-1]
	srv := httptest.NewServer(vulnerableHandler(original, "base64"))
	defer srv.Close()
	tok := base64.StdEncoding.EncodeToString(ct)

	d := New(skwshttp.NewClient().WithFollowRedirects(false))
	res, err := d.DetectFromToken(context.Background(), srv.URL+"/?session=ORIG", "session", tok, DetectOptions{
		Encoding:  "base64",
		MaxProbes: 256,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable, got buckets=%d", res.DistinctBuckets)
	}
}

func TestDetectFromToken_FullProbe_Safe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full 256-probe test in -short mode")
	}
	t.Parallel()
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()
	tok := base64.StdEncoding.EncodeToString(makeCiphertext())

	d := New(skwshttp.NewClient().WithFollowRedirects(false))
	res, err := d.DetectFromToken(context.Background(), srv.URL+"/?session=ORIG", "session", tok, DetectOptions{
		Encoding:  "base64",
		MaxProbes: 256,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("safe server must not flag, buckets=%d", res.DistinctBuckets)
	}
}

func TestDetectFromToken_ContextCancel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()
	tok := base64.StdEncoding.EncodeToString(makeCiphertext())

	d := New(skwshttp.NewClient().WithFollowRedirects(false))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	_, err := d.DetectFromToken(ctx, srv.URL+"/?session=ORIG", "session", tok, DetectOptions{
		Encoding:  "base64",
		MaxProbes: 256,
	})
	if err == nil {
		t.Fatal("expected ctx.Err() on cancelled context")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
