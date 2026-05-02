package h2reset

import (
	"context"
	"testing"
)

// The full H/2 + TLS+ALPN protocol round-trip is hard to fixture in a
// hermetic test without standing up a real h2 server. These tests cover
// the input-guard surface so the detector never misbehaves on common
// bad inputs:
//   - non-HTTPS scheme is a quiet no-op (we only attempt H/2-over-TLS)
//   - parse-error URL is a quiet no-op
//   - unreachable host is a quiet no-op (no panics, no findings)
// Live H/2 behaviour is exercised by the scanner integration tests
// against real targets.

func TestDetect_HTTPSchemeNoOp(t *testing.T) {
	det := New()
	res, err := det.Detect(context.Background(), "http://example.test/foo")
	if err != nil {
		t.Fatalf("expected nil error on http URL, got %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on plain http URL, got %d", len(res.Findings))
	}
}

func TestDetect_BadURLNoOp(t *testing.T) {
	det := New()
	res, err := det.Detect(context.Background(), "%%not-a-url")
	if err != nil {
		t.Fatalf("expected nil error on bad URL, got %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on bad URL, got %d", len(res.Findings))
	}
}

func TestDetect_UnreachableHostNoOp(t *testing.T) {
	det := New()
	// 0.0.0.0:1 is guaranteed unreachable — TLS dial fails immediately.
	res, err := det.Detect(context.Background(), "https://0.0.0.0:1/")
	if err != nil {
		t.Fatalf("expected nil error on unreachable host, got %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on unreachable host, got %d", len(res.Findings))
	}
}
