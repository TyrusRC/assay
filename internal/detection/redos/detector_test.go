package redos

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsTimingSpikeOnPathological(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("search")
		// Simulate vulnerable backtracking: any value > 25 chars stalls 600ms.
		if len(v) > 25 {
			time.Sleep(600 * time.Millisecond)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/?search=hi")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected ReDoS finding on stalling backend")
	}
	if !strings.Contains(res.Findings[0].Parameter, "search") {
		t.Errorf("expected finding on 'search' param, got %q", res.Findings[0].Parameter)
	}
}

func TestDetect_NoFindingOnFastResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/?search=hi")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on fast backend, got %d", len(res.Findings))
	}
}

func TestDetect_SkipsParamsWithoutRegexHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(600 * time.Millisecond) // would trigger if probed
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	// `?id=1` doesn't match any regex hint → detector should not probe.
	start := time.Now()
	res, _ := det.Detect(context.Background(), srv.URL+"/?id=1")
	elapsed := time.Since(start)
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings for non-regex-shaped param, got %d", len(res.Findings))
	}
	// And it should return quickly because we never probed.
	if elapsed > 200*time.Millisecond {
		t.Errorf("detector took %v on non-matching param — suggests it probed", elapsed)
	}
}

func TestIsSuspicious_LowBaseUsesAbsoluteOnly(t *testing.T) {
	if !isSuspicious(20*time.Millisecond, 320*time.Millisecond) {
		t.Error("low-baseline + 300ms delta should be suspicious")
	}
	if isSuspicious(20*time.Millisecond, 100*time.Millisecond) {
		t.Error("80ms delta should not be suspicious")
	}
}

func TestIsSuspicious_HighBaseRequiresRatio(t *testing.T) {
	// Baseline 200ms, payload 300ms → 100ms delta; under 4x ratio.
	if isSuspicious(200*time.Millisecond, 300*time.Millisecond) {
		t.Error("ratio under 4x should NOT flag")
	}
	// Baseline 200ms, payload 1s → 5x and 800ms delta.
	if !isSuspicious(200*time.Millisecond, 1000*time.Millisecond) {
		t.Error("5x ratio + 800ms delta should flag")
	}
}
