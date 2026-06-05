package h2reset

import (
	"context"
	"strings"
	"testing"
)

func TestDetectContinuationFlood_NoOpPaths(t *testing.T) {
	det := New()
	for _, target := range []string{"http://example.test/x", "%%bad", "https://0.0.0.0:1/"} {
		res, err := det.DetectContinuationFlood(context.Background(), target)
		if err != nil {
			t.Errorf("%s: unexpected error %v", target, err)
		}
		if res == nil || len(res.Findings) != 0 {
			t.Errorf("%s: expected no findings, got %+v", target, res)
		}
	}
}

func TestDetectMadeYouReset_NoOpPaths(t *testing.T) {
	det := New()
	for _, target := range []string{"http://example.test/x", "%%bad", "https://0.0.0.0:1/"} {
		res, err := det.DetectMadeYouReset(context.Background(), target)
		if err != nil {
			t.Errorf("%s: unexpected error %v", target, err)
		}
		if res == nil || len(res.Findings) != 0 {
			t.Errorf("%s: expected no findings, got %+v", target, res)
		}
	}
}

func TestBuildContinuationFinding(t *testing.T) {
	f := buildContinuationFinding("https://x.test/", "x.test:443")
	if !strings.Contains(f.Type, "CONTINUATION") {
		t.Errorf("unexpected type %q", f.Type)
	}
	if f.Confidence == "" || len(f.CWE) == 0 {
		t.Error("finding should carry confidence and CWE")
	}
}

func TestBuildMadeYouResetFinding(t *testing.T) {
	f := buildMadeYouResetFinding("https://x.test/", "x.test:443")
	if !strings.Contains(f.Type, "MadeYouReset") {
		t.Errorf("unexpected type %q", f.Type)
	}
	if len(f.CWE) == 0 || f.CWE[0] != "CWE-770" {
		t.Errorf("expected CWE-770, got %v", f.CWE)
	}
}
