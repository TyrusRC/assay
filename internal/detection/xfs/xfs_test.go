package xfs

import (
	"net/http"
	"testing"
)

func TestAnalyze_FullyProtected_XFOOnly(t *testing.T) {
	h := http.Header{"X-Frame-Options": []string{"DENY"}}
	res := Analyze(h, nil)
	if res.Frameable {
		t.Errorf("XFO=DENY must yield Frameable=false, got %+v", res)
	}
	if res.Protection != ProtectionXFO {
		t.Errorf("expected ProtectionXFO, got %q", res.Protection)
	}
}

func TestAnalyze_FullyProtected_CSPFrameAncestors(t *testing.T) {
	h := http.Header{"Content-Security-Policy": []string{"frame-ancestors 'none'; default-src 'self'"}}
	res := Analyze(h, nil)
	if res.Frameable {
		t.Errorf("frame-ancestors 'none' must yield Frameable=false, got %+v", res)
	}
	if res.Protection != ProtectionCSP {
		t.Errorf("expected ProtectionCSP, got %q", res.Protection)
	}
}

func TestAnalyze_FramebusterJSDetected(t *testing.T) {
	body := []byte(`<html><script>if (top !== self) { top.location = self.location; }</script></html>`)
	res := Analyze(http.Header{}, body)
	if res.Frameable {
		t.Errorf("expected JS framebuster to suppress Frameable, got %+v", res)
	}
	if res.Protection != ProtectionFramebuster {
		t.Errorf("expected ProtectionFramebuster, got %q", res.Protection)
	}
}

func TestAnalyze_VulnerableNoProtection(t *testing.T) {
	body := []byte(`<html><body>nothing protecting this page</body></html>`)
	res := Analyze(http.Header{}, body)
	if !res.Frameable {
		t.Errorf("expected Frameable=true on unprotected page, got %+v", res)
	}
	if res.Protection != ProtectionNone {
		t.Errorf("expected ProtectionNone, got %q", res.Protection)
	}
	if len(res.Reasons) == 0 {
		t.Errorf("expected non-empty Reasons on Frameable page")
	}
}

func TestAnalyze_XFOAllowFromDeprecated(t *testing.T) {
	h := http.Header{"X-Frame-Options": []string{"ALLOW-FROM https://example.com"}}
	res := Analyze(h, nil)
	if !res.Frameable {
		t.Errorf("ALLOW-FROM is deprecated and not enforced — must be flagged Frameable, got %+v", res)
	}
}

func TestAnalyze_CSPFrameAncestorsWildcard(t *testing.T) {
	h := http.Header{"Content-Security-Policy": []string{"frame-ancestors *"}}
	res := Analyze(h, nil)
	if !res.Frameable {
		t.Errorf("frame-ancestors * permits any framer — must be flagged Frameable, got %+v", res)
	}
}

func TestAnalyze_CSPFrameAncestorsSelf(t *testing.T) {
	h := http.Header{"Content-Security-Policy": []string{"frame-ancestors 'self'"}}
	res := Analyze(h, nil)
	if res.Frameable {
		t.Errorf("frame-ancestors 'self' is enforced, must yield Frameable=false, got %+v", res)
	}
}

func TestAnalyze_XFOSameOriginPlusFrameAncestors_Aligned(t *testing.T) {
	h := http.Header{
		"X-Frame-Options":         []string{"SAMEORIGIN"},
		"Content-Security-Policy": []string{"frame-ancestors 'self'"},
	}
	res := Analyze(h, nil)
	if res.Frameable {
		t.Errorf("XFO=SAMEORIGIN + frame-ancestors 'self' is double-protected, got Frameable=%v", res.Frameable)
	}
}

func TestAnalyze_NilHeader_TreatedAsVulnerable(t *testing.T) {
	res := Analyze(nil, nil)
	if !res.Frameable {
		t.Errorf("nil header + nil body must default to Frameable=true")
	}
}

func TestSeverity_RatesByContextSensitive(t *testing.T) {
	frame := Analyze(http.Header{}, nil)
	if frame.Severity == "" {
		t.Errorf("expected non-empty Severity")
	}
	valid := map[Severity]bool{
		SeverityHigh:   true,
		SeverityMedium: true,
		SeverityLow:    true,
		SeverityInfo:   true,
	}
	if !valid[frame.Severity] {
		t.Errorf("unexpected severity %q", frame.Severity)
	}
}
