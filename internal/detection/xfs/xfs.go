// Package xfs detects Cross-Frame Scripting / clickjacking exposure.
//
// XFS is the umbrella term for sensitive pages that can be framed by an
// attacker-controlled origin — enabling clickjacking, drag-and-drop
// hijacks, and same-site cookie-bearing UI confusion. Mirrors AWVS
// XFS.script.
//
// A page is non-frameable iff at least one of:
//   - X-Frame-Options is DENY or SAMEORIGIN (ALLOW-FROM is deprecated and
//     ignored by Chrome/Firefox, so it does NOT count as protection),
//   - Content-Security-Policy frame-ancestors directive is present and
//     does NOT include '*' or a permissive scheme-only value,
//   - The response body ships a JS framebuster (`top !== self`,
//     `if (top != self) { top.location = self.location }`,
//     `window.top.location = ...`).
//
// CSP frame-ancestors takes precedence over X-Frame-Options per
// CSP Level 2 §7.5 (browsers must ignore XFO when frame-ancestors is set).
package xfs

import (
	"net/http"
	"regexp"
	"strings"
)

// Protection identifies which mechanism is preventing framing.
type Protection string

const (
	ProtectionNone        Protection = "none"
	ProtectionXFO         Protection = "x_frame_options"
	ProtectionCSP         Protection = "csp_frame_ancestors"
	ProtectionFramebuster Protection = "js_framebuster"
)

// Severity grades the exposure.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

// Result reports the framing analysis.
type Result struct {
	Frameable  bool
	Protection Protection
	Severity   Severity
	Reasons    []string
}

// Analyze returns a clickjacking exposure verdict given response headers
// and (optionally) the rendered body. Body is only inspected for JS
// framebusters when no header-level protection is present.
func Analyze(headers http.Header, body []byte) Result {
	if headers == nil {
		headers = http.Header{}
	}

	if cspHasFrameAncestors(headers) {
		if frameAncestorsBlocks(headers) {
			return Result{
				Protection: ProtectionCSP,
				Frameable:  false,
				Severity:   SeverityInfo,
				Reasons:    []string{"CSP frame-ancestors restricts framing"},
			}
		}
		return Result{
			Protection: ProtectionNone,
			Frameable:  true,
			Severity:   SeverityMedium,
			Reasons:    []string{"CSP frame-ancestors present but permissive (wildcard or scheme-only)"},
		}
	}

	if xfoBlocks(headers) {
		return Result{
			Protection: ProtectionXFO,
			Frameable:  false,
			Severity:   SeverityInfo,
			Reasons:    []string{"X-Frame-Options enforces no/same-origin framing"},
		}
	}

	if framebusterIn(body) {
		return Result{
			Protection: ProtectionFramebuster,
			Frameable:  false,
			Severity:   SeverityLow,
			Reasons:    []string{"JS framebuster detected (defeatable but present)"},
		}
	}

	reasons := []string{
		"X-Frame-Options absent or deprecated (ALLOW-FROM ignored by modern browsers)",
		"CSP frame-ancestors absent",
		"No JS framebuster detected",
	}
	return Result{
		Protection: ProtectionNone,
		Frameable:  true,
		Severity:   SeverityHigh,
		Reasons:    reasons,
	}
}

// --- helpers ---

func xfoBlocks(h http.Header) bool {
	v := strings.TrimSpace(strings.ToUpper(h.Get("X-Frame-Options")))
	return v == "DENY" || v == "SAMEORIGIN"
}

func cspHasFrameAncestors(h http.Header) bool {
	for _, csp := range h.Values("Content-Security-Policy") {
		if strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			return true
		}
	}
	return false
}

func frameAncestorsBlocks(h http.Header) bool {
	for _, csp := range h.Values("Content-Security-Policy") {
		for _, dir := range strings.Split(csp, ";") {
			dir = strings.TrimSpace(strings.ToLower(dir))
			if !strings.HasPrefix(dir, "frame-ancestors") {
				continue
			}
			value := strings.TrimSpace(strings.TrimPrefix(dir, "frame-ancestors"))
			if value == "" || value == "*" || value == "https:" || value == "http:" || value == "data:" {
				return false
			}
			// 'none', 'self', or specific origins all restrict framing
			// from arbitrary attackers.
			return true
		}
	}
	return false
}

var framebusterRE = regexp.MustCompile(`(?i)(top\s*[!=]==?\s*self|top\s*[!=]==?\s*window|self\s*[!=]==?\s*top|top\.location\s*=\s*self\.location|window\.top\.location|parent\.location\s*=\s*window\.location)`)

func framebusterIn(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	return framebusterRE.Match(body)
}
