package decision

import (
	"strings"
)

// heuristicAdjudicate scores findings using rule-based heuristics when no
// ML engine (haruspex/jev) is available. It provides a deterministic
// baseline confidence for standalone assay users.
//
// Returns a probability slice aligned with items (same contract as Adjudicate).
// nil entries mean "no opinion" — the caller treats them as pass-through.
func heuristicAdjudicate(items []Item) []*float64 {
	probs := make([]*float64, len(items))
	for i, it := range items {
		p := heuristicScore(it.Text)
		probs[i] = &p
	}
	return probs
}

// heuristicScore returns [0,1] confidence that the finding text describes
// a real, reportable vulnerability. The score rewards:
//   - verified/confirmed status
//   - evidence of payload execution (not just reflection)
//   - high-impact classes (sqli, rce, ssti, ssrf)
//   - specific evidence (error messages, status changes, unique markers)
//
// And penalizes:
//   - info-only observations (version disclosure, missing headers)
//   - generic reflection without context
//   - low-confidence language
func heuristicScore(text string) float64 {
	lower := strings.ToLower(text)
	score := 0.5

	// Verified/confirmed findings get a bonus
	if strings.Contains(lower, "[verified]") || strings.Contains(lower, "confirmed") {
		score += 0.25
	}

	// High-impact classes
	highImpact := []string{
		"sql injection", "sqli", "command injection", "cmdi",
		"remote code execution", "rce", "ssti", "template injection",
		"ssrf", "server-side request", "xxe", "xml external",
		"deserialization", "idor", "broken access",
	}
	for _, h := range highImpact {
		if strings.Contains(lower, h) {
			score += 0.15
			break
		}
	}

	// Medium-impact classes
	mediumImpact := []string{
		"xss", "cross-site scripting", "csrf", "cross-site request",
		"path traversal", "lfi", "local file inclusion",
		"open redirect", "session fixation",
	}
	for _, m := range mediumImpact {
		if strings.Contains(lower, m) {
			score += 0.08
			break
		}
	}

	// Evidence quality markers — signs the finding has proof
	evidenceMarkers := []string{
		"error:", "syntax error", "exception", "stack trace",
		"sql error", "mysql", "postgresql", "oracle",
		"reflected", "executed", "returned",
		"status 500", "status 200",
		"unique marker", "sentinel", "canary",
		"sleep", "time-based", "blind",
	}
	for _, e := range evidenceMarkers {
		if strings.Contains(lower, e) {
			score += 0.05
			break
		}
	}

	// Noise indicators — lower confidence
	noiseIndicators := []string{
		"missing header", "x-frame-options", "content-security-policy",
		"hsts", "cookie flag", "httponly", "secure flag",
		"version disclosure", "server banner",
		"autocomplete", "missing referrer",
		"ssl/tls", "certificate",
	}
	for _, n := range noiseIndicators {
		if strings.Contains(lower, n) {
			score -= 0.25
			break
		}
	}

	// Known CVE without verification
	if strings.Contains(lower, "known cve") && !strings.Contains(lower, "[verified]") {
		score -= 0.1
	}

	// Clamp to [0, 1]
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}
	return score
}
