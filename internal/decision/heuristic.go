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
// a real, reportable vulnerability.
//
// Input text format (from adjudicateFindings):
//
//	{Type} on {URL} param "{Param}" [{sev},{conf},{verified/unverified},tool:{name}]: {evidence}
func heuristicScore(text string) float64 {
	lower := strings.ToLower(text)
	score := 0.50

	// === Verification status (strongest signal) ===
	if strings.Contains(lower, "verified-by-replay") {
		score += 0.30
	} else if strings.Contains(lower, "confirmed") {
		score += 0.25
	} else if strings.Contains(lower, "[verified]") {
		score += 0.25
	}

	// Confidence tag from the detector
	if strings.Contains(lower, ",confirmed,") {
		score += 0.10
	} else if strings.Contains(lower, ",high,") {
		score += 0.05
	} else if strings.Contains(lower, ",low,") {
		score -= 0.10
	}

	// Severity tag
	if strings.Contains(lower, "critical,") {
		score += 0.10
	}

	// === Finding class: high-impact (program pays for these) ===
	highImpact := []string{
		"sql injection", "command injection",
		"remote code execution", "rce",
		"server-side template injection", "ssti",
		"server-side request forgery", "ssrf",
		"xml external entity", "xxe",
		"deserialization", "idor", "broken access",
		"authentication bypass", "privilege escalation",
	}
	for _, h := range highImpact {
		if strings.Contains(lower, h) {
			score += 0.15
			break
		}
	}

	// Medium-impact classes
	mediumImpact := []string{
		"cross-site scripting", "xss",
		"cross-site request forgery", "csrf",
		"path traversal", "local file inclusion",
		"open redirect", "session fixation",
		"jwt", "mass assignment",
	}
	for _, m := range mediumImpact {
		if strings.Contains(lower, m) {
			score += 0.05
			break
		}
	}

	// === Low-value / noise classes (rarely reportable alone) ===
	lowValue := []string{
		"css injection",
		"email header injection", "email injection",
		"http parameter pollution", "hpp",
		"html injection",
		"ssi injection",
		"format string injection",
		"dom clobbering",
		"reverse tabnabbing",
		"content spoofing",
		"text injection",
	}
	for _, n := range lowValue {
		if strings.Contains(lower, n) {
			score -= 0.20
			break
		}
	}

	// Info-only / header-class findings
	infoNoise := []string{
		"missing header", "x-frame-options", "content-security-policy",
		"hsts", "cookie flag", "httponly", "secure flag",
		"version disclosure", "server banner",
		"autocomplete", "missing referrer",
		"ssl/tls", "certificate",
		"clickjacking",
	}
	for _, n := range infoNoise {
		if strings.Contains(lower, n) {
			score -= 0.35
			break
		}
	}

	// === Evidence quality markers ===
	strongEvidence := []string{
		"syntax error", "sql error", "mysql", "postgresql", "oracle",
		"sentinel", "canary", "marker found",
		"sleep", "time-based", "blind",
		"unique marker", "3/3 replays",
		"response diff", "baseline delta",
	}
	for _, e := range strongEvidence {
		if strings.Contains(lower, e) {
			score += 0.08
			break
		}
	}

	// Known CVE without verification — correlation, not proof
	if strings.Contains(lower, "known cve") && !strings.Contains(lower, "verified-by-replay") {
		score -= 0.15
	}

	// Unverified finding — moderate penalty
	if strings.Contains(lower, "unverified") && !strings.Contains(lower, "confirmed") {
		score -= 0.05
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
