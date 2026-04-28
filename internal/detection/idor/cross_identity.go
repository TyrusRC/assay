package idor

import (
	"context"
	"fmt"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// CrossIdentityOptions configures a two-identity IDOR probe.
type CrossIdentityOptions struct {
	// BodySimilarityThreshold is the minimum token overlap (Jaccard) at
	// which the attacker's response is considered "the same body as the
	// victim's." Defaults to 0.85 — high enough that per-request nonces
	// (CSRF tokens, request IDs in HTML) don't drag the score below the
	// threshold but low enough that two different users' dashboards do.
	BodySimilarityThreshold float64
	// MinBodyBytes is the floor below which a body is too small to
	// fingerprint reliably. Defaults to 32. Without this guard, two
	// trivial bodies ("OK", "ok!") would hash-match and flag.
	MinBodyBytes int
}

// DefaultCrossIdentityOptions returns sane defaults for the two-identity
// probe.
func DefaultCrossIdentityOptions() CrossIdentityOptions {
	return CrossIdentityOptions{
		BodySimilarityThreshold: 0.85,
		MinBodyBytes:            32,
	}
}

// DetectCrossIdentity is the canonical two-identity IDOR primitive: probe
// one target URL through two distinct auth contexts and report when the
// "attacker" gets back the "victim's" private body.
//
// This is the bug-bounty workhorse that Nuclei templates fundamentally
// cannot replicate — the detection requires:
//
//   - Two separately-authenticated HTTP clients (different cookies/Bearer)
//   - A ground-truth pull from the victim's identity to know what the
//     private response actually looks like
//   - A cross-identity pull from the attacker to compare
//   - Body-similarity reasoning that tolerates per-request nonces but
//     distinguishes two different users' dashboards
//
// The probe makes two requests:
//
//  1. victim.Get(target) — ground truth. If this isn't a 2xx response, we
//     can't establish what the private body looks like, and the probe
//     emits zero findings.
//  2. attacker.Get(target) — the IDOR test. If status is 401/403, the
//     server correctly denied access — no finding.
//
// We flag iff the attacker received a 2xx whose body is similar (Jaccard
// ≥ threshold) to the victim's. Severity grading:
//
//   - Critical when the body contains sensitive-data markers (PII,
//     financial, credentials) — direct evidence of leakage.
//   - High otherwise — same private body served to the wrong identity
//     is itself the bug, but without a marker we can't promise it's
//     "sensitive" enough to warrant Critical.
//
// Caller is responsible for:
//   - Provisioning the two clients with appropriate auth state
//   - Ensuring they target the same backend (otherwise comparing apples
//     to oranges)
//   - Choosing a URL that is private to the victim (not a shared resource)
func (d *Detector) DetectCrossIdentity(ctx context.Context, target string, victim, attacker *http.Client, opts CrossIdentityOptions) (*DetectionResult, error) {
	if victim == nil {
		return nil, fmt.Errorf("victim client is required")
	}
	if attacker == nil {
		return nil, fmt.Errorf("attacker client is required")
	}
	if opts.BodySimilarityThreshold == 0 {
		opts = DefaultCrossIdentityOptions()
	}

	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
		Evidence: make([]*IDOREvidence, 0),
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	victimResp, err := victim.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("victim baseline: %w", err)
	}
	if victimResp.StatusCode < 200 || victimResp.StatusCode >= 300 {
		// Victim cannot read their own resource — we cannot establish what
		// the private body is, so any attacker response is uninterpretable.
		return result, nil
	}
	if len(victimResp.Body) < opts.MinBodyBytes {
		// Too small to fingerprint reliably; bail rather than emit FPs.
		return result, nil
	}

	attackerResp, err := attacker.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("attacker probe: %w", err)
	}
	result.TestedIDs = 1

	// Server correctly denied access — no IDOR.
	if attackerResp.StatusCode == 401 || attackerResp.StatusCode == 403 {
		return result, nil
	}
	// Non-success on attacker side means no leak by definition.
	if attackerResp.StatusCode < 200 || attackerResp.StatusCode >= 300 {
		return result, nil
	}

	overlap := bodyJaccard(victimResp.Body, attackerResp.Body)
	if overlap < opts.BodySimilarityThreshold {
		// Attacker got a 2xx but with a meaningfully different body —
		// the server served them their OWN data, not the victim's. No IDOR.
		return result, nil
	}

	// At this point: attacker's authed request returned a body that closely
	// matches the victim's private response. That's the IDOR signal.
	severity := core.SeverityHigh
	title := "IDOR / BOLA — Cross-Identity Body Match"
	sensitiveHits := d.countSensitiveMatches(attackerResp.Body)
	if sensitiveHits > 0 {
		severity = core.SeverityCritical
		title = "IDOR / BOLA — Cross-Identity Leak of Sensitive Data"
	}

	finding := core.NewFinding(title, severity)
	finding.URL = target
	finding.Tool = "idor-detector"
	finding.Description = fmt.Sprintf(
		"Two-identity probe: the attacker's authenticated request to %s returned a body that matches the victim's authenticated response (Jaccard overlap %.2f, threshold %.2f). The attacker should not be able to read this resource.",
		target, overlap, opts.BodySimilarityThreshold,
	)
	if sensitiveHits > 0 {
		finding.Description += fmt.Sprintf(" %d sensitive-data marker(s) were found in the leaked body.", sensitiveHits)
	}

	finding.Evidence = strings.Join([]string{
		fmt.Sprintf("victim status:    %d (%d bytes)", victimResp.StatusCode, len(victimResp.Body)),
		fmt.Sprintf("attacker status:  %d (%d bytes)", attackerResp.StatusCode, len(attackerResp.Body)),
		fmt.Sprintf("body overlap:     %.2f (threshold %.2f)", overlap, opts.BodySimilarityThreshold),
		fmt.Sprintf("sensitive hits:   %d", sensitiveHits),
	}, "\n")

	finding.Remediation = "Enforce object-level authorization on every request: derive the resource owner from the authenticated session, not from a client-supplied identifier. Reject requests where the session subject doesn't match the requested object's owner. Reference: OWASP API Top 10 API1:2023 Broken Object Level Authorization."

	finding.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A01:2025"},
		[]string{"CWE-639", "CWE-285"},
	)
	finding.APITop10 = []string{"API1:2023", "API3:2023"}

	result.Findings = append(result.Findings, finding)
	result.Vulnerable = true
	result.Evidence = append(result.Evidence, &IDOREvidence{
		OriginalStatusCode:    victimResp.StatusCode,
		TestedStatusCode:      attackerResp.StatusCode,
		OriginalContentLength: len(victimResp.Body),
		TestedContentLength:   len(attackerResp.Body),
		ContentDifferent:      false,
		SensitiveDataExposed:  sensitiveHits > 0,
		ResponseSnippet:       snippet(attackerResp.Body, 200),
	})

	return result, nil
}

// countSensitiveMatches runs the detector's sensitivePatterns against
// body and returns the count of distinct patterns that fired. Used to
// grade severity — a body with multiple PII matches is far more likely
// to be a real Critical-severity finding than a generic "<h1>Order</h1>".
func (d *Detector) countSensitiveMatches(body string) int {
	if d == nil || len(d.sensitivePatterns) == 0 {
		return 0
	}
	hits := 0
	for _, p := range d.sensitivePatterns {
		if p.MatchString(body) {
			hits++
		}
	}
	return hits
}

// bodyJaccard computes a token-set Jaccard score between two response
// bodies. We tokenize on whitespace and HTML punctuation, lowercase, and
// compare set membership. Per-request nonces stay above the threshold;
// two different users' dashboards drop well below it.
//
// Returns 0 for any input where one side is empty or the body is too
// small to tokenize reliably (under 4 distinct tokens).
func bodyJaccard(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}
	if a == b {
		return 1
	}
	at := tokenize(a)
	bt := tokenize(b)
	if len(at) < 4 || len(bt) < 4 {
		return 0
	}
	inter := 0
	for k := range at {
		if _, ok := bt[k]; ok {
			inter++
		}
	}
	union := len(at) + len(bt) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func tokenize(s string) map[string]struct{} {
	out := make(map[string]struct{}, len(s)/8)
	cur := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == '<' || c == '>' || c == '"' || c == '\'' || c == '/' || c == '=' {
			if len(cur) > 0 {
				out[strings.ToLower(string(cur))] = struct{}{}
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out[strings.ToLower(string(cur))] = struct{}{}
	}
	return out
}

func snippet(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
