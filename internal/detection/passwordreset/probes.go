package passwordreset

import (
	"context"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectHostHeaderPoisoning posts a reset request with a hostile Host /
// X-Forwarded-Host header and checks whether the returned reset URL (or
// any other absolute URL in the body / Location header) carries the
// attacker host.
func (d *Detector) DetectHostHeaderPoisoning(ctx context.Context, resetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "host-header-poisoning",
	}

	// We inject through X-Forwarded-Host because the underlying
	// http.Client overwrites the Host header from the URL — proxies and
	// reverse-proxies are the realistic vector anyway.
	body := buildRequestBody(opts.UserA)

	probes := []struct{ header string }{
		{"X-Forwarded-Host"},
		{"X-Host"},
		{"X-Forwarded-Server"},
	}

	for _, hint := range requestPathHints {
		requestURL := joinPath(resetURL, hint)
		for _, p := range probes {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			client := d.client.Clone().WithHeaders(map[string]string{p.header: attackerHost})
			resp, err := client.SendRawBody(ctx, requestURL, "POST", body, "application/json")
			if err != nil || resp == nil {
				continue
			}
			if !containsAttacker(resp, attackerHost) {
				continue
			}

			result.Vulnerable = true
			result.Findings = append(result.Findings, buildHostHeaderFinding(resetURL, p.header, attackerHost, resp))
			return result, nil
		}
	}
	return result, nil
}

// DetectCrossUserToken requests a reset for UserA, extracts the issued
// token, and submits the token to confirm a password change for UserB.
// If the confirmation succeeds, the token is not scoped to the issuing
// user — a critical IDOR-style flaw.
func (d *Detector) DetectCrossUserToken(ctx context.Context, resetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "cross-user-token",
	}

	if opts.UserB == "" {
		return result, nil // cannot meaningfully test without a second user
	}

	token, requestURL, err := d.requestToken(ctx, resetURL, opts.UserA)
	if err != nil || token == "" {
		return result, nil
	}

	confirmURL := chooseConfirmURL(resetURL, requestURL)
	body := buildConfirmBody(opts.UserB, token, "Sk1ppy!NewPass#2026")

	resp, err := d.client.SendRawBody(ctx, confirmURL, "POST", body, "application/json")
	if err != nil || resp == nil {
		return result, nil
	}

	if !looksLikeConfirmSuccess(resp) {
		return result, nil
	}

	result.Vulnerable = true
	result.Findings = append(result.Findings, buildCrossUserFinding(resetURL, opts.UserA, opts.UserB, token, resp))
	return result, nil
}

// DetectTokenReplay requests a reset, submits the token successfully,
// then submits the same token again. If the second submission also
// succeeds, the token is not invalidated after first use.
func (d *Detector) DetectTokenReplay(ctx context.Context, resetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "token-replay",
	}

	token, requestURL, err := d.requestToken(ctx, resetURL, opts.UserA)
	if err != nil || token == "" {
		return result, nil
	}

	confirmURL := chooseConfirmURL(resetURL, requestURL)

	body1 := buildConfirmBody(opts.UserA, token, "Sk1ppy!NewPass#A")
	first, err := d.client.SendRawBody(ctx, confirmURL, "POST", body1, "application/json")
	if err != nil || first == nil || !looksLikeConfirmSuccess(first) {
		// If the first submission already failed, replay isn't meaningful.
		return result, nil
	}

	body2 := buildConfirmBody(opts.UserA, token, "Sk1ppy!NewPass#B")
	second, err := d.client.SendRawBody(ctx, confirmURL, "POST", body2, "application/json")
	if err != nil || second == nil {
		return result, nil
	}
	if !looksLikeConfirmSuccess(second) {
		return result, nil
	}

	result.Vulnerable = true
	result.Findings = append(result.Findings, buildReplayFinding(resetURL, token, first, second))
	return result, nil
}
