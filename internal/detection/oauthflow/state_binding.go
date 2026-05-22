package oauthflow

import (
	"context"
	"fmt"
	"net/url"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectStateBinding probes the `state` parameter handling on the
// authorization endpoint. It flags two related failure modes:
//
//   - the IdP accepts an authorize request that omits `state` entirely
//     (no CSRF token in the flow), and
//   - the IdP accepts the SAME `state` value across two distinct
//     authorize requests, implying state is not bound to a single
//     client + session (replayable token).
//
// "Success" here means a non-error response — 2xx or a 3xx whose
// Location header carries the IdP's login/consent flow rather than an
// `error=` parameter.
func (d *Detector) DetectStateBinding(ctx context.Context, authzURL string, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "state-binding",
	}

	base, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("parse authzURL: %w", err)
	}

	// Probe 1: state omitted. RFC 6749 §10.12 says clients SHOULD send
	// state; servers enforcing CSRF protection typically reject (or at
	// minimum warn) when it's missing. Acceptance is a finding.
	withoutState := d.buildAuthzURL(base, opts, map[string]string{}, false)
	respNoState, err := d.probe(ctx, withoutState)
	if err == nil && d.acceptsAuthorize(respNoState) {
		result.Findings = append(result.Findings, d.findingStateMissing(withoutState))
		result.Vulnerable = true
	}

	// Probe 2: same `state` value replayed across two requests. An IdP
	// that binds state to client+session would either reject the second
	// request or rotate it; a vulnerable IdP returns the same accepting
	// behavior twice.
	const replayState = "assay-replayable-state-0001"
	first := d.buildAuthzURL(base, opts, map[string]string{"state": replayState}, true)
	resp1, err1 := d.probe(ctx, first)
	resp2, err2 := d.probe(ctx, first)
	if err1 == nil && err2 == nil && d.acceptsAuthorize(resp1) && d.acceptsAuthorize(resp2) {
		result.Findings = append(result.Findings, d.findingStateReplayable(first, replayState))
		result.Vulnerable = true
	}

	return result, nil
}

// findingStateMissing flags acceptance of an authorize request that
// omits the `state` parameter (no CSRF token in the flow).
func (d *Detector) findingStateMissing(probeURL string) *core.Finding {
	f := core.NewFinding("OAuth Missing state Parameter", core.SeverityHigh)
	f.URL = probeURL
	f.Description = "The OAuth authorization endpoint accepted an authorize request with no `state` " +
		"parameter and progressed the flow. RFC 6749 §10.12 mandates `state` as the CSRF protection " +
		"binding the authorize redirect to the client's session — an attacker who can stitch their own " +
		"authorization code onto a victim's session reaches full account takeover."
	f.Evidence = fmt.Sprintf("Authorize request without state accepted: %s", probeURL)
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Remediation = "Reject authorize requests that lack a `state` parameter. Bind the state value to " +
		"the user's session (e.g. signed cookie + server-side store) and verify it on the redirect_uri " +
		"callback before exchanging the code."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A07:2025"},
		[]string{"CWE-352"},
	)
	return f
}

// findingStateReplayable flags acceptance of the same `state` value
// across two distinct authorize requests.
func (d *Detector) findingStateReplayable(probeURL, state string) *core.Finding {
	f := core.NewFinding("OAuth Replayable state Parameter", core.SeverityHigh)
	f.URL = probeURL
	f.Description = "The OAuth authorization endpoint accepted the same `state` value for two " +
		"independent authorize requests. RFC 6749 §10.12 requires state to be a non-guessable value " +
		"bound to the client session; if it can be replayed, the CSRF protection is illusory and an " +
		"attacker can pre-mint a state, lure the victim to authorize, and stitch the resulting code " +
		"into their own session."
	f.Evidence = fmt.Sprintf("state=%s accepted twice; same probe URL replayed: %s", state, probeURL)
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Remediation = "Bind each `state` value to a single client session and burn it on first redemption. " +
		"Reject duplicates server-side, not just on the client. Treat state as a single-use, " +
		"cryptographically random nonce."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A07:2025"},
		[]string{"CWE-352"},
	)
	return f
}
