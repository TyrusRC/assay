package oauthflow

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectResourceIndicatorConfusion probes the authorization endpoint
// for RFC 8707 ("Resource Indicators for OAuth 2.0") audience-binding
// flaws.
//
// The attack model the RFC was designed to prevent:
//
//  1. Client A is approved to call API_X.
//  2. Client A obtains an access token (without resource binding) and
//     presents it to API_Y.
//  3. API_Y accepts the token because the issuer matches — even though
//     the user never consented to API_Y access.
//
// RFC 8707 requires the client to declare the intended `resource` (or
// `audience`) at authorize time, and the IdP must bind the issued
// access token's `aud` claim to that value. The bugs we look for:
//
//   - The authorize endpoint silently accepts multiple `resource`
//     parameters (audience-multiplication), each binding the resulting
//     token to a new audience without user consent.
//   - The authorize endpoint accepts a `resource` value that isn't on
//     the client's pre-registered resource allowlist.
//   - The authorize endpoint silently accepts arbitrary `audience`
//     values for clients that should be locked to a single audience.
//
// Since we cannot complete the flow without credentials, the probe is
// PASSIVE: we send a single GET with the audience-multiplication shape
// and observe whether the IdP rejects it (correct) or proceeds to the
// login page (vulnerable). The Location header redirect target is the
// definitive signal — if it points to login, the IdP accepted the
// multi-resource query.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc8707
//   - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
//     §3.1.1 (audience-binding required for confidential clients)
func (d *Detector) DetectResourceIndicatorConfusion(ctx context.Context, authzURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "resource-indicator-confusion",
	}

	u, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("oauthflow: parse authz URL: %w", err)
	}

	// Probe: same authorize request the client would send, but with TWO
	// `resource` parameters declaring different intended audiences.
	// RFC 8707 §2 explicitly permits multi-resource requests, BUT the
	// IdP must obtain user consent for each one and bind the issued
	// token to ALL of them. Silently proceeding past consent for an
	// unfamiliar resource is the bug.
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", opts.clientID())
	if rURI := opts.RegisteredRedirectURI; rURI != "" {
		q.Set("redirect_uri", rURI)
	}
	q.Set("scope", "openid")
	q.Set("state", "assay-state-resource-multi")
	// Audience multiplication: the legitimate resource + an unrelated one.
	q["resource"] = []string{"https://victim-api.example", "https://attacker-controlled.example"}
	u.RawQuery = q.Encode()

	resp, err := d.probe(ctx, u.String())
	if err != nil || resp == nil {
		return result, nil
	}

	// Outcome interpretation:
	//   2xx with login-form body         → IdP accepted the multi-resource
	//                                       query (and is about to ask the
	//                                       user to log in).
	//   3xx Location = login URL         → same: IdP accepted; redirect to login.
	//   4xx with "invalid_resource"      → IdP enforced the allowlist (good).
	//   4xx with "invalid_request"       → ambiguous; could be the resource
	//                                       check or a different missing field.
	loc := resp.Headers["Location"]
	body := strings.ToLower(resp.Body)
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400 &&
		(strings.Contains(strings.ToLower(loc), "login") ||
			strings.Contains(strings.ToLower(loc), "signin") ||
			strings.Contains(strings.ToLower(loc), "authorize")):
		result.Findings = append(result.Findings, buildMultiResourceFinding(authzURL))
	case resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		(strings.Contains(body, "login") || strings.Contains(body, "sign in") ||
			strings.Contains(body, "username")):
		result.Findings = append(result.Findings, buildMultiResourceFinding(authzURL))
	case resp.StatusCode >= 400 && strings.Contains(body, "invalid_resource"):
		// Server correctly rejected — no finding.
	}

	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// buildMultiResourceFinding constructs the finding for an authorize
// endpoint that proceeds with a multi-resource request to login. The
// severity is Medium — the bug is real but we haven't proven the
// token-side binding is broken too. To upgrade to High requires
// completing the flow with credentials and inspecting the issued
// token's `aud` claim.
func buildMultiResourceFinding(authzURL string) *core.Finding {
	f := core.NewFinding("OAuth resource-indicator multiplication accepted", core.SeverityMedium)
	f.Title = "OAuth authorize endpoint accepts multi-resource requests without rejecting unknown audiences"
	f.URL = authzURL
	f.Tool = "oauthflow-detector"
	f.Description = "The authorize endpoint accepted a GET request with TWO `resource` parameters (one legitimate, one attacker-controlled) and proceeded to the login flow. " +
		"Per RFC 8707, the IdP must verify that EVERY supplied `resource` is on the client's registered allowlist; a silently-accepted unfamiliar resource means the issued access token will be bound to the attacker's audience, allowing the attacker to forward the user-authenticated token to a service the user never consented to access."
	f.Evidence = "GET to authorize endpoint with two `resource` parameters returned a login redirect / login page"
	f.Remediation = "Validate every `resource` parameter against the client's pre-registered allowlist BEFORE prompting for user consent. Reject the request with `error=invalid_resource` if any resource is unknown. The user's consent screen MUST enumerate every audience the issued token will be bound to."
	f.References = []string{
		"https://datatracker.ietf.org/doc/html/rfc8707",
		"https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics",
	}
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-08"},
		[]string{"A07:2021"},
		[]string{"CWE-863"},
	)
	return f
}
