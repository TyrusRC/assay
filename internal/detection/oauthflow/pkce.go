package oauthflow

import (
	"context"
	"fmt"
	"net/url"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// DetectPKCEDowngrade verifies that an IdP advertising / accepting PKCE
// on the authorize side actually enforces `code_verifier` on the token
// exchange. The probe:
//
//  1. drives the authorize endpoint with code_challenge +
//     code_challenge_method=S256, captures the resulting code, and
//  2. POSTs to the token endpoint WITHOUT a code_verifier.
//
// If a token is issued, PKCE is effectively unenforced — the protection
// has been silently downgraded by the server (RFC 9700 §2.1.1).
func (d *Detector) DetectPKCEDowngrade(ctx context.Context, authzURL, tokenURL string, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "pkce-downgrade",
	}

	if tokenURL == "" {
		return result, fmt.Errorf("tokenURL is required")
	}

	base, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("parse authzURL: %w", err)
	}

	// Step 1: drive the authorize endpoint with a synthetic S256
	// challenge. A real flow would compute SHA-256(verifier) and
	// base64url-encode it; for the downgrade probe the exact value is
	// irrelevant — the server-side enforcement is what we measure.
	authReq := d.buildAuthzURL(base, opts, map[string]string{
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
		"state":                 "assay-pkce-probe",
	}, true)

	authResp, err := d.probe(ctx, authReq)
	if err != nil || authResp == nil {
		return result, nil
	}

	code := extractCode(authResp)
	if code == "" {
		// No code → either the IdP didn't issue one (consent screen) or
		// it errored. Either way we can't observe a downgrade.
		return result, nil
	}

	// Step 2: token exchange without code_verifier.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", opts.clientID())
	if opts.RegisteredRedirectURI != "" {
		form.Set("redirect_uri", opts.RegisteredRedirectURI)
	}

	tokenResp, err := d.client.Post(ctx, tokenURL, form.Encode())
	if err != nil || tokenResp == nil {
		return result, nil
	}

	if d.tokenIssued(tokenResp) {
		result.Findings = append(result.Findings, d.findingPKCEDowngrade(authReq, tokenURL))
		result.Vulnerable = true
	}

	return result, nil
}

// extractCode pulls an `authorization_code` value out of a 3xx
// Location header. RFC 6749 §4.1.2 says the code lives on the
// redirect_uri's query string.
func extractCode(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	loc := resp.Headers["Location"]
	if loc == "" {
		loc = resp.Headers["location"]
	}
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if c := u.Query().Get("code"); c != "" {
		return c
	}
	// Some servers stuff the code into the fragment for hybrid flows.
	if frag := u.Fragment; frag != "" {
		if vals, err := url.ParseQuery(frag); err == nil {
			return vals.Get("code")
		}
	}
	return ""
}

// findingPKCEDowngrade flags token issuance without code_verifier on a
// PKCE-initiated authorization-code exchange.
func (d *Detector) findingPKCEDowngrade(authzReq, tokenURL string) *core.Finding {
	f := core.NewFinding("OAuth PKCE Enforcement Bypass", core.SeverityHigh)
	f.URL = tokenURL
	f.Description = "The OAuth authorization endpoint accepted a `code_challenge` (S256) on the " +
		"authorize side, but the token endpoint issued an access_token / id_token in exchange for the " +
		"code WITHOUT a matching `code_verifier`. This silently downgrades the flow to non-PKCE — an " +
		"attacker who intercepts the code (malicious app, network, log leak) can redeem it without " +
		"knowing the verifier, defeating RFC 7636's protection entirely."
	f.Evidence = fmt.Sprintf("authorize: %s; token-exchange to %s succeeded without code_verifier",
		authzReq, tokenURL)
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Remediation = "Enforce code_verifier verification at the token endpoint whenever the original " +
		"authorize request carried code_challenge. Reject token exchanges that are missing code_verifier " +
		"or whose SHA-256(verifier) does not match the stored challenge (RFC 7636 §4.6)."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A07:2025"},
		[]string{"CWE-1004"},
	)
	return f
}
