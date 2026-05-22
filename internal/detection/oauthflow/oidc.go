package oauthflow

import (
	"context"
	"fmt"
	"net/url"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectImplicitFlow probes whether the IdP still issues tokens via the
// OAuth 2.0 implicit grant (response_type=token or id_token token). The
// implicit flow is deprecated in OAuth 2.1 (draft) and OIDC best
// practices for browser apps; servers that still accept it expose
// access tokens directly in the URL fragment, where they leak to
// browser history, referer headers, and analytics.
func (d *Detector) DetectImplicitFlow(ctx context.Context, authzURL string, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "implicit-flow",
	}

	base, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("parse authzURL: %w", err)
	}

	for _, rt := range []string{"token", "id_token token"} {
		probeURL := d.buildAuthzURL(base, opts, map[string]string{
			"response_type": rt,
			"nonce":         "assay-implicit-nonce",
			"state":         "assay-implicit-state",
		}, true)
		resp, err := d.probe(ctx, probeURL)
		if err != nil || resp == nil {
			continue
		}
		if d.acceptsAuthorize(resp) {
			result.Findings = append(result.Findings, d.findingImplicitFlowAccepted(probeURL, rt))
			result.Vulnerable = true
		}
	}
	return result, nil
}

// DetectNonceMissing probes an OIDC authorize endpoint with a request
// that mints an id_token but omits `nonce`. OIDC Core §3.1.2.1 makes
// nonce REQUIRED for implicit and hybrid flows; servers that issue an
// id_token without one let the token be replayed cross-session.
func (d *Detector) DetectNonceMissing(ctx context.Context, authzURL string, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "nonce-missing",
	}

	base, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("parse authzURL: %w", err)
	}

	probeURL := d.buildAuthzURL(base, opts, map[string]string{
		"response_type": "id_token",
		"state":         "assay-nonce-missing-state",
		// Explicitly clear any default nonce — buildAuthzURL doesn't set
		// one but a future change might. The strip-from-final-URL pass
		// in buildAuthzURL only covers `state`, so we use an empty
		// override which strings.URL.Encode treats as a present-but-
		// empty value. We re-parse and delete the key to be safe.
	}, true)

	if parsed, err := url.Parse(probeURL); err == nil {
		q := parsed.Query()
		q.Del("nonce")
		parsed.RawQuery = q.Encode()
		probeURL = parsed.String()
	}

	resp, err := d.probe(ctx, probeURL)
	if err != nil || resp == nil {
		return result, nil
	}
	if d.acceptsAuthorize(resp) {
		result.Findings = append(result.Findings, d.findingNonceMissing(probeURL))
		result.Vulnerable = true
	}
	return result, nil
}

func (d *Detector) findingImplicitFlowAccepted(probeURL, responseType string) *core.Finding {
	f := core.NewFinding("OAuth/OIDC implicit flow still accepted", core.SeverityMedium)
	f.Title = "OAuth/OIDC authorize endpoint issues tokens via the deprecated implicit grant"
	f.URL = probeURL
	f.Tool = "oauthflow-detector"
	f.Description = fmt.Sprintf("The authorize endpoint accepted response_type=%q and returned a non-error redirect. Implicit-flow access tokens are returned directly in the URL fragment (no PKCE-protected exchange), where they leak to browser history, the Referer header, third-party scripts on the redirect-target page, and any browser extension that reads the URL. OAuth 2.1 (draft), the OIDC Security BCP (RFC 9700 §2.1.2), and OWASP all deprecate this grant in favor of authorization-code + PKCE.", responseType)
	f.Evidence = "GET " + probeURL + " was accepted (no error= in 3xx Location or 200 body)"
	f.Remediation = "Disable implicit and hybrid flows for browser clients. Require authorization_code + PKCE (S256) for public clients."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-10"},
		[]string{"A02:2025", "A07:2025"},
		[]string{"CWE-1391", "CWE-522"},
	)
	return f
}

func (d *Detector) findingNonceMissing(probeURL string) *core.Finding {
	f := core.NewFinding("OIDC nonce missing", core.SeverityMedium)
	f.Title = "OIDC authorize endpoint issues id_token without requiring nonce"
	f.URL = probeURL
	f.Tool = "oauthflow-detector"
	f.Description = "The OIDC authorize endpoint accepted a request with response_type=id_token but no nonce parameter. OIDC Core §3.1.2.1 makes nonce REQUIRED for any flow that returns an id_token, and the relying party MUST verify the nonce matches its session — without it, an attacker who intercepts an id_token can replay it into a different session."
	f.Evidence = "GET " + probeURL + " returned a non-error response despite missing nonce"
	f.Remediation = "Reject authorize requests for response_type containing id_token when nonce is absent. The relying party should also bind nonce to its session and reject any id_token whose nonce claim doesn't match."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-10"},
		[]string{"A02:2025", "A07:2025"},
		[]string{"CWE-345", "CWE-352"},
	)
	return f
}
