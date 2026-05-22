package oauthflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// toolName is stamped on every Finding produced by this package so that
// downstream reporting / dedup can attribute the source detector.
const toolName = "oauthflow-detector"

// Detector drives an OAuth/OIDC authorization endpoint with crafted
// requests and reasons about whether the IdP honors RFC-level
// protections (state binding, exact redirect_uri match, PKCE
// enforcement, signed ID-tokens).
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new oauthflow Detector wrapping the given HTTP client.
// The client's redirect policy is preserved for callers; internally,
// each probe clones the client and disables redirect-following so the
// raw `Location` header on a 3xx is observable.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles verbose logging on the detector.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the active OAuth-flow probes.
type DetectOptions struct {
	// ClientID is the public client identifier sent to the authorize
	// endpoint. Defaults to "assay-oauthflow-probe" when empty.
	ClientID string
	// RegisteredRedirectURI is the URI that has been pre-registered with
	// the IdP for the ClientID. The redirect_uri partial-match probe
	// derives hostile variants from this base.
	RegisteredRedirectURI string
	// AuthzURL is the full authorization endpoint URL (e.g.
	// https://idp.example.com/oauth/authorize).
	AuthzURL string
	// TokenURL is the token endpoint URL used by the PKCE downgrade and
	// alg=none probes.
	TokenURL string
	// IDToken is an optional pre-fetched id_token to feed the alg=none
	// probe. When empty, DetectIDTokenAlgNone synthesizes an unsigned
	// token and submits it for validation against TokenURL.
	IDToken string
	// Timeout caps a single probe; the detector composes a derived
	// context with this deadline.
	Timeout time.Duration
}

// DefaultOptions returns sensible defaults for an OAuth-flow audit.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		ClientID: "assay-oauthflow-probe",
		Timeout:  8 * time.Second,
	}
}

// DetectionResult bundles the findings produced by a single sub-check.
type DetectionResult struct {
	// Vulnerable is true when at least one finding was emitted.
	Vulnerable bool
	// Findings carries every issue this sub-check produced.
	Findings []*core.Finding
	// DetectionType identifies which sub-check ran (state-binding,
	// redirect-uri-matching, pkce-downgrade, id-token-alg-none).
	DetectionType string
}

// withTimeout returns a derived context honoring opts.Timeout when set.
func withTimeout(parent context.Context, opts DetectOptions) (context.Context, context.CancelFunc) {
	if opts.Timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, opts.Timeout)
}

// clientID returns the configured client_id or a stable default.
func (o DetectOptions) clientID() string {
	if o.ClientID == "" {
		return "assay-oauthflow-probe"
	}
	return o.ClientID
}

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

// DetectRedirectURIMatching probes the authorize endpoint with hostile
// `redirect_uri` variants derived from the registered URI. Per RFC 6749
// §3.1.2.2 and RFC 9700 §4.1, redirect_uri matching MUST be exact;
// suffix, prefix, or path-normalization matching enables open-redirect
// → code-leak → account-takeover chains.
func (d *Detector) DetectRedirectURIMatching(ctx context.Context, authzURL string, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "redirect-uri-matching",
	}

	if opts.RegisteredRedirectURI == "" {
		return result, fmt.Errorf("RegisteredRedirectURI is required")
	}

	base, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("parse authzURL: %w", err)
	}

	variants := extendedRedirectURIVariants(opts.RegisteredRedirectURI)
	for _, variant := range variants {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		probeURL := d.buildAuthzURL(base, opts, map[string]string{
			"redirect_uri": variant,
			"state":        "assay-redir-probe",
		}, true)

		resp, err := d.probe(ctx, probeURL)
		if err != nil || resp == nil {
			continue
		}
		if !d.redirectsToVariant(resp, variant) {
			continue
		}

		result.Findings = append(result.Findings, d.findingRedirectURIBypass(probeURL, variant, opts.RegisteredRedirectURI, resp))
		result.Vulnerable = true
		// One confirmed bypass is enough to prove the bug class; bail
		// out to avoid spamming findings for cousin variants.
		return result, nil
	}

	return result, nil
}

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

// DetectIDTokenAlgNone checks whether a validation surface accepts an
// ID-token whose JOSE header declares `alg: none`. When opts.IDToken is
// supplied, the detector inspects its header directly and (if `none`)
// submits the unsigned token to the token endpoint for echo-based
// validation. When IDToken is empty, the detector synthesizes a minimal
// unsigned token (`{"alg":"none"}.{"sub":"attacker"}.`) and submits it
// the same way.
func (d *Detector) DetectIDTokenAlgNone(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "id-token-alg-none",
	}

	if opts.TokenURL == "" {
		return result, fmt.Errorf("TokenURL is required")
	}

	token := opts.IDToken
	if token == "" {
		token = synthesizeAlgNoneToken(opts.clientID())
	}

	// Inspect the supplied token's header — if it isn't even claiming
	// alg=none then this check has nothing to say.
	hdr, ok := decodeJOSEHeader(token)
	if !ok {
		return result, nil
	}
	alg, _ := hdr["alg"].(string)
	if !strings.EqualFold(alg, "none") {
		return result, nil
	}

	// Submit the unsigned token to a validation surface. RFC 7519
	// validators MUST reject alg=none for confidentiality-critical
	// tokens; acceptance (2xx with non-error body) is a critical bug.
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", token)
	form.Set("client_id", opts.clientID())

	resp, err := d.client.Post(ctx, opts.TokenURL, form.Encode())
	if err != nil || resp == nil {
		return result, nil
	}

	if d.tokenIssued(resp) {
		result.Findings = append(result.Findings, d.findingAlgNone(opts.TokenURL, token))
		result.Vulnerable = true
	}

	return result, nil
}

// DetectAll runs every sub-check and aggregates the findings. Errors
// from individual probes are swallowed (with their findings dropped) so
// one broken endpoint doesn't mask others; the returned error reflects
// only context cancellation or setup-level failure.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	combined := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "all",
	}

	if opts.AuthzURL != "" {
		if r, err := d.DetectStateBinding(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if opts.RegisteredRedirectURI != "" {
			if r, err := d.DetectRedirectURIMatching(ctx, opts.AuthzURL, opts); err == nil && r != nil {
				combined.Findings = append(combined.Findings, r.Findings...)
			}
		}
		if r, err := d.DetectResponseModeConfusion(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if r, err := d.DetectImplicitFlow(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if r, err := d.DetectNonceMissing(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if opts.TokenURL != "" {
			if r, err := d.DetectPKCEDowngrade(ctx, opts.AuthzURL, opts.TokenURL, opts); err == nil && r != nil {
				combined.Findings = append(combined.Findings, r.Findings...)
			}
		}
	}
	if opts.TokenURL != "" {
		if r, err := d.DetectIDTokenAlgNone(ctx, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
	}

	combined.Vulnerable = len(combined.Findings) > 0
	return combined, nil
}

// --- internal helpers ------------------------------------------------

// probe sends a GET with redirect-following disabled so the raw 3xx
// Location header (where OAuth flows surface their result) is visible.
func (d *Detector) probe(ctx context.Context, target string) (*http.Response, error) {
	client := d.client.Clone().WithFollowRedirects(false)
	return client.Get(ctx, target)
}

// buildAuthzURL composes an authorization-endpoint URL with a baseline
// set of parameters (response_type, client_id, redirect_uri, scope,
// state) and overlays the supplied overrides. When includeState is
// false, the state parameter is removed from the final URL even if the
// caller specified one — used by the "state omitted" probe.
func (d *Detector) buildAuthzURL(base *url.URL, opts DetectOptions, overrides map[string]string, includeState bool) string {
	u := *base
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", opts.clientID())
	if opts.RegisteredRedirectURI != "" {
		q.Set("redirect_uri", opts.RegisteredRedirectURI)
	}
	q.Set("scope", "openid")
	q.Set("state", "assay-state-default")
	for k, v := range overrides {
		q.Set(k, v)
	}
	if !includeState {
		q.Del("state")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// acceptsAuthorize reports whether the response looks like the IdP
// progressed the flow rather than rejecting it. A 2xx without `error=`
// in the body, or a 3xx whose Location lacks `error=` and `error_uri=`,
// counts as acceptance.
func (d *Detector) acceptsAuthorize(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Headers["Location"]
		if loc == "" {
			loc = resp.Headers["location"]
		}
		lower := strings.ToLower(loc)
		if strings.Contains(lower, "error=") || strings.Contains(lower, "error_uri=") {
			return false
		}
		return loc != ""
	}
	if resp.StatusCode == 200 {
		lower := strings.ToLower(resp.Body)
		if strings.Contains(lower, `"error"`) || strings.Contains(lower, "invalid_request") {
			return false
		}
		return true
	}
	return false
}

// redirectsToVariant returns true when the response is a 3xx whose
// Location header carries the hostile variant URI. This is the
// confirmation signal for redirect_uri exact-match bypass.
func (d *Detector) redirectsToVariant(resp *http.Response, variant string) bool {
	if resp == nil || resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	loc := resp.Headers["Location"]
	if loc == "" {
		loc = resp.Headers["location"]
	}
	if loc == "" {
		return false
	}
	// The IdP-emitted Location often URL-encodes the redirect_uri; match
	// both raw and decoded forms against the variant's host/path.
	decoded, _ := url.QueryUnescape(loc)
	target := strings.ToLower(variant)
	host := strings.ToLower(variantHost(variant))
	candidates := []string{strings.ToLower(loc), strings.ToLower(decoded)}
	for _, c := range candidates {
		if strings.Contains(c, target) {
			return true
		}
		if host != "" && strings.Contains(c, host) {
			return true
		}
	}
	return false
}

// tokenIssued reports whether a token-endpoint response represents a
// successful issuance. RFC 6749 §5 mandates 200 + JSON with
// access_token; servers that hand back access_token / id_token in any
// 2xx body count.
func (d *Detector) tokenIssued(resp *http.Response) bool {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	lower := strings.ToLower(resp.Body)
	if strings.Contains(lower, `"error"`) {
		return false
	}
	if strings.Contains(lower, `"access_token"`) || strings.Contains(lower, `"id_token"`) {
		return true
	}
	return false
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

// redirectURIVariants derives a small fixed set of hostile variants
// from the registered URI. Each represents a distinct exact-match
// bypass technique observed in real bug bounty reports.
func redirectURIVariants(registered string) []string {
	u, err := url.Parse(registered)
	if err != nil || u.Host == "" {
		return nil
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}

	return []string{
		// Suffix-host bypass: many naïve regexes anchor on the
		// registered host as a prefix, so `app.example.com.attacker.com`
		// passes a `startsWith("app.example.com")` check.
		fmt.Sprintf("%s://%s.attacker.com%s", scheme, host, path),
		// Path traversal: `/cb/../redirect` normalizes to `/redirect`
		// on some IdPs and to `/cb/../redirect` (string match) on
		// others — either way it isn't the registered path.
		fmt.Sprintf("%s://%s%s/../redirect", scheme, host, path),
		// Open-redirect chain via query parameter: even with exact host
		// match, a trusting downstream `next=` redirect lets the
		// attacker pivot off-host.
		fmt.Sprintf("%s://%s%s?next=//attacker.com", scheme, host, path),
	}
}

// variantHost extracts the host portion of a probe variant for relaxed
// Location-header matching when the IdP normalizes the URI.
func variantHost(v string) string {
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return u.Host
}

// decodeJOSEHeader parses the JOSE header (first segment) of a compact
// JWT. Returns false when the token isn't compact-serialized.
func decodeJOSEHeader(token string) (map[string]interface{}, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Tolerate padded encoders.
		raw, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, false
		}
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return nil, false
	}
	return hdr, true
}

// synthesizeAlgNoneToken builds an unsigned JWT-like assertion suitable
// for submission to a validation surface. The signature segment is
// empty per RFC 7519's "Unsecured JWS" encoding.
func synthesizeAlgNoneToken(clientID string) string {
	headerJSON := `{"alg":"none","typ":"JWT"}`
	claimsJSON := fmt.Sprintf(`{"sub":"attacker","iss":"%s","aud":"%s"}`, clientID, clientID)
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	c := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return h + "." + c + "."
}

// --- findings --------------------------------------------------------

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

// findingRedirectURIBypass flags acceptance of a non-exact-match
// redirect_uri variant.
func (d *Detector) findingRedirectURIBypass(probeURL, variant, registered string, resp *http.Response) *core.Finding {
	loc := resp.Headers["Location"]
	if loc == "" {
		loc = resp.Headers["location"]
	}
	f := core.NewFinding("OAuth redirect_uri Partial-Match Bypass", core.SeverityCritical)
	f.URL = probeURL
	f.Description = "The OAuth authorization endpoint accepted a `redirect_uri` that does not match " +
		"the registered URI byte-for-byte and emitted a 3xx redirecting toward the attacker-supplied " +
		"value. Per RFC 6749 §3.1.2.2 and RFC 9700 §4.1, redirect_uri matching MUST be exact; partial, " +
		"prefix, or path-normalized matching enables an attacker to exfiltrate the authorization code " +
		"to a host they control, completing full account takeover."
	f.Evidence = fmt.Sprintf("registered=%s; variant=%s; Location=%s; status=%d",
		registered, variant, loc, resp.StatusCode)
	f.Tool = toolName
	f.Confidence = core.ConfidenceConfirmed
	f.Remediation = "Compare the supplied `redirect_uri` byte-for-byte against the registered URI " +
		"after URL normalization. Reject prefix/suffix matching, path traversal, and query-string " +
		"appendage. Reject the request with 400 when the comparison fails; do NOT redirect."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A07:2025"},
		[]string{"CWE-601"},
	)
	return f
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

// findingAlgNone flags acceptance of an `alg: none` JWT by a token
// validation surface.
func (d *Detector) findingAlgNone(tokenURL, token string) *core.Finding {
	preview := token
	if len(preview) > 64 {
		preview = preview[:64] + "..."
	}
	f := core.NewFinding("OIDC ID Token alg=none Accepted", core.SeverityCritical)
	f.URL = tokenURL
	f.Description = "The token validation endpoint accepted an ID-token whose JOSE header declares " +
		"`alg: none` (RFC 7519 \"Unsecured JWS\") and issued / echoed a successful authentication. " +
		"An attacker can mint id_tokens with arbitrary claims (sub, email, groups) and present them as " +
		"authenticated identity — a one-step path to authentication bypass and privilege escalation."
	f.Evidence = fmt.Sprintf("tokenURL=%s; submitted id_token header alg=none; token=%s", tokenURL, preview)
	f.Tool = toolName
	f.Confidence = core.ConfidenceConfirmed
	f.Remediation = "Maintain an explicit allowlist of accepted `alg` values (RS256, ES256, EdDSA) and " +
		"reject any token whose header is outside it. Never honor `alg: none`. Treat the alg value as " +
		"part of the security contract, not as a parser-selection hint."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A07:2025"},
		[]string{"CWE-345"},
	)
	return f
}
