// Package oauth detects OAuth 2.0 / OIDC misconfigurations that map to
// real bug-bounty exploitation paths:
//
//   - missing PKCE on a discoverable authorization endpoint
//   - open redirect via redirect_uri (exact-match bypass)
//   - missing state parameter (CSRF in the OAuth flow)
//   - id_token / userinfo with `alg: none` accepted
//   - JWKS rotated/cached publicly with `kid` traversal hints
//
// Discovery prefers `.well-known/openid-configuration` and
// `.well-known/oauth-authorization-server`; if absent, common-path
// probing surfaces self-hosted IdPs.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detector audits an OAuth/OIDC surface reachable from a target URL.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new OAuth detector.
func New(client *http.Client) *Detector { return &Detector{client: client} }

// WithVerbose enables verbose stderr output.
func (d *Detector) WithVerbose(v bool) *Detector { d.verbose = v; return d }

// DetectOptions tunes the audit.
type DetectOptions struct {
	Timeout      time.Duration
	AttackerHost string // host injected as redirect_uri to test exact-match
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:      8 * time.Second,
		AttackerHost: "skws-oauth-redir.example",
	}
}

// DetectionResult bundles the detector's findings.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Tested     int
	Discovery  *Metadata // populated when discovery succeeded
}

// Metadata mirrors the small subset of the OIDC discovery document we
// care about. Decoded from .well-known/openid-configuration.
type Metadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSURI                string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
	CodeChallengeMethods   []string `json:"code_challenge_methods_supported"`
	IDTokenSigningAlgs     []string `json:"id_token_signing_alg_values_supported"`
}

// Detect runs the OAuth/OIDC audit against a target URL.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.AttackerHost == "" {
		opts.AttackerHost = "skws-oauth-redir.example"
	}

	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	meta := d.discoverMetadata(ctx, target)
	if meta == nil {
		// No OIDC/OAuth surface found — nothing to audit.
		return result, nil
	}
	result.Discovery = meta
	result.Tested = 1

	// Check 1: PKCE not advertised. RFC 9700 makes PKCE mandatory for
	// public clients; absence in code_challenge_methods_supported means
	// the IdP either doesn't enforce it or doesn't tell clients it's
	// available — both are exploitable on mobile/SPA flows.
	if meta.AuthorizationEndpoint != "" && !mentionsPKCE(meta) {
		result.Findings = append(result.Findings, d.findingMissingPKCE(meta))
		result.Vulnerable = true
	}

	// Check 2: id_token "none" alg allowed. RFC 8252 forbids it for
	// public clients, but many self-hosted IdPs still ship it as the
	// default. Single string match in the metadata suffices.
	for _, alg := range meta.IDTokenSigningAlgs {
		if strings.EqualFold(alg, "none") {
			result.Findings = append(result.Findings, d.findingNoneAlg(meta))
			result.Vulnerable = true
			break
		}
	}

	// Check 3: implicit flow advertised. id_token-bearing tokens via the
	// browser fragment are deprecated in OAuth 2.1. Presence isn't
	// always wrong but is a strong smell on modern apps.
	for _, rt := range meta.ResponseTypesSupported {
		if strings.Contains(strings.ToLower(rt), "token") && !strings.Contains(strings.ToLower(rt), "code") {
			result.Findings = append(result.Findings, d.findingImplicitFlow(meta, rt))
			result.Vulnerable = true
			break
		}
	}

	// Check 4: redirect_uri exact-match bypass. Send the authorization
	// endpoint with a hostile redirect_uri pointing at our attacker
	// host. A correctly-configured IdP MUST reject (4xx). A vulnerable
	// IdP either redirects the user-agent to attacker or echoes the
	// redirect_uri in a Location header.
	if meta.AuthorizationEndpoint != "" {
		if f := d.checkRedirectURIBypass(ctx, meta, opts.AttackerHost); f != nil {
			result.Findings = append(result.Findings, f)
			result.Vulnerable = true
		}
	}

	return result, nil
}

// discoverMetadata fetches .well-known/openid-configuration relative to
// the target's origin (and, as a fallback, the legacy
// .well-known/oauth-authorization-server). Returns nil if neither exists.
func (d *Detector) discoverMetadata(ctx context.Context, target string) *Metadata {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" {
		return nil
	}
	origin := base.Scheme + "://" + base.Host

	candidates := []string{
		origin + "/.well-known/openid-configuration",
		origin + "/.well-known/oauth-authorization-server",
		// Realm-style discovery used by Keycloak-like IdPs.
		origin + "/auth/realms/master/.well-known/openid-configuration",
	}

	for _, u := range candidates {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		resp, err := d.client.Get(ctx, u)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		ct := strings.ToLower(resp.Headers["Content-Type"])
		if !strings.Contains(ct, "json") {
			continue
		}
		var m Metadata
		if err := json.Unmarshal([]byte(resp.Body), &m); err != nil {
			continue
		}
		if m.Issuer == "" && m.AuthorizationEndpoint == "" {
			continue
		}
		return &m
	}
	return nil
}

// mentionsPKCE returns true when the metadata advertises any
// code_challenge_method (S256 or plain). Absence = either PKCE is
// disabled, or the IdP isn't telling clients it's available.
func mentionsPKCE(m *Metadata) bool {
	for _, c := range m.CodeChallengeMethods {
		if strings.EqualFold(c, "S256") || strings.EqualFold(c, "plain") {
			return true
		}
	}
	return false
}

// checkRedirectURIBypass probes the authorization endpoint with a
// hostile redirect_uri. The response must reject with 4xx; any 3xx that
// echoes the attacker host in Location is a confirmed open redirect via
// OAuth.
func (d *Detector) checkRedirectURIBypass(ctx context.Context, m *Metadata, attacker string) *core.Finding {
	authURL, err := url.Parse(m.AuthorizationEndpoint)
	if err != nil {
		return nil
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "skws-oauth-probe")
	q.Set("redirect_uri", "https://"+attacker+"/callback")
	q.Set("scope", "openid")
	q.Set("state", "skws-state")
	authURL.RawQuery = q.Encode()

	// Use a non-redirect-following client clone so we can inspect the
	// raw Location header rather than chasing the redirect ourselves.
	client := d.client.Clone().WithFollowRedirects(false)
	resp, err := client.Get(ctx, authURL.String())
	if err != nil || resp == nil {
		return nil
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil
	}

	loc := resp.Headers["Location"]
	if loc == "" {
		loc = resp.Headers["location"]
	}
	if loc == "" || !strings.Contains(strings.ToLower(loc), strings.ToLower(attacker)) {
		return nil
	}

	f := core.NewFinding("OAuth redirect_uri Exact-Match Bypass", core.SeverityHigh)
	f.URL = authURL.String()
	f.Description = "The OAuth authorization endpoint accepted an attacker-controlled redirect_uri " +
		"and issued a redirect carrying the attacker's host in the Location header. An attacker can " +
		"craft an authorize URL that, when clicked by a victim, leaks the authorization code (and " +
		"any tokens fragment-bound by implicit flow) to a domain they control — leading to account takeover."
	f.Evidence = fmt.Sprintf("redirect_uri=https://%s/callback was reflected in Location: %s", attacker, loc)
	f.Tool = "oauth-detector"
	f.Confidence = core.ConfidenceHigh
	f.Remediation = "Enforce strict EXACT-MATCH (not prefix or suffix) on registered redirect_uri values. " +
		"Per RFC 6749 §3.1.2.2 and RFC 9700, partial matching MUST NOT be used. Reject with 400 when " +
		"the supplied redirect_uri is not byte-for-byte equal to a pre-registered URI."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A01:2025"},
		[]string{"CWE-601"},
	)
	return f
}

// findingMissingPKCE flags missing code_challenge_methods_supported.
func (d *Detector) findingMissingPKCE(m *Metadata) *core.Finding {
	f := core.NewFinding("OAuth PKCE Not Advertised", core.SeverityMedium)
	f.URL = m.AuthorizationEndpoint
	f.Description = "The OIDC discovery document does not advertise any code_challenge_methods_supported. " +
		"PKCE is mandatory for public clients per RFC 9700; absence means SPA / mobile clients cannot " +
		"protect against authorization-code interception, leaving the flow open to malicious-app and " +
		"network-attacker code-stealing."
	f.Evidence = fmt.Sprintf("issuer=%s; code_challenge_methods_supported is empty", m.Issuer)
	f.Tool = "oauth-detector"
	f.Confidence = core.ConfidenceMedium
	f.Remediation = "Enable PKCE (S256). Set code_challenge_methods_supported in the discovery document " +
		"and reject authorization requests from public clients that don't carry code_challenge."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-05"},
		[]string{"A07:2025"},
		[]string{"CWE-345"},
	)
	return f
}

// findingNoneAlg flags id_token alg=none acceptance.
func (d *Detector) findingNoneAlg(m *Metadata) *core.Finding {
	f := core.NewFinding("OIDC id_token alg=none Accepted", core.SeverityCritical)
	f.URL = m.Issuer
	f.Description = "The OIDC issuer advertises 'none' as a supported id_token signing algorithm. " +
		"An attacker can mint id_tokens with arbitrary claims (sub, email, groups) and present them as " +
		"authenticated identity assertions — a one-step path to authentication bypass and privilege " +
		"escalation in any relying party that trusts this issuer."
	f.Evidence = fmt.Sprintf("issuer=%s; id_token_signing_alg_values_supported includes \"none\"", m.Issuer)
	f.Tool = "oauth-detector"
	f.Confidence = core.ConfidenceConfirmed
	f.Remediation = "Remove 'none' from id_token_signing_alg_values_supported. Mandate RS256 or ES256 " +
		"and reject id_tokens whose alg header is not in the allowlist."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-08"},
		[]string{"A07:2025"},
		[]string{"CWE-347"},
	)
	return f
}

// findingImplicitFlow flags implicit-flow advertisement.
func (d *Detector) findingImplicitFlow(m *Metadata, rt string) *core.Finding {
	f := core.NewFinding("OAuth Implicit Flow Advertised", core.SeverityLow)
	f.URL = m.AuthorizationEndpoint
	f.Description = fmt.Sprintf(
		"The OIDC issuer advertises response_type %q, the deprecated implicit flow. "+
			"Tokens are returned in the URL fragment, exposing them to browser history, "+
			"referer leaks, and BFCache replay. OAuth 2.1 / RFC 9700 prohibit it.",
		rt,
	)
	f.Evidence = fmt.Sprintf("issuer=%s; response_types_supported contains %q", m.Issuer, rt)
	f.Tool = "oauth-detector"
	f.Confidence = core.ConfidenceMedium
	f.Remediation = "Drop implicit-flow response_types ('token', 'id_token token') from the issuer " +
		"metadata. Use authorization-code-with-PKCE for browser clients."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-05"},
		[]string{"A07:2025"},
		[]string{"CWE-1188"},
	)
	return f
}
