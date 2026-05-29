package webauthn

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector probes a target for WebAuthn / FIDO2 endpoints. This is a
// discovery-only detector: it surfaces the existence of WebAuthn
// surface area and flags the configurable policy choices that matter
// (RP-ID, attestation policy, signature-counter handling) so a human
// auditor knows where to look. Active flow-level exploitation requires
// a registered authenticator and is out of scope for an unauthenticated
// scanner.
//
// Findings emitted:
//   - Informational when a WebAuthn endpoint is discovered.
//   - Medium when the registration options response shows policy
//     choices that have known footguns (attestation="none" /
//     "indirect", userVerification="discouraged").
type Detector struct {
	client  *http.Client
	verbose bool
}

// New constructs a Detector.
func New(client *http.Client) *Detector {
	if client == nil {
		client = http.DefaultClient
	}
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the probe.
type DetectOptions struct {
	Timeout time.Duration
	// MaxBodyBytes caps the inspected response body. WebAuthn responses
	// are typically small (< 4 KiB).
	MaxBodyBytes int64
	// MaxEndpoints caps how many of the CommonEndpoints() wordlist
	// entries are probed against the target. Default 0 = all.
	MaxEndpoints int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:      6 * time.Second,
		MaxBodyBytes: 16 << 10,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Found      []string // discovered WebAuthn endpoint paths
	Findings   []*core.Finding
	Vulnerable bool // true if any policy-footgun was flagged; informational findings alone do not set this
}

// Detect probes the target host for WebAuthn-shaped endpoints.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 16 << 10
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parse URL: %w", err)
	}
	base := u.Scheme + "://" + u.Host

	result := &DetectionResult{URL: target}

	endpoints := CommonEndpoints()
	if opts.MaxEndpoints > 0 && len(endpoints) > opts.MaxEndpoints {
		endpoints = endpoints[:opts.MaxEndpoints]
	}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		probeURL := base + ep
		body, status, ok := d.probe(ctx, probeURL, opts)
		if !ok {
			continue
		}
		if !looksLikeWebAuthn(body, status) {
			continue
		}
		result.Found = append(result.Found, ep)
		result.Findings = append(result.Findings, d.discoveryFinding(probeURL, body))

		if footguns := policyFootguns(body); len(footguns) > 0 {
			result.Vulnerable = true
			result.Findings = append(result.Findings, d.policyFinding(probeURL, footguns))
		}
	}
	return result, nil
}

// probe issues a single GET to the candidate endpoint and returns the
// body + status. The third return is false on transport errors.
func (d *Detector) probe(ctx context.Context, target string, opts DetectOptions) (string, int, bool) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return "", 0, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	return string(body), resp.StatusCode, true
}

// looksLikeWebAuthn returns true when the response body or status code
// strongly suggests a WebAuthn endpoint. Recognises both the FIDO2
// server reference shape (challenge / pubKeyCredParams / authenticator
// selection) and the simpler Yubico-style server shape.
func looksLikeWebAuthn(body string, status int) bool {
	// 405 is common when the endpoint exists but rejects GET — a real
	// WebAuthn endpoint usually only accepts POST. We treat 405 as a
	// soft positive, paired with body inspection below.
	if status == 0 {
		return false
	}
	for _, fp := range ErrorPatterns() {
		if strings.Contains(body, fp) {
			return true
		}
	}
	// JSON envelope indicators that show up even on 4xx responses.
	jsonIndicators := []string{
		`"publicKey"`,
		`"challenge"`,
		`"pubKeyCredParams"`,
		`"rp":{`,
		`"user":{`,
		`"attestation"`,
		`"authenticatorSelection"`,
	}
	for _, ind := range jsonIndicators {
		if strings.Contains(body, ind) {
			return true
		}
	}
	return false
}

// policyFootguns scans the body for explicit RP-side policy choices
// known to weaken passkey security. Returns a slice of short labels for
// each footgun found.
func policyFootguns(body string) []string {
	var found []string
	if strings.Contains(body, `"attestation":"none"`) || strings.Contains(body, `"attestation": "none"`) {
		found = append(found, "attestation=none (no authenticator provenance check)")
	}
	if strings.Contains(body, `"attestation":"indirect"`) || strings.Contains(body, `"attestation": "indirect"`) {
		found = append(found, "attestation=indirect (provenance accepted from anonymous CA)")
	}
	if strings.Contains(body, `"userVerification":"discouraged"`) || strings.Contains(body, `"userVerification": "discouraged"`) {
		found = append(found, "userVerification=discouraged (phishing-resistance not enforced)")
	}
	if strings.Contains(body, `"residentKey":"discouraged"`) || strings.Contains(body, `"residentKey": "discouraged"`) {
		found = append(found, "residentKey=discouraged (passkey/discoverable-credential support disabled)")
	}
	// RP-ID that doesn't include a dot (single-label) — usually a
	// development misconfiguration. Spec allows it but most production
	// deployments should have a registrable suffix.
	if strings.Contains(body, `"rp":{"id":"localhost"`) {
		found = append(found, `RP-ID="localhost" (likely development config exposed to production)`)
	}
	return found
}

func (d *Detector) discoveryFinding(target, body string) *core.Finding {
	f := core.NewFinding("webauthn_endpoint_discovered", core.SeverityInfo)
	f.Tool = "webauthn"
	f.URL = target
	f.Title = "WebAuthn / FIDO2 endpoint discovered"
	f.Confidence = core.ConfidenceHigh
	f.Description = "A WebAuthn-shaped endpoint was discovered at this URL. Audit the server-side verification logic (origin pinning, RP-ID equality, signature-counter monotonicity, attestation policy enforcement, credential-ID-to-user binding). The flow-level payload bank in internal/payloads/webauthn covers the most common server-side WebAuthn flaws."
	bodySnippet := body
	if len(bodySnippet) > 256 {
		bodySnippet = bodySnippet[:256] + "..."
	}
	f.Evidence = "body snippet: " + bodySnippet
	f.Remediation = "Verify the implementation against the FIDO2 server test suite (https://github.com/google/webauthndemo or webauthn.io). Pin origin and RP-ID with byte-exact comparison; enforce signature-counter monotonicity; reject credentialIDs not bound to the calling user."
	f.References = []string{
		"https://www.w3.org/TR/webauthn-3/",
		"https://webauthn.guide/",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2021"},
		[]string{"CWE-287"},
	)
	return f
}

func (d *Detector) policyFinding(target string, footguns []string) *core.Finding {
	f := core.NewFinding("webauthn_weak_policy", core.SeverityMedium)
	f.Tool = "webauthn"
	f.URL = target
	f.Title = "WebAuthn policy choices weaken passkey security"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The registration / authentication options exposed by this WebAuthn endpoint include policy values that are known to weaken the phishing-resistance / attestation guarantees passkeys provide:\n  - " + strings.Join(footguns, "\n  - ")
	f.Evidence = strings.Join(footguns, "; ")
	f.Metadata["footguns"] = footguns
	f.Remediation = "Set attestation=\"direct\" (or at minimum \"indirect\" with a known-CA filter), userVerification=\"required\" or \"preferred\", and residentKey=\"required\" or \"preferred\" so the WebAuthn flow actually delivers its security promises. Set RP-ID to the production registrable domain — never \"localhost\" in production."
	f.References = []string{
		"https://www.w3.org/TR/webauthn-3/#sctn-attestation",
		"https://www.imperialviolet.org/2022/09/22/passkeys.html",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2021"},
		[]string{"CWE-287"},
	)
	return f
}
