// Package samlinj probes a SAML SSO endpoint for two well-known
// validator-bypass classes:
//
//   - XML signature wrapping (XSW): the original signed Assertion is
//     kept (so signature validation passes) but the SP reads attributes
//     from a sibling Assertion the attacker injected. The PortSwigger
//     and CIS-Cat write-ups cover this in detail.
//   - XML comment injection: an `<!-- comment -->` placed inside the
//     signed NameID text-content makes some XML parsers truncate the
//     value at the comment, while the signature still validates over
//     the original bytes — flipping `victim@x.com<!--ignore-->@evil.com`
//     into the `victim@x.com` identity at the SP.
//
// Detection is shape-based: we POST a malformed-but-recognisable
// SAMLResponse to the candidate endpoint and watch for parser-level
// success (200 + a SAML-style redirect / set-cookie). The detector
// does not hold a real signing key — its goal is to surface endpoints
// that don't reject the malformed input outright, which is the gate
// the deeper attack depends on.
package samlinj

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// candidatePaths covers the SP-side endpoints SAML deployments expose.
var candidatePaths = []string{
	"/saml/acs", "/saml/SSO", "/saml/SSO/POST",
	"/saml2/acs", "/sso/acs", "/SAML2/SSO/POST",
	"/Shibboleth.sso/SAML2/POST",
	"/auth/saml/callback", "/auth/saml2/callback",
}

// xswPayload is a minimal XSW-shaped SAMLResponse: an outer Response
// element containing two Assertion siblings, the second of which
// declares the attacker's NameID. Real attacks need a real signature
// over the first assertion; this probe just wants to see if the SP
// accepts the malformed envelope at all.
const xswPayload = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z" Destination="REPLACE_DEST" ID="r1">
  <saml:Issuer>https://idp.example/</saml:Issuer>
  <saml:Assertion ID="a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>victim@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="a2" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>attacker@evil.example</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>`

// commentPayload uses comment injection in the NameID. A vulnerable
// parser would extract "victim@example.com" while the signature still
// validates over the full attacker-controlled bytes.
const commentPayload = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z" Destination="REPLACE_DEST" ID="r1">
  <saml:Issuer>https://idp.example/</saml:Issuer>
  <saml:Assertion ID="a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>victim@example.com<!--skws-comment-->@evil.example</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>`

// Detector probes for SAML-injection-friendly endpoints.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings from Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect tests every candidate ACS path for shape-level acceptance of
// the malformed SAMLResponse. A 2xx (or 302 with a session cookie)
// response indicates the SP parsed the envelope without rejecting it
// outright — the necessary precondition for both XSW and comment-
// injection attacks. False-positive risk is tempered by ignoring
// 4xx/5xx responses entirely.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	for _, path := range candidatePaths {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		probe := *base
		probe.Path = path
		probe.RawQuery = ""

		// Test XSW envelope.
		if hit, severity := d.probe(ctx, probe.String(), xswPayload); hit {
			res.Findings = append(res.Findings, buildFinding(probe.String(), path, "xml-signature-wrapping", severity))
		}
		// Test comment-injection envelope.
		if hit, severity := d.probe(ctx, probe.String(), commentPayload); hit {
			res.Findings = append(res.Findings, buildFinding(probe.String(), path, "xml-comment-injection", severity))
		}
	}
	return res, nil
}

// probe POSTs a SAMLResponse=base64(payload) form body, mimicking the
// HTTP-POST binding most SPs accept. Returns (hit, severity) — the
// detector emits Medium when the SP accepts the malformed envelope
// without 4xx-rejecting it. We disable redirect-following so the
// SP's immediate 302 (typical post-login flow) reaches us as 302
// rather than the final dashboard page.
func (d *Detector) probe(ctx context.Context, target, payload string) (bool, core.Severity) {
	body := payload
	body = strings.ReplaceAll(body, "REPLACE_DEST", target)
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	form := "SAMLResponse=" + url.QueryEscape(encoded) + "&RelayState=skws"
	noRedirect := d.client.Clone().WithFollowRedirects(false)
	resp, err := noRedirect.SendRawBody(ctx, target, "POST", form, "application/x-www-form-urlencoded")
	if err != nil || resp == nil {
		return false, core.SeverityInfo
	}
	if resp.StatusCode >= 400 {
		return false, core.SeverityInfo
	}
	// 2xx + session cookie OR 302 redirect = SP processed the envelope.
	if resp.StatusCode == 302 || resp.StatusCode == 303 {
		return true, core.SeverityMedium
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// 2xx alone is weaker — a flat error page also returns 2xx
		// on some SPs. Require body to mention SAML or session.
		lower := strings.ToLower(resp.Body)
		if strings.Contains(lower, "saml") || strings.Contains(lower, "session") || strings.Contains(lower, "logged") {
			return true, core.SeverityMedium
		}
	}
	return false, core.SeverityInfo
}

func buildFinding(target, path, kind string, severity core.Severity) *core.Finding {
	finding := core.NewFinding("SAML Validator Bypass Surface ("+kind+")", severity)
	finding.URL = target
	finding.Parameter = path
	finding.Tool = "samlinj"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = fmt.Sprintf(
		"The SAML SP at %s accepted a malformed SAMLResponse without 4xx-rejecting it. The shape we sent (%s) is the canonical precondition for XML-signature-wrapping or XML-comment-injection attacks; SPs that strictly reject malformed envelopes return 4xx instead.",
		path, kind,
	)
	finding.Evidence = "Path: " + path + "\nProbe: " + kind + "\nSP did not 4xx-reject the malformed SAMLResponse."
	finding.Remediation = "Ensure the SAML library you use rejects responses with multiple Assertion elements when only one is signed (XSW), and uses an XML parser that fails closed on comment nodes inside text content. Pin the IDP's signing certificate; reject responses signed by anything else. Validate Destination, AudienceRestriction, and NotOnOrAfter strictly."
	finding.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2025"},
		[]string{"CWE-347"},
	)
	finding.APITop10 = []string{"API2:2023"}
	return finding
}
