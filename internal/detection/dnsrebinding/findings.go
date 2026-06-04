package dnsrebinding

import (
	"context"
	"fmt"
	"net"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// toctouProbe issues two consecutive requests against the configured
// rebinding test host. If both fetches succeed we report High severity:
// the server made no attempt to pin DNS between the allowlist check and
// the actual fetch.
func (d *Detector) toctouProbe(ctx context.Context, targetURL, ssrfParam, host string, baseline *http.Response, baselineErr error) *core.Finding {
	payloadURL := "http://" + host + "/"
	resp1, err1 := d.client.SendPayload(ctx, targetURL, ssrfParam, payloadURL, "GET")
	resp2, err2 := d.client.SendPayload(ctx, targetURL, ssrfParam, payloadURL, "GET")

	if err1 != nil || err2 != nil || resp1 == nil || resp2 == nil {
		return nil
	}
	if !looksLikeFetchSuccess(resp1, baseline, baselineErr) || !looksLikeFetchSuccess(resp2, baseline, baselineErr) {
		return nil
	}

	f := core.NewFinding(TypeTOCTOU, core.SeverityHigh).At(targetURL, ssrfParam)
	f.Tool = toolName
	f.Description = fmt.Sprintf(
		"Server consistently fetched the rebinding test host %q across consecutive "+
			"requests, indicating no DNS pinning between allowlist validation and the "+
			"actual fetch. Susceptible to a real DNS-rebinding TOCTOU attack.",
		host,
	)
	f.Evidence = fmt.Sprintf("Probe URL: %s\nResp1 status: %d\nResp2 status: %d", payloadURL, resp1.StatusCode, resp2.StatusCode)
	f.Remediation = "Resolve the URL once, pin to the resolved IP, then enforce the IP " +
		"allowlist on the pinned address. Reject responses whose final remote IP differs " +
		"from the validated one."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-19"},
		[]string{"A01:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}

// toctouInformationalFinding emits the "TOCTOU probe skipped" placeholder
// when the operator has not configured a rebinding test host.
func (d *Detector) toctouInformationalFinding(targetURL, ssrfParam string) *core.Finding {
	f := core.NewFinding(TypeTOCTOU, core.SeverityInfo).At(targetURL, ssrfParam)
	f.Tool = toolName
	f.Description = "TOCTOU rebinding probe skipped: no operator-controlled rebinding test " +
		"host was configured. Set DetectOptions.RebindingTestHost to a hostname you " +
		"control to confirm whether the server pins DNS between validation and fetch."
	f.Remediation = "If your application accepts user-supplied URLs, resolve the host once " +
		"and reuse the resolved IP for the actual outbound request (DNS pinning)."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-19"},
		[]string{"A01:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}

// buildShortTTLFinding constructs the finding emitted by
// DetectShortTTLMultiIP. The reason string is folded from the
// mixedSingle / changed flags.
func (d *Detector) buildShortTTLFinding(targetURL, host string, r1, r2 []net.IPAddr, mixedSingle, changed bool) *core.Finding {
	f := core.NewFinding(TypeShortTTLMultiIP, core.SeverityMedium)
	f.URL = targetURL
	f.Tool = toolName

	reason := "mixed-scope multi-IP A-record"
	if changed && !mixedSingle {
		reason = "A-record changed between consecutive resolutions and combined set mixes public and private scope"
	} else if changed && mixedSingle {
		reason = "mixed-scope multi-IP record AND A-record changed between resolutions"
	}

	f.Description = fmt.Sprintf(
		"Hostname %q presents a DNS configuration consistent with rebinding "+
			"attacks (%s). An attacker controlling such a record can alternate "+
			"between a public and an internal IP to bypass SSRF allowlists that "+
			"validate the hostname/IP only at request time.",
		host, reason,
	)
	f.Evidence = fmt.Sprintf("Resolution 1: %s\nResolution 2: %s", joinIPs(r1), joinIPs(r2))
	f.Remediation = "Resolve the hostname once during validation, pin the resulting IP " +
		"address, and reuse it for the outbound request. Reject hostnames whose A-record " +
		"contains private or loopback addresses."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-19"},
		[]string{"A01:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}

// buildAllowlistBypassFinding constructs the finding emitted by the
// rebinding-friendly hostname probe loop in DetectAllowlistBypass.
func (d *Detector) buildAllowlistBypassFinding(targetURL, ssrfParam, hostname string, resp *http.Response) *core.Finding {
	f := core.NewFinding(TypeAllowlistBypass, core.SeverityCritical).At(targetURL, ssrfParam)
	f.Tool = toolName
	f.Description = fmt.Sprintf(
		"Server accepted and fetched a request to %q, a hostname that resolves to a "+
			"private/loopback address. The URL allowlist relies on hostname strings rather "+
			"than the resolved IP and is bypassable by any attacker-controlled DNS record.",
		hostname,
	)
	body := resp.Body
	if len(body) > 300 {
		body = body[:300] + "..."
	}
	f.Evidence = fmt.Sprintf("Hostname: %s\nResponse status: %d\nResponse snippet: %s", hostname, resp.StatusCode, body)
	f.Remediation = "Resolve the user-supplied hostname, then evaluate the allowlist on the " +
		"resolved IP (rejecting RFC1918, loopback, link-local, and cloud-metadata ranges). " +
		"Pin the resolved IP for the actual fetch to prevent rebinding."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-19"},
		[]string{"A01:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}
