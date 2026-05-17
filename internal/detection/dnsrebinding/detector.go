package dnsrebinding

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detection type strings (exposed as constants because they appear in
// findings and tests assert against them).
const (
	// TypeShortTTLMultiIP labels findings raised by the short-TTL /
	// mixed-scope multi-IP heuristic.
	TypeShortTTLMultiIP = "DNS Rebinding Susceptible (Short TTL Multi-IP)"
	// TypeAllowlistBypass labels findings where the application accepted
	// a request to a hostname that resolves into a private/loopback IP
	// (rebinding-friendly DNS service).
	TypeAllowlistBypass = "SSRF Allowlist Bypass via Hostname Resolution"
	// TypeTOCTOU labels findings raised by the consecutive-request TOCTOU
	// probe against a configured rebinding test host.
	TypeTOCTOU = "DNS Rebinding TOCTOU Window Susceptibility"

	toolName = "dnsrebinding-detector"
)

// rebindBypassHosts is the curated list of public wildcard-DNS hostnames
// that resolve to RFC1918 / loopback addresses. A target that fetches any
// of these has effectively no DNS-based allowlist enforcement.
var rebindBypassHosts = []string{
	"localtest.me",           // -> 127.0.0.1
	"127.0.0.1.nip.io",       // -> 127.0.0.1
	"10.0.0.1.nip.io",        // -> 10.0.0.1
	"169.254.169.254.nip.io", // -> 169.254.169.254 (cloud metadata)
	"127.0.0.1.xip.io",       // legacy xip.io (may be defunct, included for completeness)
}

// baselineBogusHost is a guaranteed-nonexistent hostname used to establish
// "what does a failed fetch look like?" against the target endpoint.
const baselineBogusHost = "definitely-not-a-real-host-12345.invalid"

// Resolver is the minimal DNS surface this package needs. Defining it as
// an interface lets tests inject canned answers without going to the
// network.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Detector performs DNS-rebinding susceptibility detection.
type Detector struct {
	client   *http.Client
	resolver Resolver
}

// New constructs a Detector with the default system resolver.
func New(client *http.Client) *Detector {
	return &Detector{
		client:   client,
		resolver: net.DefaultResolver,
	}
}

// WithResolver overrides the resolver (primarily for tests).
func (d *Detector) WithResolver(r Resolver) *Detector {
	d.resolver = r
	return d
}

// DetectOptions configures a detection run.
type DetectOptions struct {
	// SSRFParam is the request parameter that accepts a URL (required for
	// the allowlist-bypass leg).
	SSRFParam string
	// RebindingTestHost, when set, is the operator-controlled hostname
	// used to perform the TOCTOU probe. Empty means we only emit an
	// Informational note.
	RebindingTestHost string
	// Timeout caps each individual probe request.
	Timeout time.Duration
	// EmitInformational controls whether we surface the "TOCTOU probe
	// skipped" informational finding when RebindingTestHost is empty.
	EmitInformational bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:           10 * time.Second,
		EmitInformational: false,
	}
}

// DetectionResult is the aggregated outcome of a detector method.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// DetectShortTTLMultiIP probes the target's hostname for short-TTL or
// mixed-scope DNS records. The check is heuristic: stdlib does not expose
// TTL, so we simulate "short TTL" by doing two resolutions within a 5s
// window and treating any change as evidence of a very short TTL.
func (d *Detector) DetectShortTTLMultiIP(ctx context.Context, targetURL string) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectionType: TypeShortTTLMultiIP,
		Findings:      []*core.Finding{},
	}

	host, err := hostFromURL(targetURL)
	if err != nil {
		return result, err
	}
	if host == "" {
		return result, errors.New("targetURL has no host")
	}
	// Skip when the host is a literal IP — DNS rebinding requires a name.
	if net.ParseIP(host) != nil {
		return result, nil
	}

	round1, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return result, fmt.Errorf("dns lookup failed: %w", err)
	}

	// Second resolution within a short window simulates the TTL probe.
	round2, err2 := d.resolver.LookupIPAddr(ctx, host)
	if err2 != nil {
		// Non-fatal: we can still evaluate round1 alone.
		round2 = nil
	}

	allIPs := append([]net.IPAddr{}, round1...)
	allIPs = append(allIPs, round2...)

	hasPrivate, hasPublic := classifyScope(allIPs)
	changedBetweenRounds := ipsChanged(round1, round2)

	// Flag when round-to-round answers differ AND the combined set mixes
	// private + public scopes, OR when a single round already contains
	// both scopes (the classic multi-IP rebinding setup).
	mixedSingleRound := hasPrivate && hasPublic
	if !(mixedSingleRound || (changedBetweenRounds && hasPrivate && hasPublic)) {
		return result, nil
	}

	f := d.buildShortTTLFinding(targetURL, host, round1, round2, mixedSingleRound, changedBetweenRounds)
	result.Findings = append(result.Findings, f)
	result.Vulnerable = true
	return result, nil
}

// DetectAllowlistBypass probes the SSRF endpoint with rebinding-friendly
// hostnames and (optionally) with a configured rebinding test host to
// estimate TOCTOU exposure.
func (d *Detector) DetectAllowlistBypass(ctx context.Context, targetURL, ssrfParam string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectionType: TypeAllowlistBypass,
		Findings:      []*core.Finding{},
	}

	if ssrfParam == "" {
		return result, errors.New("ssrfParam is required")
	}
	if d.client == nil {
		return result, errors.New("http client is nil")
	}

	probeCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, opts.Timeout*time.Duration(len(rebindBypassHosts)+3))
		defer cancel()
	}

	// 1. Baseline: send an obviously-bogus host. Most servers will fail
	//    or 5xx; that "failure shape" is what we compare against.
	baseline, baselineErr := d.client.SendPayload(probeCtx, targetURL, ssrfParam, "http://"+baselineBogusHost+"/", "GET")

	// 2. For each rebinding-friendly host, see whether the server fetched
	//    it (response differs from baseline in a "successful fetch" way).
	for _, h := range rebindBypassHosts {
		select {
		case <-probeCtx.Done():
			return result, probeCtx.Err()
		default:
		}

		payloadURL := "http://" + h + "/"
		resp, err := d.client.SendPayload(probeCtx, targetURL, ssrfParam, payloadURL, "GET")
		if err != nil || resp == nil {
			continue
		}
		if !looksLikeFetchSuccess(resp, baseline, baselineErr) {
			continue
		}
		result.Findings = append(result.Findings, d.buildAllowlistBypassFinding(targetURL, ssrfParam, h, resp))
		result.Vulnerable = true
	}

	// 3. TOCTOU probe.
	if opts.RebindingTestHost != "" {
		toctouFinding := d.toctouProbe(probeCtx, targetURL, ssrfParam, opts.RebindingTestHost, baseline, baselineErr)
		if toctouFinding != nil {
			result.Findings = append(result.Findings, toctouFinding)
			if toctouFinding.Severity == core.SeverityHigh {
				result.Vulnerable = true
			}
		}
	} else if opts.EmitInformational {
		result.Findings = append(result.Findings, d.toctouInformationalFinding(targetURL, ssrfParam))
	}

	return result, nil
}

// DetectAll runs every available DNS-rebinding check and aggregates the
// findings.
func (d *Detector) DetectAll(ctx context.Context, targetURL, ssrfParam string, opts DetectOptions) (*DetectionResult, error) {
	combined := &DetectionResult{
		DetectionType: "DNS Rebinding (All)",
		Findings:      []*core.Finding{},
	}

	if r, err := d.DetectShortTTLMultiIP(ctx, targetURL); err == nil && r != nil {
		combined.Findings = append(combined.Findings, r.Findings...)
		if r.Vulnerable {
			combined.Vulnerable = true
		}
	}

	if ssrfParam != "" {
		if r, err := d.DetectAllowlistBypass(ctx, targetURL, ssrfParam, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
			if r.Vulnerable {
				combined.Vulnerable = true
			}
		}
	}

	return combined, nil
}

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

	f := core.NewFinding(TypeTOCTOU, core.SeverityHigh)
	f.URL = targetURL
	f.Parameter = ssrfParam
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
		[]string{"A10:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}

func (d *Detector) toctouInformationalFinding(targetURL, ssrfParam string) *core.Finding {
	f := core.NewFinding(TypeTOCTOU, core.SeverityInfo)
	f.URL = targetURL
	f.Parameter = ssrfParam
	f.Tool = toolName
	f.Description = "TOCTOU rebinding probe skipped: no operator-controlled rebinding test " +
		"host was configured. Set DetectOptions.RebindingTestHost to a hostname you " +
		"control to confirm whether the server pins DNS between validation and fetch."
	f.Remediation = "If your application accepts user-supplied URLs, resolve the host once " +
		"and reuse the resolved IP for the actual outbound request (DNS pinning)."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-19"},
		[]string{"A10:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}

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
		[]string{"A10:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}

func (d *Detector) buildAllowlistBypassFinding(targetURL, ssrfParam, hostname string, resp *http.Response) *core.Finding {
	f := core.NewFinding(TypeAllowlistBypass, core.SeverityCritical)
	f.URL = targetURL
	f.Parameter = ssrfParam
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
		[]string{"A10:2025"},
		[]string{"CWE-918", "CWE-350"},
	)
	return f
}

// hostFromURL extracts the hostname portion of a URL, returning an error
// only when the URL is unparseable.
func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	h := u.Hostname()
	if h == "" {
		// Treat "no host" as an empty hostname rather than an error so
		// the caller can decide; but also surface as an error when the
		// original string didn't even contain a scheme.
		if !strings.Contains(raw, "://") {
			return "", fmt.Errorf("URL %q has no scheme", raw)
		}
	}
	return h, nil
}

// classifyScope returns whether the given IPs contain any private/loopback
// (hasPrivate) and any public-routable (hasPublic) addresses.
func classifyScope(ips []net.IPAddr) (hasPrivate, hasPublic bool) {
	for _, a := range ips {
		if a.IP == nil {
			continue
		}
		if isPrivateOrSpecial(a.IP) {
			hasPrivate = true
		} else {
			hasPublic = true
		}
	}
	return
}

// isPrivateOrSpecial reports whether the IP belongs to a scope an SSRF
// allowlist would normally reject.
func isPrivateOrSpecial(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// 169.254.169.254 / 100.100.100.200 are already covered by IsLinkLocalUnicast.
	return false
}

// ipsChanged reports whether the two resolutions returned different sets.
func ipsChanged(a, b []net.IPAddr) bool {
	if len(b) == 0 {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, x := range a {
		seen[x.IP.String()] = true
	}
	for _, y := range b {
		if !seen[y.IP.String()] {
			return true
		}
	}
	// Symmetric check.
	seenB := make(map[string]bool, len(b))
	for _, y := range b {
		seenB[y.IP.String()] = true
	}
	for _, x := range a {
		if !seenB[x.IP.String()] {
			return true
		}
	}
	return false
}

func joinIPs(ips []net.IPAddr) string {
	if len(ips) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ips))
	for _, a := range ips {
		parts = append(parts, a.IP.String())
	}
	return strings.Join(parts, ", ")
}

// looksLikeFetchSuccess reports whether resp looks meaningfully different
// from the baseline-bogus response in a way that suggests the server did
// in fact fetch the URL.
func looksLikeFetchSuccess(resp, baseline *http.Response, baselineErr error) bool {
	if resp == nil {
		return false
	}
	// A 2xx response strongly suggests success.
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	if baseline == nil || baselineErr != nil {
		// No baseline to compare against — fall back to "2xx with body".
		return is2xx && len(resp.Body) > 0
	}
	if resp.StatusCode == baseline.StatusCode {
		// Same status — only call it success if the body diverged
		// noticeably.
		return len(resp.Body) > 0 && len(resp.Body) != len(baseline.Body) && is2xx
	}
	// Different status: 2xx vs anything else is a strong signal.
	return is2xx
}
