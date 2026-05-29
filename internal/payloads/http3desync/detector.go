package http3desync

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector is a discovery-only probe: it identifies that a target
// advertises HTTP/3 support (Alt-Svc), records the upstream stack from
// the Server header, and emits an Informational finding showing the H3
// desync attack surface that opens up. Active QUIC-level desync
// payloads are NOT fired here — the standard library doesn't ship a
// QUIC/H3 transport, and a single H3 desync probe is enough to
// destabilise the upstream stack on misconfigured deployments.
//
// Findings emitted:
//   - Informational when H3 is advertised. Lists the FrameMarkers /
//     techniques the operator should watch for during their own
//     fuzz pass.
//   - Medium when H3 is advertised AND the Server header identifies an
//     upstream known to have shipped H3 implementations with public
//     desync CVEs in the last 24 months.
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
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 6 * time.Second}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL            string
	H3Advertised   bool
	AltSvcValue    string
	ServerHeader   string
	UpstreamKnown  string // identified upstream label, if known
	Findings       []*core.Finding
	Vulnerable     bool
}

// Detect probes the target for HTTP/3 advertisement and upstream
// fingerprint.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	result := &DetectionResult{URL: target}

	resp, err := d.head(ctx, target, opts.Timeout)
	if err != nil || resp == nil {
		return result, err
	}
	defer resp.Body.Close()

	for _, h := range DiscoveryHeaders() {
		if v := resp.Header.Get(h); v != "" {
			if isH3Advertisement(v) {
				result.H3Advertised = true
				result.AltSvcValue = v
				break
			}
		}
	}

	if !result.H3Advertised {
		return result, nil
	}

	result.ServerHeader = resp.Header.Get("Server")
	result.UpstreamKnown = identifyUpstream(result.ServerHeader)

	result.Findings = append(result.Findings, d.discoveryFinding(target, result))
	if result.UpstreamKnown != "" {
		result.Vulnerable = true
		result.Findings = append(result.Findings, d.upstreamFinding(target, result))
	}
	return result, nil
}

func (d *Detector) head(ctx context.Context, target string, timeout time.Duration) (*http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return d.client.Do(req)
}

// isH3Advertisement reports whether the Alt-Svc / equivalent header
// value advertises HTTP/3 support. Per RFC 9114 §3.1.1 the canonical
// form is `h3=":443"; ma=86400`, with `h3-29` / `h3-32` etc. used by
// older drafts that some servers still emit.
func isH3Advertisement(value string) bool {
	lv := strings.ToLower(value)
	tokens := []string{"h3=", "h3-29", "h3-31", "h3-32", "h3-33", "h3-34"}
	for _, t := range tokens {
		if strings.Contains(lv, t) {
			return true
		}
	}
	return false
}

// identifyUpstream returns a non-empty label when the Server header
// matches a server stack that has shipped publicly-known H3 desync
// CVEs in the last 24 months. Empty string means "unknown / not in
// the at-risk list".
func identifyUpstream(server string) string {
	if server == "" {
		return ""
	}
	ls := strings.ToLower(server)
	cases := []struct {
		match string
		label string
	}{
		// nginx-quic / boringSSL stack: multiple CVEs around stream
		// reset and 0-RTT handling.
		{"nginx", "nginx (quic / 0-RTT replay CVE-2024-31079)"},
		// Apache + mod_http3 still experimental as of 2.4.59.
		{"apache", "Apache httpd mod_http3 (experimental, pre-2.4.60)"},
		// LiteSpeed: lsquic 3.x had several QPACK-decoder CVEs.
		{"litespeed", "LiteSpeed (lsquic <3.4 QPACK decoder CVEs)"},
		// Cloudflare quiche: prior cf-quiche CVE around CONNECT-UDP.
		{"cloudflare", "Cloudflare quiche (cf-quiche CVE-2024-2456 CONNECT-UDP)"},
		// Envoy + quic-go: H3 desync research from PortSwigger 2023.
		{"envoy", "Envoy QUIC (PortSwigger 2023 desync research)"},
		// Caddy uses quic-go; quic-go shipped a 0-RTT replay fix mid-2024.
		{"caddy", "Caddy / quic-go (CVE-2024-22189 0-RTT replay)"},
	}
	for _, c := range cases {
		if strings.Contains(ls, c.match) {
			return c.label
		}
	}
	return ""
}

func (d *Detector) discoveryFinding(target string, r *DetectionResult) *core.Finding {
	f := core.NewFinding("h3_advertised", core.SeverityInfo)
	f.Tool = "http3desync"
	f.URL = target
	f.Title = "Target advertises HTTP/3 — desync attack surface present"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The target advertised HTTP/3 support via Alt-Svc. HTTP/3 inherits HTTP/2's framing-level desync surface plus QUIC-specific twists (stream-split early FIN, QPACK desync, 0-RTT replay, CONNECT-UDP smuggle, field-section-size mismatch). The standard library does not ship an H3 client, so this scanner cannot fire active QUIC desync probes; the internal/payloads/http3desync bank documents the canonical attack frames for use with quiche-client / h3-shooter / custom QUIC tooling."
	f.Evidence = fmt.Sprintf("Alt-Svc: %s; Server: %s", r.AltSvcValue, r.ServerHeader)
	f.Metadata["alt_svc"] = r.AltSvcValue
	f.Metadata["server_header"] = r.ServerHeader
	f.Remediation = "Audit the H3 implementation against the active CVE list for your upstream stack. Disable HTTP/3 in front of legacy back-ends that don't speak it natively (H3 → H2 → H1 translation chains are where the desync surface lives). Set strict SETTINGS_MAX_FIELD_SECTION_SIZE alignment between front-end and back-end."
	f.References = []string{
		"https://portswigger.net/research/http-3-the-shame-of-it-all",
		"https://datatracker.ietf.org/doc/html/rfc9114",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-15"},
		[]string{"A05:2021"},
		[]string{"CWE-444"},
	)
	return f
}

func (d *Detector) upstreamFinding(target string, r *DetectionResult) *core.Finding {
	f := core.NewFinding("h3_upstream_known_vuln", core.SeverityMedium)
	f.Tool = "http3desync"
	f.URL = target
	f.Title = "HTTP/3 advertised on an upstream with known desync CVEs"
	f.Confidence = core.ConfidenceMedium
	f.Description = "The upstream identified from the Server header has shipped publicly-known HTTP/3 desync CVEs within the last 24 months: " + r.UpstreamKnown + ". Verify the running version is patched against the cited advisory."
	f.Evidence = "Server: " + r.ServerHeader + "; identified as: " + r.UpstreamKnown
	f.Metadata["upstream"] = r.UpstreamKnown
	f.Remediation = "Upgrade the upstream to a version that includes the cited fix. For nginx-quic verify CVE-2024-31079. For Cloudflare quiche verify CVE-2024-2456. For quic-go (Caddy / others) verify CVE-2024-22189."
	f.References = []string{
		"https://nvd.nist.gov/vuln/search?form_type=Basic&query=quic+desync",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-15"},
		[]string{"A06:2021"},
		[]string{"CWE-444"},
	)
	return f
}
