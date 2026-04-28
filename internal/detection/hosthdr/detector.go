// Package hosthdr detects Host-header injection vulnerabilities:
// reflected Host in absolute URLs, X-Forwarded-Host overriding, and
// password-reset / cache-key flows that trust the Host header. These
// have a long bug-bounty track record (cache poisoning into account
// takeover, reset-link hijack) and aren't covered by CRLF/redirect.
package hosthdr

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Detector audits the Host header surface of a target URL.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Host-header detector.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose enables verbose stderr output.
func (d *Detector) WithVerbose(v bool) *Detector { d.verbose = v; return d }

// DetectOptions tunes the audit.
type DetectOptions struct {
	Timeout       time.Duration
	AttackerHost  string // host string injected into Host / X-Forwarded-* headers
}

// DefaultOptions returns sensible defaults. The default attacker host is
// chosen so it cannot accidentally match a legitimate domain — picking a
// reserved TLD ("example") plus a unique subdomain.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:      8 * time.Second,
		AttackerHost: "skws-host-poison.example",
	}
}

// DetectionResult bundles the host-header detector's findings.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Tested     int
}

// Detect runs the host-header audit against a target URL.
//
// Tests performed (each is a single request with a hostile header,
// compared against a baseline that uses the legitimate host):
//
//  1. **Host override reflection** — set Host: <attacker> and check
//     whether <attacker> appears in any Location / Link / Refresh /
//     <base href> / canonical link / og:url / form action / absolute
//     URL inside the response, but NOT in the legitimate baseline.
//  2. **X-Forwarded-Host reflection** — same probe with X-Forwarded-Host
//     header (commonly trusted by reverse proxies for absolute-URL
//     building, including password-reset emails).
//  3. **X-Host / X-Forwarded-Server reflection** — variants used by
//     some frameworks (Symfony, Rails) that trust them when
//     X-Forwarded-Host is unavailable.
//
// Each successful reflection is a high-severity finding because the
// classic exploit (password-reset email containing the attacker's host
// in the activation link) is one HTTP request away from account
// takeover.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.AttackerHost == "" {
		opts.AttackerHost = "skws-host-poison.example"
	}

	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	// Baseline using the legitimate host. This is what the response
	// looks like normally — every signal we report must NOT appear here.
	baseline, err := d.client.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	probes := []struct {
		header string
		desc   string
	}{
		{"Host", "Host header override"},
		{"X-Forwarded-Host", "X-Forwarded-Host override (reverse-proxy trust)"},
		{"X-Host", "X-Host override (Symfony / framework trust)"},
		{"X-Forwarded-Server", "X-Forwarded-Server override"},
	}

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		result.Tested++

		resp, err := d.client.SendPayloadInHeader(ctx, target, p.header, opts.AttackerHost, "GET")
		if err != nil {
			continue
		}
		if !d.reflectsAttacker(resp, baseline, opts.AttackerHost) {
			continue
		}

		result.Findings = append(result.Findings, d.createFinding(target, p.header, p.desc, opts.AttackerHost, resp))
		result.Vulnerable = true
	}

	return result, nil
}

// reflectsAttacker returns true when the attacker host appears in
// link-building locations of resp but not in baseline. We deliberately
// look only at structured locations (Location, Link, Refresh headers,
// <base>, canonical, og:url, form action, hardcoded absolute URLs) —
// matching anywhere in the body would FP on echoed headers in HTML
// debug pages or error messages.
func (d *Detector) reflectsAttacker(resp, baseline *http.Response, attacker string) bool {
	if resp == nil {
		return false
	}
	atk := strings.ToLower(attacker)

	// Header-based reflections. These are the highest-confidence signals
	// — Location/Link with attacker host means absolute-URL construction
	// trusted the user's Host.
	for _, hdr := range []string{"Location", "Link", "Refresh", "Content-Location"} {
		if v := resp.Headers[hdr]; v != "" && strings.Contains(strings.ToLower(v), atk) {
			if base := baseline.Headers[hdr]; !strings.Contains(strings.ToLower(base), atk) {
				return true
			}
		}
	}

	// Body-based: attacker host inside common absolute-URL anchors. We
	// require the attacker to be absent from baseline body and not just
	// echoed — many sites reflect Host into a debug banner without it
	// being used to build links.
	body := strings.ToLower(resp.Body)
	baseBody := strings.ToLower(baseline.Body)
	if !strings.Contains(body, atk) || strings.Contains(baseBody, atk) {
		return false
	}

	anchors := []string{
		`<base href="http`,
		`<link rel="canonical" href="http`,
		`<meta property="og:url" content="http`,
		`<form action="http`,
		`href="https://` + atk,
		`href="http://` + atk,
		`action="https://` + atk,
		`action="http://` + atk,
	}
	for _, a := range anchors {
		if strings.Contains(body, a) {
			return true
		}
	}
	return false
}

// createFinding builds the core.Finding for a confirmed reflection.
func (d *Detector) createFinding(target, header, desc, attacker string, resp *http.Response) *core.Finding {
	f := core.NewFinding("Host Header Injection", core.SeverityHigh)
	f.URL = target
	f.Description = fmt.Sprintf(
		"The application reflects the user-controlled %s header into absolute URLs in the response. "+
			"An attacker can poison password-reset emails, session links, and shared caches with their own domain — "+
			"a one-step path to account takeover when the application uses these links in transactional emails.",
		header,
	)
	f.Evidence = fmt.Sprintf("%s: %s -> attacker host reflected in response (%s)", header, attacker, desc)
	f.Tool = "hosthdr-detector"
	f.Confidence = core.ConfidenceHigh
	f.Remediation = "Build absolute URLs from a server-side allowlist of canonical hosts. Never trust Host, " +
		"X-Forwarded-Host, X-Host, or X-Forwarded-Server when constructing links used in emails or cache keys. " +
		"Configure reverse proxies to drop or normalize these headers before they reach the application."
	f.WithOWASPMapping(
		[]string{"WSTG-CONF-09"},   // Test for Subdomain Takeover / proxy misconfig family
		[]string{"A05:2025"},       // Security Misconfiguration
		[]string{"CWE-644"},        // Improper Neutralization of HTTP Headers for Scripting Syntax
	)
	return f
}
