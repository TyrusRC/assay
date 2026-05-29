package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/cookietoss"
	"github.com/TyrusRC/assay/internal/detection/cspaudit"
	"github.com/TyrusRC/assay/internal/detection/iistilde"
	"github.com/TyrusRC/assay/internal/detection/samesitescript"
	"github.com/TyrusRC/assay/internal/detection/wafdetect"
	"github.com/TyrusRC/assay/internal/detection/webhooksig"
	"github.com/TyrusRC/assay/internal/detection/xfs"
	"github.com/TyrusRC/assay/internal/payloads/http3desync"
	"github.com/TyrusRC/assay/internal/payloads/vhost"
	"github.com/TyrusRC/assay/internal/payloads/webauthn"
)

// This file groups the URL-level detectors that perform no parameter
// injection — they consume baseline responses or fire small, RFC-
// conformant probes (DNS lookups, HEAD requests, header inspection).
// Used by the passive scan profile and on every other profile too.

// testWAFDetect runs a single passive GET and fingerprints any WAF
// product in the path. Output is informational (SeverityInfo); the
// scanner uses the vendor downstream to switch in evasion-class payloads.
func (s *InternalScanner) testWAFDetect(ctx context.Context, targetURL string) []*core.Finding {
	if s.wafDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Fingerprinting WAF on '%s'...\n", targetURL)
	}
	opts := wafdetect.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.wafDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testXFS runs a single passive GET and reports clickjacking exposure
// from the combination of X-Frame-Options, CSP frame-ancestors, and any
// JS framebuster in the rendered body.
func (s *InternalScanner) testXFS(ctx context.Context, targetURL string) []*core.Finding {
	if s.xfsDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Analyzing clickjacking exposure on '%s'...\n", targetURL)
	}
	opts := xfs.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.xfsDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testIISTilde runs the IIS short-name (~1) differential probe.
// Auto no-ops on non-IIS hosts because the differential is undetectable
// there. Fires 6 cheap GETs total.
func (s *InternalScanner) testIISTilde(ctx context.Context, targetURL string) []*core.Finding {
	if s.iisTildeDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing IIS short-name disclosure on '%s'...\n", targetURL)
	}
	opts := iistilde.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.iisTildeDetector.DetectWithOptions(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testSameSiteScript runs the DNS-only probe for the
// localhost.victim.com → 127.0.0.1 misconfiguration. No HTTP traffic
// hits the target — purely local DNS resolution.
func (s *InternalScanner) testSameSiteScript(ctx context.Context, targetURL string) []*core.Finding {
	if s.sameSiteScriptDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Checking Same-Site Scripting DNS misconfigurations for '%s'...\n", targetURL)
	}
	res, err := s.sameSiteScriptDetector.Detect(ctx, targetURL, samesitescript.DefaultOptions())
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testVHostEnum rotates Host: through a hostname wordlist and reports
// distinct vhost blocks served from the same IP. Off by default because
// of the request budget (default 150 GETs); enable for recon-class scans.
func (s *InternalScanner) testVHostEnum(ctx context.Context, targetURL string) []*core.Finding {
	if s.vhostDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Enumerating virtual hosts on '%s'...\n", targetURL)
	}
	opts := vhost.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	if s.config.VHostMaxRequests > 0 {
		opts.MaxVHosts = s.config.VHostMaxRequests
	}
	res, err := s.vhostDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testWebAuthn probes the target for WebAuthn / FIDO2 endpoints and
// emits Informational findings on discovery plus Medium findings on
// known policy footguns (attestation=none, userVerification=discouraged,
// RP-ID=localhost). Auto no-op on hosts without the standard
// /webauthn or /api/passkey route shapes.
func (s *InternalScanner) testWebAuthn(ctx context.Context, targetURL string) []*core.Finding {
	if s.webauthnDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Discovering WebAuthn endpoints on '%s'...\n", targetURL)
	}
	opts := webauthn.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.webauthnDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || len(res.Findings) == 0 {
		return nil
	}
	return res.Findings
}

// testHTTP3Desync passively parses Alt-Svc to confirm HTTP/3
// advertisement and fingerprints the upstream against the public H3
// desync CVE list. Single passive HEAD; auto no-op on hosts without
// Alt-Svc.
func (s *InternalScanner) testHTTP3Desync(ctx context.Context, targetURL string) []*core.Finding {
	if s.http3DesyncDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Checking HTTP/3 advertisement on '%s'...\n", targetURL)
	}
	opts := http3desync.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.http3DesyncDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || len(res.Findings) == 0 {
		return nil
	}
	return res.Findings
}

// testCSPAudit performs a deep CSP policy audit — nonce reuse, strict-
// dynamic with permissive baseline, unsafe-eval combined with nonce,
// data: in script-src. Complements secheaders (which only checks
// presence) with policy-shape analysis. 1-2 GETs total.
func (s *InternalScanner) testCSPAudit(ctx context.Context, targetURL string) []*core.Finding {
	if s.cspAuditDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Auditing CSP policy on '%s'...\n", targetURL)
	}
	opts := cspaudit.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.cspAuditDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || len(res.Findings) == 0 {
		return nil
	}
	return res.Findings
}

// testCookieToss audits Set-Cookie attributes for cookie-tossing
// exposure: missing __Host-/__Secure- prefix on auth cookies,
// over-broad Domain attribute, missing scoping defaults. Single GET.
func (s *InternalScanner) testCookieToss(ctx context.Context, targetURL string) []*core.Finding {
	if s.cookieTossDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Auditing cookies on '%s'...\n", targetURL)
	}
	opts := cookietoss.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.cookieTossDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || len(res.Findings) == 0 {
		return nil
	}
	return res.Findings
}

// testWebhookSig audits webhook receiver endpoints for signature-
// verification flaws (missing signature accepted, wrong signature
// accepted, stale timestamp accepted). Probes the curated CommonEndpoints
// wordlist; off-by-default endpoints auto-skip.
func (s *InternalScanner) testWebhookSig(ctx context.Context, targetURL string) []*core.Finding {
	if s.webhookSigDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Auditing webhook receivers on '%s'...\n", targetURL)
	}
	opts := webhooksig.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.webhookSigDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || len(res.Findings) == 0 {
		return nil
	}
	return res.Findings
}
