package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/iistilde"
	"github.com/TyrusRC/assay/internal/detection/samesitescript"
	"github.com/TyrusRC/assay/internal/detection/wafdetect"
	"github.com/TyrusRC/assay/internal/detection/xfs"
	"github.com/TyrusRC/assay/internal/payloads/vhost"
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
