package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/auth"
	"github.com/TyrusRC/assay/internal/detection/cloud"
	"github.com/TyrusRC/assay/internal/detection/exposure"
	"github.com/TyrusRC/assay/internal/detection/graphql"
	"github.com/TyrusRC/assay/internal/detection/jndi"
	"github.com/TyrusRC/assay/internal/detection/secheaders"
	"github.com/TyrusRC/assay/internal/detection/subtakeover"
	tlsdetect "github.com/TyrusRC/assay/internal/detection/tls"
	"github.com/TyrusRC/assay/internal/detection/iistilde"
	"github.com/TyrusRC/assay/internal/detection/samesitescript"
	"github.com/TyrusRC/assay/internal/detection/wafdetect"
	"github.com/TyrusRC/assay/internal/detection/xfs"
	"github.com/TyrusRC/assay/internal/payloads/esi"
	"github.com/TyrusRC/assay/internal/payloads/solrinject"
	"github.com/TyrusRC/assay/internal/payloads/vhost"
)

// testJNDI tests for JNDI/Log4Shell vulnerabilities.
func (s *InternalScanner) testJNDI(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing JNDI/Log4Shell on '%s'...\n", targetURL)
	}
	result, err := s.jndiDetector.Detect(ctx, targetURL, jndi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		TestHeaders:      true,
		TestParams:       true,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testSecHeaders tests for missing or insecure HTTP security headers.
func (s *InternalScanner) testSecHeaders(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing security headers on '%s'...\n", targetURL)
	}
	result, err := s.secHeadersDetector.Detect(ctx, targetURL, secheaders.DetectOptions{
		Timeout:             s.config.RequestTimeout,
		CheckRequired:       true,
		CheckOptional:       true,
		CheckInfoDisclosure: true,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

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

// testESI probes URL parameters for Edge Side Includes injection by
// injecting fingerprint ESI payloads and looking for engine-evaluation
// markers in the response.
func (s *InternalScanner) testESI(ctx context.Context, targetURL string) []*core.Finding {
	if s.esiDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing ESI injection on '%s'...\n", targetURL)
	}
	opts := esi.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	if s.config.MaxPayloadsPerParam > 0 && s.config.MaxPayloadsPerParam < opts.MaxPayloadsPerParam {
		opts.MaxPayloadsPerParam = s.config.MaxPayloadsPerParam
	}
	res, err := s.esiDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testSolrInject probes URL parameters for Apache Solr injection.
// Gated on baseline showing Solr error patterns when
// ConfirmedSolrOnly is enabled — keeps RCE payloads off non-Solr targets.
func (s *InternalScanner) testSolrInject(ctx context.Context, targetURL string) []*core.Finding {
	if s.solrInjectDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Apache Solr injection on '%s'...\n", targetURL)
	}
	opts := solrinject.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	if s.config.MaxPayloadsPerParam > 0 && s.config.MaxPayloadsPerParam < opts.MaxPayloadsPerParam {
		opts.MaxPayloadsPerParam = s.config.MaxPayloadsPerParam
	}
	res, err := s.solrInjectDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testExposure tests for exposed sensitive files and directories.
func (s *InternalScanner) testExposure(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing sensitive file exposure on '%s'...\n", targetURL)
	}
	result, err := s.exposureDetector.Detect(ctx, targetURL, exposure.DetectOptions{
		Timeout:       s.config.RequestTimeout,
		ContinueOnHit: true,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testCloud tests for cloud storage misconfigurations.
func (s *InternalScanner) testCloud(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing cloud storage misconfigurations for '%s'...\n", targetURL)
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	result, err := s.cloudDetector.Detect(ctx, parsedURL.Hostname(), cloud.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testSubTakeover tests for subdomain takeover vulnerabilities.
func (s *InternalScanner) testSubTakeover(ctx context.Context) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing subdomain takeover (%d subdomains)...\n", len(s.config.Subdomains))
	}
	result, err := s.subTakeoverDetector.Detect(ctx, s.config.Subdomains, subtakeover.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testTLS tests for TLS/SSL vulnerabilities and misconfigurations.
func (s *InternalScanner) testTLS(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing TLS configuration on '%s'...\n", targetURL)
	}
	result, err := s.tlsAnalyzer.Analyze(ctx, targetURL, tlsdetect.AnalyzeOptions{
		Timeout:          s.config.RequestTimeout,
		CheckCertificate: true,
		CheckProtocol:    true,
		CertExpiryDays:   30,
		RequireHSTS:      true,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testAuth tests for authentication vulnerabilities.
func (s *InternalScanner) testAuth(ctx context.Context, loginURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing authentication on '%s'...\n", loginURL)
	}

	var findings []*core.Finding

	result, err := s.authDetector.DetectDefaultCredentials(ctx, loginURL, auth.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err == nil && result.Vulnerable {
		findings = append(findings, result.Findings...)
	}

	result, err = s.authDetector.DetectUserEnumeration(ctx, loginURL, auth.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err == nil && result.Vulnerable {
		findings = append(findings, result.Findings...)
	}

	result, err = s.authDetector.DetectMissingRateLimit(ctx, loginURL, auth.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err == nil && result.Vulnerable {
		findings = append(findings, result.Findings...)
	}

	return findings
}

// testGraphQL tests for GraphQL-specific vulnerabilities.
func (s *InternalScanner) testGraphQL(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing GraphQL vulnerabilities on '%s'...\n", targetURL)
	}

	endpoints, err := s.graphqlDetector.DiscoverEndpoints(ctx, targetURL)
	if err != nil || len(endpoints) == 0 {
		result, detectErr := s.graphqlDetector.Detect(ctx, targetURL, graphql.DetectOptions{
			Timeout: s.config.RequestTimeout,
		})
		if detectErr != nil || !result.IsGraphQL {
			return nil
		}
		return result.Findings
	}

	var findings []*core.Finding
	for _, endpoint := range endpoints {
		result, detectErr := s.graphqlDetector.Detect(ctx, endpoint, graphql.DetectOptions{
			Timeout: s.config.RequestTimeout,
		})
		if detectErr != nil || !result.IsGraphQL {
			continue
		}
		findings = append(findings, result.Findings...)
	}
	return findings
}

// testSmuggling tests for HTTP request smuggling vulnerabilities.
func (s *InternalScanner) testSmuggling(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HTTP smuggling on '%s'...\n", targetURL)
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	target := parsedURL.Host
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	results := s.smugglingDetector.Detect(ctx, target, path)

	var findings []*core.Finding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		finding := core.NewFinding("HTTP Request Smuggling", core.SeverityHigh)
		finding.URL = targetURL
		finding.Description = fmt.Sprintf("HTTP Request Smuggling (%s) detected with %.0f%% confidence",
			r.Type, r.Confidence*100)
		finding.Evidence = r.Evidence
		finding.Tool = "internal-smuggling"
		finding.Remediation = "Ensure consistent interpretation of Content-Length and Transfer-Encoding headers between frontend and backend servers."
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-15"},
			[]string{"A02:2025"},
			[]string{"CWE-444"},
		)
		findings = append(findings, finding)
	}
	return findings
}
