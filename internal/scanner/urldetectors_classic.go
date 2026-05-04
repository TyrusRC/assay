package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/auth"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cloud"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/exposure"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/graphql"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/jndi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/secheaders"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/subtakeover"
	tlsdetect "github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/tls"
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
			[]string{"A05:2025"},
			[]string{"CWE-444"},
		)
		findings = append(findings, finding)
	}
	return findings
}
