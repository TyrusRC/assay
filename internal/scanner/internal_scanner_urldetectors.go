package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/auth"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cloud"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/exposure"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/fileupload"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/graphql"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/hosthdr"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/jndi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/loginj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/oauth"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/pathnorm"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/racecond"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/secheaders"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/storageinj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/subtakeover"
	tlsdetect "github.com/swiss-knife-for-web-security/skws/internal/detection/tls"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/verbtamper"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ws"
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

	// Test for default credentials
	result, err := s.authDetector.DetectDefaultCredentials(ctx, loginURL, auth.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err == nil && result.Vulnerable {
		findings = append(findings, result.Findings...)
	}

	// Test for user enumeration
	result, err = s.authDetector.DetectUserEnumeration(ctx, loginURL, auth.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err == nil && result.Vulnerable {
		findings = append(findings, result.Findings...)
	}

	// Test for missing rate limiting
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

	// Discover GraphQL endpoints first
	endpoints, err := s.graphqlDetector.DiscoverEndpoints(ctx, targetURL)
	if err != nil || len(endpoints) == 0 {
		// Try direct detection on the target URL
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

// testStorageInj tests for client-side storage injection vulnerabilities.
func (s *InternalScanner) testStorageInj(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing storage injection on '%s'...\n", targetURL)
	}

	result, err := s.storageInjDetector.Detect(ctx, targetURL, storageinj.DetectOptions{
		Timeout:        s.config.RequestTimeout,
		CheckSensitive: true,
		MaxPayloads:    s.config.MaxPayloadsPerParam,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Storage injection test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testLogInj tests for log injection vulnerabilities via HTTP headers.
func (s *InternalScanner) testLogInj(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing log injection on '%s'...\n", targetURL)
	}

	result, err := s.logInjDetector.Detect(ctx, targetURL, "", "GET", loginj.DefaultOptions())
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Log injection test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testFileUpload tests for file upload vulnerabilities.
func (s *InternalScanner) testFileUpload(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing file upload on '%s'...\n", targetURL)
	}

	result, err := s.fileUploadDetector.Detect(ctx, targetURL, "", "POST", fileupload.DetectOptions{
		MaxPayloads:       s.config.MaxPayloadsPerParam,
		IncludeMIMEBypass: s.config.IncludeWAFBypass,
		IncludeDoubleExt:  true,
		IncludeNullByte:   true,
		Timeout:           s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] File upload test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testVerbTamper tests for HTTP verb tampering bypass vulnerabilities.
func (s *InternalScanner) testVerbTamper(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing verb tampering on '%s'...\n", targetURL)
	}

	result, err := s.verbTamperDetector.Detect(ctx, targetURL, "", "GET", verbtamper.DetectOptions{
		MaxPayloads:          s.config.MaxPayloadsPerParam,
		IncludeOverrideTests: true,
		Timeout:              s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Verb tampering test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testPathNorm tests for path normalization bypass vulnerabilities.
func (s *InternalScanner) testPathNorm(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing path normalization on '%s'...\n", targetURL)
	}

	result, err := s.pathNormDetector.Detect(ctx, targetURL, "", "GET", pathnorm.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Path normalization test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testRaceCond tests for race condition vulnerabilities.
func (s *InternalScanner) testRaceCond(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing race conditions on '%s'...\n", targetURL)
	}

	result, err := s.raceCondDetector.Detect(ctx, targetURL, "", "GET", racecond.DetectOptions{
		ConcurrentRequests: 10,
		Timeout:            s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Race condition test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testWS audits WebSocket endpoints reachable from the target URL —
// CSWSH (Origin-bypass), missing-auth handshake, and message reflection.
// All dials honor the global proxy/headers/cookies/UA/insecure plumbing.
func (s *InternalScanner) testWS(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing WebSocket security on '%s'...\n", targetURL)
	}

	s.wsDetector.WithVerbose(s.config.Verbose)
	result, err := s.wsDetector.Detect(ctx, targetURL, ws.DefaultOptions())
	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testHostHdr audits Host / X-Forwarded-Host header trust on the target —
// the path to password-reset hijack and cache-poisoning ATO. All requests
// honor the global proxy/headers/cookies/UA/insecure plumbing.
func (s *InternalScanner) testHostHdr(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Host header injection on '%s'...\n", targetURL)
	}

	result, err := s.hostHdrDetector.Detect(ctx, targetURL, hosthdr.DefaultOptions())
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testOAuth audits OAuth/OIDC discovery for missing PKCE, alg=none,
// implicit-flow advertisement, and redirect_uri exact-match bypass.
// Honors the global proxy/headers/cookies/UA/insecure plumbing.
func (s *InternalScanner) testOAuth(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing OAuth/OIDC on '%s'...\n", targetURL)
	}

	result, err := s.oauthDetector.Detect(ctx, targetURL, oauth.DefaultOptions())
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}
