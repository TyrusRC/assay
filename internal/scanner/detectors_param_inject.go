package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cmdi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/crlf"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/csti"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/csvinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/headerinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ldap"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/lfi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/nosql"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/redirect"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/rfi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ssrf"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ssti"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xpath"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xss"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xxe"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/sqli"
)

// testSQLiWithClient tests a parameter for SQL injection using the internal detector and provided client.
func (s *InternalScanner) testSQLiWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, client *http.Client) []*core.Finding {
	var findings []*core.Finding
	paramName := param.Name

	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing SQLi on param '%s'...\n", paramName)
	}

	payloads := sqli.GetPayloads(sqli.Generic)
	if s.config.IncludeWAFBypass {
		payloads = append(payloads, sqli.GetWAFBypassPayloads(sqli.Generic)...)
	}

	if len(payloads) > s.config.MaxPayloadsPerParam {
		payloads = payloads[:s.config.MaxPayloadsPerParam]
	}

	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing %d SQLi payloads...\n", len(payloads))
	}

	testedCount := 0
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] SQLi test canceled by context\n")
			}
			return findings
		default:
		}

		resp, err := client.SendPayload(ctx, targetURL, paramName, payload.Value, method)
		if err != nil {
			continue
		}
		testedCount++

		analysis := s.sqliDetector.AnalyzeResponse(resp.Body)
		if analysis.IsVulnerable {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[+] SQLi FOUND in '%s' with payload: %s\n", paramName, payload.Value[:min(30, len(payload.Value))])
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
			break
		}
	}

	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] SQLi test complete: tested %d payloads, found %d vulns\n", testedCount, len(findings))
	}

	if len(findings) == 0 {
		if blindRes, err := s.sqliDetector.DetectBoolean(ctx, client, targetURL, paramName, method); err == nil && blindRes.IsVulnerable {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[+] Boolean-blind SQLi FOUND in '%s' (true=%s | false=%s)\n",
					paramName, blindRes.TruePayload, blindRes.FalsePayload)
			}
			finding := core.NewFinding("SQL Injection (boolean-blind)", core.SeverityCritical)
			finding.URL = targetURL
			finding.Parameter = paramName
			finding.Description = fmt.Sprintf(
				"Boolean-based blind SQL Injection detected in '%s' parameter. The response shape changes deterministically with a controlled WHERE-clause boolean, indicating the value flows into a SQL query.",
				paramName,
			)
			finding.Evidence = fmt.Sprintf("True payload: %s\nFalse payload: %s\nDifferential confidence: %.2f",
				blindRes.TruePayload, blindRes.FalsePayload, blindRes.Confidence)
			finding.Tool = "internal-sqli-detector"
			finding.Remediation = "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A03:2025"},
				[]string{"CWE-89"},
			)
			findings = append(findings, finding)
		}
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

// testCMDI tests a parameter for Command Injection using the internal detector.
func (s *InternalScanner) testCMDI(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CMDI on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing SSRF on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing LFI on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing XXE on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing NoSQL Injection on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing SSTI on param '%s'...\n", param.Name)
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

// testRedirect tests a parameter for Open Redirect vulnerabilities.
func (s *InternalScanner) testRedirect(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Open Redirect on param '%s'...\n", param.Name)
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

// testCRLF tests a parameter for CRLF Injection vulnerabilities.
func (s *InternalScanner) testCRLF(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CRLF Injection on param '%s'...\n", param.Name)
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

// testLDAP tests a parameter for LDAP Injection using the internal detector.
func (s *InternalScanner) testLDAP(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing LDAP Injection on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing XPath Injection on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing Header Injection on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing CSTI on param '%s'...\n", param.Name)
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
		fmt.Fprintf(os.Stderr, "[*] Testing RFI on param '%s'...\n", param.Name)
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

// testCSVInj tests a parameter for CSV/Formula Injection vulnerabilities.
func (s *InternalScanner) testCSVInj(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CSV injection on param '%s'...\n", param.Name)
	}
	result, err := s.csvInjDetector.Detect(ctx, targetURL, param.Name, method, csvinj.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] CSV injection test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}
	return result.Findings
}

