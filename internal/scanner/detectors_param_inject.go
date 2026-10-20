package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/cmdi"
	"github.com/TyrusRC/assay/internal/detection/crlf"
	"github.com/TyrusRC/assay/internal/detection/csti"
	"github.com/TyrusRC/assay/internal/detection/csvinj"
	"github.com/TyrusRC/assay/internal/detection/headerinj"
	"github.com/TyrusRC/assay/internal/detection/injection"
	"github.com/TyrusRC/assay/internal/detection/ldap"
	"github.com/TyrusRC/assay/internal/detection/lfi"
	"github.com/TyrusRC/assay/internal/detection/nosql"
	"github.com/TyrusRC/assay/internal/detection/redirect"
	"github.com/TyrusRC/assay/internal/detection/rfi"
	"github.com/TyrusRC/assay/internal/detection/ssrf"
	"github.com/TyrusRC/assay/internal/detection/ssti"
	"github.com/TyrusRC/assay/internal/detection/xpath"
	"github.com/TyrusRC/assay/internal/detection/xss"
	"github.com/TyrusRC/assay/internal/detection/xxe"
	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/payloads/sqli"
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

		resp, err := client.SendPayloadAt(ctx, targetURL, param, payload.Value, method)
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
				[]string{"A05:2025"},
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
		var blindRes *injection.BooleanResult
		var blindErr error
		if param.Location != core.ParamLocationQuery && param.Location != "" {
			send := func(ctx context.Context, payload string) (*http.Response, error) {
				return client.SendPayloadAt(ctx, targetURL, param, payload, method)
			}
			blindRes, blindErr = s.sqliDetector.DetectBooleanAt(ctx, client, targetURL, param, method, send)
		} else {
			blindRes, blindErr = s.sqliDetector.DetectBoolean(ctx, client, targetURL, paramName, method)
		}
		if blindErr == nil && blindRes != nil && blindRes.IsVulnerable {
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
				[]string{"A05:2025"},
				[]string{"CWE-89"},
			)
			findings = append(findings, finding)
		}
	}

	// UNION-based SQLi — runs last (noisier, more requests than error/boolean).
	if len(findings) == 0 {
		if unionRes, err := s.sqliDetector.DetectUnion(ctx, client, targetURL, paramName, method); err == nil && unionRes.IsVulnerable {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[+] UNION SQLi FOUND in '%s' (%d columns, reflected col %d)\n",
					paramName, unionRes.ColumnCount, unionRes.ReflectedColumn+1)
			}
			finding := core.NewFinding("SQL Injection (UNION-based)", core.SeverityCritical)
			finding.URL = targetURL
			finding.Parameter = paramName
			finding.Description = fmt.Sprintf(
				"UNION-based SQL Injection detected in '%s' parameter with %d columns. %s",
				paramName, unionRes.ColumnCount, unionRes.Evidence,
			)
			finding.Evidence = fmt.Sprintf("Payload: %s\n%s", unionRes.Payload, unionRes.Evidence)
			finding.Tool = "internal-sqli-detector"
			finding.Remediation = "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A05:2025"},
				[]string{"CWE-89"},
			)
			findings = append(findings, finding)
		}
	}

	// Response-differential SQLi — catches custom-error-wrapped SQL (JSON
	// APIs that never surface raw DB errors). Runs after UNION because it
	// sends more probes and overlaps with boolean-blind.
	if len(findings) == 0 {
		if diffRes, err := s.sqliDetector.DetectDifferential(ctx, client, targetURL, paramName, method); err == nil && diffRes.IsVulnerable {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[+] Differential SQLi FOUND in '%s' (true=%s | false=%s)\n",
					paramName, diffRes.TruePayload, diffRes.FalsePayload)
			}
			finding := core.NewFinding("SQL Injection (response-differential)", core.SeverityCritical)
			finding.URL = targetURL
			finding.Parameter = paramName
			finding.Description = fmt.Sprintf(
				"Response-differential SQL Injection detected in '%s' parameter. A SQL metacharacter changes the response shape, and a boolean WHERE-clause pair confirms the differential is SQL-controlled.",
				paramName,
			)
			finding.Evidence = fmt.Sprintf("True payload: %s\nFalse payload: %s\nDifferential confidence: %.2f",
				diffRes.TruePayload, diffRes.FalsePayload, diffRes.Confidence)
			finding.Tool = "internal-sqli-detector"
			finding.Remediation = "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A05:2025"},
				[]string{"CWE-89"},
			)
			findings = append(findings, finding)
		}
	}

	// Time-based blind SQLi — last resort (slowest, 3s delay per probe).
	// Gated behind EnableTimeBasedSQLi (off in quick profile).
	if len(findings) == 0 && s.config.EnableTimeBasedSQLi {
		send := func(ctx context.Context, payload string) (*http.Response, error) {
			return client.SendPayloadAt(ctx, targetURL, param, payload, method)
		}
		if timeRes, err := s.sqliDetector.DetectTimeBasedAt(ctx, client, targetURL, paramName, method, send); err == nil && timeRes.IsVulnerable {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[+] Time-based blind SQLi FOUND in '%s' (baseline: %v, delayed: %v)\n",
					paramName, timeRes.BaselineTime, timeRes.DelayedTime)
			}
			finding := core.NewFinding("SQL Injection (time-based blind)", core.SeverityCritical)
			finding.URL = targetURL
			finding.Parameter = paramName
			finding.Description = fmt.Sprintf(
				"Time-based blind SQL Injection detected in '%s' parameter (Database: %s). Response delayed by %v vs baseline %v.",
				paramName, timeRes.DatabaseType, timeRes.DelayedTime, timeRes.BaselineTime,
			)
			finding.Evidence = fmt.Sprintf("Payload: %s\nBaseline: %v\nDelayed: %v\nConfidence: %.2f",
				timeRes.Payload, timeRes.BaselineTime, timeRes.DelayedTime, timeRes.Confidence)
			finding.Tool = "internal-sqli-detector"
			finding.Remediation = "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A05:2025"},
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
	result, err := s.cmdiDetector.DetectParam(ctx, targetURL, param, method, cmdi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		EnableTimeBased:  s.config.EnableTimeBasedSQLi,
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
// For body params with XML content type, the detector replaces the entire
// request body so the DOCTYPE + entity declaration is valid XML.
func (s *InternalScanner) testXXEInParam(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing XXE on param '%s'...\n", param.Name)
	}

	opts := xxe.DefaultOptions()
	opts.MaxPayloads = s.config.MaxPayloadsPerParam
	opts.Timeout = s.config.RequestTimeout

	if param.Location == core.ParamLocationBody && strings.Contains(strings.ToLower(param.ContentType), "xml") {
		opts.ContentType = param.ContentType
		result, err := s.xxeDetector.DetectInXMLBody(ctx, targetURL, param.Name, method, opts)
		if err != nil || !result.Vulnerable {
			return nil
		}
		return result.Findings
	}

	result, err := s.xxeDetector.DetectInParameter(ctx, targetURL, param.Name, method, opts)
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
