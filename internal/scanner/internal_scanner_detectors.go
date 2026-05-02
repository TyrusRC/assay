package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/apispec"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cmdi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cors"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/crlf"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/csti"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/csvinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/domdetect"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/headerinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/idor"
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
		fmt.Fprintf(os.Stderr, "[*] Testing %d SQLi payloads...\n", len(payloads))
	}

	// Test each payload
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
			// Stop after first finding for this parameter
			break
		}
	}

	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] SQLi test complete: tested %d payloads, found %d vulns\n", testedCount, len(findings))
	}

	// If error-based found nothing, fall back to boolean-blind differential.
	// PortSwigger-style labs (and any modern app with display_errors off)
	// don't leak DB error strings — the only way to surface them is the
	// classic baseline / true / false response-similarity probe.
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

// testOOBWithClient tests a parameter using out-of-band techniques with the provided client.
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

// acquireDOMRunner pulls one Page off the headless pool. The caller must
// release it via the returned cleanup func; on failure both runner and
// cleanup are nil so the caller can early-return without nil-checks.
func (s *InternalScanner) acquireDOMRunner(ctx context.Context) (domdetect.Runner, func()) {
	if s.headlessPool == nil {
		return nil, nil
	}
	page, err := s.headlessPool.Acquire(ctx)
	if err != nil || page == nil {
		return nil, nil
	}
	return page, func() { s.headlessPool.Release(page) }
}

// testDOMXSS runs the headless DOM-XSS probe on every query parameter of
// targetURL. No-op when no headless pool is available.
func (s *InternalScanner) testDOMXSS(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing DOM XSS on '%s'...\n", targetURL)
	}
	runner, release := s.acquireDOMRunner(ctx)
	if runner == nil {
		return nil
	}
	defer release()

	res, err := domdetect.DetectXSS(ctx, runner, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testProtoPollutionDOM runs the headless client-side prototype-pollution
// probe on targetURL. No-op when no headless pool is available.
func (s *InternalScanner) testProtoPollutionDOM(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing client-side prototype pollution on '%s'...\n", targetURL)
	}
	runner, release := s.acquireDOMRunner(ctx)
	if runner == nil {
		return nil
	}
	defer release()

	res, err := domdetect.DetectProtoPollution(ctx, runner, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testDOMRedirect runs the headless DOM-based open-redirect probe on
// targetURL. No-op when no headless pool is available.
func (s *InternalScanner) testDOMRedirect(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing DOM-based open redirect on '%s'...\n", targetURL)
	}
	runner, release := s.acquireDOMRunner(ctx)
	if runner == nil {
		return nil
	}
	defer release()

	res, err := domdetect.DetectDOMRedirect(ctx, runner, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testDataExposure walks the JSON response for sensitive field names
// (OWASP API3:2023, read-side excessive data exposure).
func (s *InternalScanner) testDataExposure(ctx context.Context, targetURL string) []*core.Finding {
	if s.dataExposureDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing excessive data exposure on '%s'...\n", targetURL)
	}
	res, err := s.dataExposureDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testAdminPath probes the host for admin / debug / internal endpoints
// reachable without authentication (OWASP API5:2023, A05:2025).
func (s *InternalScanner) testAdminPath(ctx context.Context, targetURL string) []*core.Finding {
	if s.adminPathDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing admin / debug paths on '%s'...\n", targetURL)
	}
	res, err := s.adminPathDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testAPIVersion probes sibling versions of the URL's /vN/ segment
// (OWASP API9:2023 Improper Inventory Management).
func (s *InternalScanner) testAPIVersion(ctx context.Context, targetURL string) []*core.Finding {
	if s.apiVersionDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing sibling API versions for '%s'...\n", targetURL)
	}
	res, err := s.apiVersionDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testRateLimit sends a controlled burst to detect missing rate limits
// (OWASP API4:2023). Off by default to avoid load-bearing probes.
func (s *InternalScanner) testRateLimit(ctx context.Context, targetURL string) []*core.Finding {
	if s.rateLimitDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Burst-probing rate limit on '%s'...\n", targetURL)
	}
	res, err := s.rateLimitDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testAPISpec drives the OpenAPI spec runner against the target. Loads
// the spec on first call; only active when APISpecURL is configured.
func (s *InternalScanner) testAPISpec(ctx context.Context, targetURL string) []*core.Finding {
	if s.apiSpecRunner == nil || s.config.APISpecURL == "" {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Loading OpenAPI spec from '%s'...\n", s.config.APISpecURL)
	}
	spec, err := apispec.LoadFromURL(ctx, s.client, s.config.APISpecURL)
	if err != nil || spec == nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] OpenAPI spec load failed: %v\n", err)
		}
		return nil
	}
	res, err := s.apiSpecRunner.Run(ctx, spec, targetURL)
	if err != nil || res == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[+] OpenAPI runner: probed %d endpoints, %d findings\n",
			res.EndpointsProbed, len(res.Findings))
	}
	return res.Findings
}

// testPromptInjection probes LLM-backed endpoints for prompt-injection
// susceptibility (OWASP A04 / API10).
func (s *InternalScanner) testPromptInjection(ctx context.Context, targetURL string) []*core.Finding {
	if s.promptInjDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing LLM prompt-injection on '%s'...\n", targetURL)
	}
	res, err := s.promptInjDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testXSLT probes for server-side XSLT injection.
func (s *InternalScanner) testXSLT(ctx context.Context, targetURL string) []*core.Finding {
	if s.xsltDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing XSLT injection on '%s'...\n", targetURL)
	}
	res, err := s.xsltDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testSAMLInj probes SAML SP endpoints for malformed-envelope acceptance.
func (s *InternalScanner) testSAMLInj(ctx context.Context, targetURL string) []*core.Finding {
	if s.samlInjDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing SAML SP envelopes on '%s'...\n", targetURL)
	}
	res, err := s.samlInjDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testCSRF probes a state-change endpoint for missing Origin / token
// enforcement (OWASP A01 / API5).
func (s *InternalScanner) testCSRF(ctx context.Context, targetURL string, scanCfg *Config) []*core.Finding {
	if s.csrfDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CSRF on '%s'...\n", targetURL)
	}
	method, body := "", ""
	if scanCfg != nil {
		method = scanCfg.Method
		body = scanCfg.Data
	}
	res, err := s.csrfDetector.Detect(ctx, targetURL, method, body)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testTabnabbing scans the response HTML for `target=_blank` anchors
// without rel=noopener / noreferrer (reverse-tabnabbing).
func (s *InternalScanner) testTabnabbing(ctx context.Context, targetURL string) []*core.Finding {
	if s.tabnabbingDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Scanning HTML for reverse-tabnabbing on '%s'...\n", targetURL)
	}
	res, err := s.tabnabbingDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testReDoS times pathological-input requests against regex-shaped
// query parameters (OWASP A04, API4). Off by default — adds latency.
func (s *InternalScanner) testReDoS(ctx context.Context, targetURL string) []*core.Finding {
	if s.redosDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing ReDoS surfaces on '%s'...\n", targetURL)
	}
	res, err := s.redosDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testSSE probes the host for unauthenticated text/event-stream
// endpoints (OWASP API2 / API5).
func (s *InternalScanner) testSSE(ctx context.Context, targetURL string) []*core.Finding {
	if s.sseDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing SSE / event-stream endpoints on '%s'...\n", targetURL)
	}
	res, err := s.sseDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testGRPCReflect probes the host for an exposed gRPC reflection
// service (OWASP API9).
func (s *InternalScanner) testGRPCReflect(ctx context.Context, targetURL string) []*core.Finding {
	if s.grpcReflectDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing gRPC reflection on '%s'...\n", targetURL)
	}
	res, err := s.grpcReflectDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testH2Reset probes for HTTP/2 rapid-reset DDoS exposure
// (CVE-2023-44487, OWASP API4). Off by default; opt-in via --h2-reset.
func (s *InternalScanner) testH2Reset(ctx context.Context, targetURL string) []*core.Finding {
	if s.h2ResetDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing HTTP/2 rapid-reset on '%s'...\n", targetURL)
	}
	res, err := s.h2ResetDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testContentType probes a JSON endpoint for content-type confusion
// (OWASP API3 / API8). No-op when EnableContentType is off.
func (s *InternalScanner) testContentType(ctx context.Context, targetURL string) []*core.Finding {
	if s.contentTypeDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing content-type confusion on '%s'...\n", targetURL)
	}
	res, err := s.contentTypeDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testJSDep fetches the URL, identifies any known JS libraries via their
// <script src> URLs, and queries NVD for CVEs affecting the detected
// version. Findings are emitted one per CVE so reports cite each
// vulnerability discretely. Best-effort against NVD outage: a 5xx from
// the upstream is logged via verbose only, never breaks the scan.
func (s *InternalScanner) testJSDep(ctx context.Context, targetURL string) []*core.Finding {
	if s.jsdepDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing JS dependencies (NVD lookup) on '%s'...\n", targetURL)
	}
	res, err := s.jsdepDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[+] JS deps: %d libraries identified, %d CVE finding(s)\n",
			len(res.Libraries), len(res.Findings))
	}
	return res.Findings
}

// testXXEPost tests an endpoint for XXE by sending the payload as a POST
// application/xml body. This is the canonical XXE attack surface (think
// PortSwigger's `/catalog/product/stock` lab) — the parameter-injection
// path can't reach it because the entire request body is the XML document,
// not a parameter. We only emit findings when the endpoint actually
// accepts an XML body distinct from its non-XML default; pages that
// reflect the same response regardless of method/content-type can't be
// XXE-vulnerable and would just produce FPs otherwise.
func (s *InternalScanner) testXXEPost(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing XXE (POST application/xml) on '%s'...\n", targetURL)
	}

	opts := xxe.DefaultOptions()
	if s.config.MaxPayloadsPerParam > 0 {
		opts.MaxPayloads = s.config.MaxPayloadsPerParam
	}
	if s.config.RequestTimeout > 0 {
		opts.Timeout = s.config.RequestTimeout
	}
	opts.ContentType = "application/xml"

	result, err := s.xxeDetector.Detect(ctx, targetURL, "POST", opts)
	if err != nil || result == nil || !result.Vulnerable {
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

// testIDOR tests for Insecure Direct Object Reference vulnerabilities.
func (s *InternalScanner) testIDOR(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing IDOR on '%s'...\n", targetURL)
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

// testCORS tests for CORS misconfigurations.
func (s *InternalScanner) testCORS(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CORS on '%s'...\n", targetURL)
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

// testJWT tests JWT tokens for vulnerabilities.
// Note: This requires JWT tokens to be extracted from the target first.
func (s *InternalScanner) testJWT(ctx context.Context, token string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing JWT token for vulnerabilities...\n")
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

// testJNDI tests for JNDI/Log4Shell vulnerabilities using the internal detector.

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
