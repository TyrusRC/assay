package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cors"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/idor"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xxe"
)

// testTypeJuggling probes login-shaped paths for PHP loose-equality
// auth bypass.
func (s *InternalScanner) testTypeJuggling(ctx context.Context, targetURL string, scanCfg *Config) []*core.Finding {
	if s.typeJugglingDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing type-juggling auth bypass on '%s'...\n", targetURL)
	}
	username := ""
	if scanCfg != nil && scanCfg.Headers != nil {
		username = scanCfg.Headers["X-Username"]
	}
	res, err := s.typeJugglingDetector.Detect(ctx, targetURL, username)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testDepConfusion probes the host for internal-package manifest
// leaks that enable dependency-confusion.
func (s *InternalScanner) testDepConfusion(ctx context.Context, targetURL string) []*core.Finding {
	if s.depConfusionDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing for dependency-confusion manifests on '%s'...\n", targetURL)
	}
	res, err := s.depConfusionDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testTokenEntropy inspects Set-Cookie / embedded CSRF tokens for
// insecure-randomness signals.
func (s *InternalScanner) testTokenEntropy(ctx context.Context, targetURL string) []*core.Finding {
	if s.tokenEntropyDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Inspecting token entropy on '%s'...\n", targetURL)
	}
	res, err := s.tokenEntropyDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
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

// testCrossIdentityIDOR runs the two-identity BOLA probe when both
// AuthA and AuthB are configured. The detector itself is generic; the
// orchestrator decides which URL to probe (config override or scan
// target) and constructs the two auth-bearing clients from AuthState.
// Only meaningful with at least one of the two identities providing
// auth material; otherwise it would just be two anonymous fetches.
func (s *InternalScanner) testCrossIdentityIDOR(ctx context.Context, targetURL string) []*core.Finding {
	if s.idorDetector == nil {
		return nil
	}
	if !s.config.AuthA.HasAuth() || !s.config.AuthB.HasAuth() {
		return nil
	}
	probeURL := s.config.IDORTargetURL
	if probeURL == "" {
		probeURL = targetURL
	}
	if probeURL == "" {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing two-identity IDOR/BOLA on '%s'...\n", probeURL)
	}

	victim := buildAuthClient(s.client, s.config.AuthA)
	attacker := buildAuthClient(s.client, s.config.AuthB)
	result, err := s.idorDetector.DetectCrossIdentity(ctx, probeURL, victim, attacker, idor.DefaultCrossIdentityOptions())
	if err != nil || result == nil || !result.Vulnerable {
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
