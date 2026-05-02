package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// Scan performs internal vulnerability scanning on a target. It is the main
// entry point for the scanner: configures the shared HTTP client with the
// per-scan settings (proxy, headers, UA, cookies), then orchestrates tech
// detection, discovery, parameter extraction, and the four detector phases
// (parameter, URL-level, templates, OOB).
func (s *InternalScanner) Scan(ctx context.Context, target *core.Target, scanConfig *Config) (*InternalScanResult, error) {
	result := &InternalScanResult{
		Findings: make(core.Findings, 0),
	}

	targetURL := target.URL()

	fmt.Fprintf(os.Stderr, "[*] Internal scanner starting for: %s\n", targetURL)

	// Start OOB initialization in background immediately (non-blocking)
	// This gives OOB time to initialize while we run other tests
	if s.config.EnableOOB {
		s.startOOBClientAsync()
		fmt.Fprintf(os.Stderr, "[*] OOB initialization started in background...\n")
	}

	// Apply per-scan settings (proxy, headers, cookies, UA, insecure) to
	// the SHARED client so that EVERY detector inherits them. All
	// detectors were constructed with s.client; mutating it here is the
	// single point where Burp-Suite proxying, custom headers, and
	// authenticated User-Agent/cookies are wired in for the whole scan.
	// One-Scanner-per-Scan is the contract; concurrent scans on the same
	// scanner instance would race on these settings.
	applyScanConfig(s.client, scanConfig)

	// scanClient is kept as an alias for the few hot paths that take an
	// explicit *http.Client argument (SQLi, ClassifyParameters, OOB).
	// They now share the same configured instance as the rest.
	scanClient := s.client

	// 1. Technology detection (fast, provides context)
	if s.config.EnableTechScan && s.techDetector != nil {
		fmt.Fprintf(os.Stderr, "[*] Running tech stack detection...\n")
		techResult := s.detectTechnologiesWithClient(ctx, targetURL, scanClient)
		result.Technologies = techResult
		if techResult != nil {
			fmt.Fprintf(os.Stderr, "[+] Detected %d technologies\n", len(techResult.Technologies))
		}

		// Derive tech-aware hints for downstream detectors. Writing under
		// mutex because the same InternalScanner may service concurrent
		// Scan calls, and downstream readers (future detectors) will read
		// this field.
		hint := s.techAwareConfig(techResult)
		s.mu.Lock()
		s.techHint = hint
		s.mu.Unlock()
	}

	// 2. Run discovery pipeline to auto-discover injectable points
	var discoveredParams []core.Parameter
	if s.config.EnableDiscovery && s.discoveryPipeline != nil {
		fmt.Fprintf(os.Stderr, "[*] Running auto-discovery pipeline...\n")
		discoveryResult, discoveryErr := s.discoveryPipeline.Run(ctx, targetURL)
		if discoveryErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("discovery: %v", discoveryErr))
		} else if discoveryResult != nil {
			discoveredParams = discoveryResult.Parameters
			fmt.Fprintf(os.Stderr, "[+] Discovery found %d parameters from %d sources\n",
				len(discoveredParams), len(discoveryResult.Sources))
		}
	}

	// 3. Extract parameters from target config (query, cookie, path)
	params := s.extractParametersWithConfig(target, scanConfig)

	// Merge discovered params into params (deduplicate by Name+Location)
	if len(discoveredParams) > 0 {
		seen := make(map[string]bool)
		for _, p := range params {
			seen[p.Name+":"+p.Location] = true
		}
		for _, dp := range discoveredParams {
			key := dp.Name + ":" + dp.Location
			if !seen[key] {
				seen[key] = true
				params = append(params, dp)
			}
		}
	}

	// URL-level detectors (secheaders, TLS, cloud, smuggling, WS, etc.)
	// must run regardless of how many parameters were discovered — they
	// audit the host, not a parameter. Only the parameter-injection
	// phase is skipped when there's nothing to inject into.
	paramNames := make([]string, 0, len(params))
	for _, p := range params {
		paramNames = append(paramNames, p.Name+"("+p.Location+")")
	}
	if len(params) == 0 {
		fmt.Fprintf(os.Stderr, "[!] No parameters found — skipping injection phase, URL-level tests will still run\n")
	} else if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing %d parameters: %v\n", len(params), paramNames)
	} else {
		fmt.Fprintf(os.Stderr, "[*] Testing %d parameters\n", len(params))
	}

	var wg sync.WaitGroup
	findingsChan := make(chan *core.Finding, 100)

	method := "GET"
	if scanConfig != nil && scanConfig.Method != "" {
		method = scanConfig.Method
	}

	// Drain findings concurrently to prevent channel deadlock
	var collectedFindings core.Findings
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for finding := range findingsChan {
			collectedFindings = append(collectedFindings, finding)
		}
	}()

	// Phase 1: parameter-injection tests, only when we have params to inject into.
	if len(params) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Phase 1: parameter-injection tests...\n")
		ClassifyParameters(ctx, scanClient, targetURL, params, method)
		s.runParameterTests(ctx, &wg, findingsChan, params, targetURL, method, scanClient)
		wg.Wait()
	}

	// Phase 1.5: URL-level tests (IDOR, CORS, StorageInj) - run once per URL, not per parameter
	fmt.Fprintf(os.Stderr, "[*] Phase 1.5: URL-level tests...\n")
	s.runURLLevelTests(ctx, &wg, findingsChan, targetURL)

	// Wait for URL-level tests
	wg.Wait()

	// Phase 1.75: Template scanning (after URL-level tests, before OOB)
	if s.config.EnableTemplates && len(s.config.TemplatePaths) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Phase 1.75: template scans...\n")
		proxyURL := ""
		if scanConfig != nil {
			proxyURL = scanConfig.ProxyURL
		}
		s.runTemplateTests(ctx, &wg, findingsChan, target, proxyURL, scanConfig)
		wg.Wait()
	}

	// Phase 2: OOB detection (after SQLi/XSS, wait for OOB client with timeout)
	fmt.Fprintf(os.Stderr, "[*] Phase 2: OOB / blind-vulnerability detection...\n")
	s.runOOBTests(ctx, &wg, findingsChan, result, params, targetURL, method, scanClient)

	wg.Wait()

	// Close channel and wait for collector to finish
	close(findingsChan)
	collectWg.Wait()

	// Deduplicate findings
	result.Findings = collectedFindings.Deduplicate()

	fmt.Fprintf(os.Stderr, "[+] Internal scan finished for %s — %d findings\n", targetURL, len(result.Findings))

	return result, nil
}
