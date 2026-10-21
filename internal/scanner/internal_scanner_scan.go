package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/xss"
	"github.com/TyrusRC/assay/internal/payloads/paraminject"
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
	// the shared client. Detectors hold their own reference to this same
	// client object, so mutating it propagates settings to every detector.
	// One-Scanner-per-Scan is the contract — concurrent scans on the same
	// InternalScanner instance are not supported.
	applyScanConfigInPlace(s.client, scanConfig)
	scanClient := s.client

	// Target-down detection: cancel the scan when the HTTP client has seen
	// too many consecutive connection failures.
	maxConnErr := s.config.MaxConsecutiveErrors
	if maxConnErr <= 0 {
		maxConnErr = 20
	}
	scanCtx, scanCancel := context.WithCancel(ctx)

	// Keep the authenticated session alive for the scan's duration: poll the
	// canary and re-authenticate on logout so authed probes do not silently
	// degrade to unauthenticated. Uses scanClient (not s.client) so the
	// keepalive traffic goes through the same proxy and carries the same
	// auth headers as the actual scan.
	if s.config.Session != nil {
		sessCtx, sessCancel := context.WithCancel(scanCtx)
		defer sessCancel()
		go s.config.Session.Keepalive(sessCtx, scanClient, s.config.SessionCheckInterval, func(note string) {
			fmt.Fprintf(os.Stderr, "[*] %s\n", note)
		})
	}
	defer scanCancel()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-scanCtx.Done():
				return
			case <-ticker.C:
				if scanClient.ConnErrors() >= maxConnErr {
					fmt.Fprintf(os.Stderr, "[!] Aborting scan — target appears down (%d consecutive connection failures)\n", scanClient.ConnErrors())
					scanCancel()
					return
				}
			}
		}
	}()

	// Reset the per-scan baseline cache. Each of the 7 bank-driven
	// parameter-injection detectors fetches the target URL once as its
	// baseline; sharing those results across detectors saves up to 6
	// duplicate GETs per parameterised URL.
	s.baselineCache = paraminject.NewCache()

	// 1. Technology detection (fast, provides context)
	if s.config.EnableTechScan && s.techDetector != nil {
		fmt.Fprintf(os.Stderr, "[*] Running tech stack detection...\n")
		techResult := s.detectTechnologiesWithClient(scanCtx, targetURL, scanClient)
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
		discoveryResult, discoveryErr := s.discoveryPipeline.Run(scanCtx, targetURL)
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

	// Prioritize spec-discovered params (SourceURL set) over generic
	// built-in header probes. Without this, 12 built-in headers eat
	// the first concurrency slots and body/path params from the OpenAPI
	// spec never reach the detectors within the scan timeout.
	sort.SliceStable(params, func(i, j int) bool {
		iSpec := params[i].SourceURL != ""
		jSpec := params[j].SourceURL != ""
		return iSpec && !jSpec
	})

	// --param filter: test only the named parameters.
	if len(s.config.OnlyParams) > 0 {
		allowed := make(map[string]bool, len(s.config.OnlyParams))
		for _, n := range s.config.OnlyParams {
			allowed[n] = true
		}
		var filtered []core.Parameter
		for _, p := range params {
			if allowed[p.Name] {
				filtered = append(filtered, p)
			}
		}
		params = filtered
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

	// Live progress tracking. The per-parameter counter is only printed in
	// verbose mode; counters are always maintained and summarized at the end.
	prog := NewProgress(len(params), s.config.Verbose)

	var wg sync.WaitGroup
	findingsChan := make(chan *core.Finding, 100)

	method := "GET"
	if scanConfig != nil && scanConfig.Method != "" {
		method = scanConfig.Method
	}

	// Drain findings concurrently to prevent channel deadlock.
	// A mutex protects the slice so mid-phase flushes can snapshot
	// without racing the collector goroutine.
	var collectedFindings core.Findings
	var findingsMu sync.Mutex
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for finding := range findingsChan {
			findingsMu.Lock()
			collectedFindings = append(collectedFindings, finding)
			findingsMu.Unlock()
			prog.IncrementFindings(1)
		}
	}()

	// partialDir is where we flush intermediate results so early-phase
	// findings survive if a later phase hangs or the process is killed.
	partialDir := ""
	if scanConfig != nil && scanConfig.OutputDir != "" {
		partialDir = scanConfig.OutputDir
	}

	// Phase 1: parameter-injection tests, only when we have params to inject into.
	// Split into two batches: spec-discovered params (SourceURL set) run first
	// to completion, then generic built-in headers. This prevents header probes
	// from starving the API params that carry the real findings.
	if len(params) > 0 {
		prog.SetPhase("parameter-injection")
		ClassifyParameters(scanCtx, scanClient, targetURL, params, method)

		var specParams, genericParams []core.Parameter
		for _, p := range params {
			if p.SourceURL != "" {
				specParams = append(specParams, p)
			} else {
				genericParams = append(genericParams, p)
			}
		}

		if len(specParams) > 0 {
			fmt.Fprintf(os.Stderr, "[*] Phase 1a: spec-discovered params (%d)...\n", len(specParams))
			s.runParameterTests(scanCtx, &wg, findingsChan, specParams, targetURL, method, scanClient, prog)
			wg.Wait()
			flushPartialFindings(&findingsMu, &collectedFindings, partialDir)
		}
		if len(genericParams) > 0 {
			fmt.Fprintf(os.Stderr, "[*] Phase 1b: generic header params (%d)...\n", len(genericParams))
			s.runParameterTests(scanCtx, &wg, findingsChan, genericParams, targetURL, method, scanClient, prog)
			wg.Wait()
		}
	}
	flushPartialFindings(&findingsMu, &collectedFindings, partialDir)

	// Phase 1.5: URL-level tests (IDOR, CORS, StorageInj) - run once per URL, not per parameter
	prog.SetPhase("url-level")
	fmt.Fprintf(os.Stderr, "[*] Phase 1.5: URL-level tests...\n")
	s.runURLLevelTests(scanCtx, &wg, findingsChan, targetURL, scanConfig)

	// Wait for URL-level tests
	wg.Wait()
	flushPartialFindings(&findingsMu, &collectedFindings, partialDir)

	// Phase 1.75: Template scanning (after URL-level tests, before OOB)
	if s.config.EnableTemplates && len(s.config.TemplatePaths) > 0 {
		prog.SetPhase("templates")
		fmt.Fprintf(os.Stderr, "[*] Phase 1.75: template scans...\n")
		proxyURL := ""
		if scanConfig != nil {
			proxyURL = scanConfig.ProxyURL
		}
		s.runTemplateTests(scanCtx, &wg, findingsChan, target, proxyURL, scanConfig)
		wg.Wait()
		flushPartialFindings(&findingsMu, &collectedFindings, partialDir)
	}

	// Phase 1.8: Stored XSS (inject→crawl→match→confirm). Runs after injection
	// and URL-level phases so discovered parameters are available. Opt-in
	// because it's slow and noisy — enabled in the thorough profile or via flag.
	if s.config.EnableStoredXSS && len(params) > 0 && s.storedXSSDetector != nil {
		prog.SetPhase("stored-xss")
		fmt.Fprintf(os.Stderr, "[*] Phase 1.8: stored XSS detection...\n")
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts := xss.DefaultStoredOptions()
			findings := s.storedXSSDetector.DetectStored(scanCtx, targetURL, params, method, opts)
			emit(scanCtx, findingsChan, findings)
			if len(findings) > 0 {
				fmt.Fprintf(os.Stderr, "[+] Stored XSS: %d findings\n", len(findings))
			}
		}()
		wg.Wait()
		flushPartialFindings(&findingsMu, &collectedFindings, partialDir)
	}

	// Phase 2: OOB detection (after SQLi/XSS, wait for OOB client with timeout)
	prog.SetPhase("oob")
	fmt.Fprintf(os.Stderr, "[*] Phase 2: OOB / blind-vulnerability detection...\n")
	s.runOOBTests(scanCtx, &wg, findingsChan, result, params, targetURL, method, scanClient)

	wg.Wait()

	// Close channel and wait for collector to finish
	close(findingsChan)
	collectWg.Wait()

	prog.Finish()

	// Deduplicate findings
	result.Findings = collectedFindings.Deduplicate()

	// Remove partial-results file — the caller writes the final report.
	if partialDir != "" {
		os.Remove(filepath.Join(partialDir, "assay-partial.json"))
	}

	fmt.Fprintf(os.Stderr, "[+] Internal scan finished for %s — %d findings\n", targetURL, len(result.Findings))

	// Surface baseline-cache effectiveness. Quiet on verbose-off when the
	// cache was never consulted (no parameterised URLs in scope).
	if stats := s.baselineCache.Stats(); stats.Hits+stats.Misses > 0 {
		fmt.Fprintf(os.Stderr, "[*] Baseline cache: %d hits / %d misses (%.0f%% hit rate; %d GETs saved)\n",
			stats.Hits, stats.Misses, stats.HitRate()*100, stats.Hits)
	}

	return result, nil
}

// flushPartialFindings writes the current findings snapshot to
// <dir>/assay-partial.json. Called after each scan phase so findings
// from earlier phases survive if a later phase hangs or the process
// is killed. The partial file is removed on normal scan completion.
func flushPartialFindings(mu *sync.Mutex, findings *core.Findings, dir string) {
	if dir == "" {
		return
	}
	mu.Lock()
	n := len(*findings)
	if n == 0 {
		mu.Unlock()
		return
	}
	snapshot := make(core.Findings, n)
	copy(snapshot, *findings)
	mu.Unlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "assay-partial.json")
	if err := os.WriteFile(path, data, 0o644); err == nil {
		fmt.Fprintf(os.Stderr, "[*] Flushed %d partial findings to %s\n", n, path)
	}
}
