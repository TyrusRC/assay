package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/iast"
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

	// Start the IAST callback server when enabled. Sensors deployed in the
	// target app POST SinkHit reports here when a taint marker reaches a
	// dangerous function (sql_query, sys_command, file_open, etc.).
	if s.config.EnableIAST {
		addr := s.config.IASTCallbackAddr
		if addr == "" {
			addr = iast.DefaultAddr
		}
		s.iastServer = iast.NewServer(addr)
		iastCtx, iastCancel := context.WithCancel(ctx)
		defer iastCancel()
		go func() {
			if err := s.iastServer.Start(iastCtx); err != nil {
				fmt.Fprintf(os.Stderr, "[!] IAST callback server: %v\n", err)
			}
		}()
		fmt.Fprintf(os.Stderr, "[*] IAST callback server listening on %s\n", addr)
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
		maxConnErr = 50
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
	// Check connection health at phase boundaries (below), not on a
	// ticker. A 5s ticker cancelled the context mid-Phase-1a when
	// transient Docker/WSL connection bursts spiked the counter,
	// killing goroutines that had already found real vulnerabilities.
	checkHealth := func(phase string) bool {
		if scanClient.ConnErrors() >= maxConnErr {
			fmt.Fprintf(os.Stderr, "[!] Aborting scan after %s — target appears down (%d consecutive connection failures)\n", phase, scanClient.ConnErrors())
			scanCancel()
			return false
		}
		return true
	}

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
		// Populate Technologies for the smart tool dispatcher.
		s.Technologies = s.Technologies[:0]
		if techResult != nil {
			for _, tech := range techResult.Technologies {
				s.Technologies = append(s.Technologies, tech.Name)
			}
		}
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
			// Save discovered URLs for the smart tool dispatcher.
			urls := make([]string, 0, len(discoveryResult.Sources))
			for src := range discoveryResult.Sources {
				urls = append(urls, src)
			}
			s.mu.Lock()
			s.discoveredURLs = urls
			s.mu.Unlock()
		}
	}

	// 3. Extract parameters from target config (query, cookie, path)
	params := s.extractParametersWithConfig(target, scanConfig)

	// Merge discovered params into params. Dedup by Name+Location+SourceURL
	// so the same header on different endpoints (e.g. X-Auth-Token on /user
	// vs /widget) is tested separately — each endpoint may have different
	// SQL queries behind the same param name.
	if len(discoveredParams) > 0 {
		seen := make(map[string]bool)
		for _, p := range params {
			seen[p.Name+":"+p.Location+":"+p.SourceURL] = true
		}
		for _, dp := range discoveredParams {
			key := dp.Name + ":" + dp.Location + ":" + dp.SourceURL
			if !seen[key] {
				seen[key] = true
				params = append(params, dp)
			}
		}
	}

	// Prioritize params by source quality: spec-discovered first, then
	// path/cookie/body params, then headers, then JS-extracted query params.
	// Without this, JS-extracted noise eats concurrency slots and real
	// injectable params (path IDs, form fields) never reach detectors.
	sort.SliceStable(params, func(i, j int) bool {
		return paramPriority(params[i]) < paramPriority(params[j])
	})

	// Filter out garbage params from JS minification. Real param names are
	// short identifiers: alphanumeric + hyphens + underscores. Dots in
	// query params indicate JS property chains (e.g. e.elem.parentNode).
	{
		var clean []core.Parameter
		for _, p := range params {
			if len(p.Name) > 40 {
				continue
			}
			if strings.ContainsAny(p.Name, "(){}[]|;=<>!&^~`$?#@+*%/\\:, \"'") {
				continue
			}
			if strings.Contains(p.Name, ".") && p.Location == "query" {
				continue
			}
			clean = append(clean, p)
		}
		params = clean
	}

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

	// Hard cap: keep the top-priority params to avoid multi-hour scans
	// on apps with hundreds of pages and thousands of form fields.
	maxParams := s.config.MaxParams
	if maxParams <= 0 {
		maxParams = 200
	}
	if len(params) > maxParams {
		fmt.Fprintf(os.Stderr, "[*] Capping parameters from %d to %d (sorted by priority)\n", len(params), maxParams)
		params = params[:maxParams]
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

	// Phase 0: GraphQL introspection + injection. Runs FIRST because GraphQL
	// targets often have hundreds of noise params from JS that bog down Phase 1.
	if s.config.EnableGraphQL && s.graphqlDetector != nil {
		prog.SetPhase("graphql")
		gqlCtx, gqlCancel := context.WithTimeout(scanCtx, 15*time.Second)
		gqlFindings := s.testGraphQL(gqlCtx, targetURL)
		gqlCancel()
		emit(scanCtx, findingsChan, gqlFindings)

		gqlEndpoints, _ := s.graphqlDetector.DiscoverEndpoints(scanCtx, target.BaseURL())
		if len(gqlEndpoints) > 0 {
			gqlURL := gqlEndpoints[0]
			fmt.Fprintf(os.Stderr, "[*] GraphQL injection on %s (%d endpoints)...\n", gqlURL, len(gqlEndpoints))
			prog.SetPhase("graphql-inject")
			gqlInjectCtx, gqlInjectCancel := context.WithTimeout(scanCtx, 60*time.Second)
			s.runGraphQLInjection(gqlInjectCtx, &wg, findingsChan, gqlURL, scanClient)
			wg.Wait()
			gqlInjectCancel()

			// Advanced GraphQL checks (IDOR, SSRF, stored XSS, DoS, info disclosure).
			prog.SetPhase("graphql-advanced")
			fmt.Fprintf(os.Stderr, "[*] GraphQL advanced checks on %s...\n", gqlURL)
			gqlAdvCtx, gqlAdvCancel := context.WithTimeout(scanCtx, 45*time.Second)
			s.runGraphQLAdvancedChecks(gqlAdvCtx, findingsChan, gqlURL, scanClient)
			gqlAdvCancel()
		}
		flushPartialFindings(&findingsMu, &collectedFindings, partialDir)
	}

	// Phase 1: parameter-injection tests in 3 tiers by priority.
	// Tier 1 (body params) get ALL detectors — highest injection value.
	// Tier 2 (query/path/cookie) get the top 5 classes (sqli, xss, cmdi, ssrf, lfi).
	// Tier 3 (headers/noise) get sqli + cmdi only.
	// This ensures body params are fully tested even under time pressure.
	if len(params) > 0 {
		prog.SetPhase("parameter-injection")
		ClassifyParameters(scanCtx, scanClient, targetURL, params, method)

		var tier1, tier2, tier3 []core.Parameter
		for _, p := range params {
			pri := paramPriority(p)
			switch {
			case pri <= 1:
				tier1 = append(tier1, p)
			case pri <= 5:
				tier2 = append(tier2, p)
			default:
				tier3 = append(tier3, p)
			}
		}
		if len(tier1) > 30 {
			tier1 = tier1[:30]
		}
		if len(tier2) > 30 {
			tier2 = tier2[:30]
		}
		if len(tier3) > 15 {
			tier3 = tier3[:15]
		}

		tier2Filter := map[string]bool{
			"sqli": true, "xss": true, "cmdi": true, "ssrf": true, "lfi": true,
			"ssti": true, "nosql": true, "redirect": true,
		}
		tier3Filter := map[string]bool{
			"sqli": true, "cmdi": true, "ssti": true,
		}

		if len(tier1) > 0 {
			fmt.Fprintf(os.Stderr, "[*] Phase 1a: body params — all detectors (%d)...\n", len(tier1))
			s.runParameterTests(scanCtx, &wg, findingsChan, tier1, targetURL, method, scanClient, prog, nil)
			wg.Wait()
			flushPartialFindings(&findingsMu, &collectedFindings, partialDir)
		}
		if len(tier2) > 0 {
			fmt.Fprintf(os.Stderr, "[*] Phase 1b: query/path/cookie — top 5 detectors (%d)...\n", len(tier2))
			s.runParameterTests(scanCtx, &wg, findingsChan, tier2, targetURL, method, scanClient, prog, tier2Filter)
			wg.Wait()
			flushPartialFindings(&findingsMu, &collectedFindings, partialDir)
		}
		if len(tier3) > 0 {
			fmt.Fprintf(os.Stderr, "[*] Phase 1c: headers/noise — sqli+cmdi only (%d)...\n", len(tier3))
			s.runParameterTests(scanCtx, &wg, findingsChan, tier3, targetURL, method, scanClient, prog, tier3Filter)
			wg.Wait()
		}
	}
	flushPartialFindings(&findingsMu, &collectedFindings, partialDir)

	// (GraphQL probe already ran in Phase 0 above.)

	// Phase 1.5: URL-level tests with a hard 90s cap so slow targets
	// (WebLogic, etc.) don't block the entire scan.
	if checkHealth("Phase 1") {
		prog.SetPhase("url-level")
		fmt.Fprintf(os.Stderr, "[*] Phase 1.5: URL-level tests...\n")
		urlCtx, urlCancel := context.WithTimeout(scanCtx, 90*time.Second)
		s.runURLLevelTests(urlCtx, &wg, findingsChan, targetURL, scanConfig)
		wg.Wait()
		urlCancel()
		flushPartialFindings(&findingsMu, &collectedFindings, partialDir)
	}

	// Phase 1.6: Template scanning (runs after URL-level to avoid WAF
	// rate-limit conflicts, but no longer blocked by slow URL-level probes).
	if s.config.EnableTemplates && len(s.config.TemplatePaths) > 0 {
		prog.SetPhase("templates")
		fmt.Fprintf(os.Stderr, "[*] Phase 1.6: template scans...\n")
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

	// IAST confidence upgrade: check the callback server for sink hits and
	// match them to findings. A sink hit means the payload reached the
	// dangerous function, which is the strongest possible confirmation.
	if s.iastServer != nil {
		upgraded := 0
		hits := s.iastServer.Hits()
		for _, hit := range hits {
			for _, f := range result.Findings {
				if f.Confidence == core.ConfidenceConfirmed {
					continue
				}
				evidence := f.Evidence + " " + f.Description
				if hit.MarkerID != "" && strings.Contains(evidence, hit.MarkerID) {
					f.Confidence = core.ConfidenceConfirmed
					f.Evidence += fmt.Sprintf(" [IAST] Marker %s reached %s sink: %s",
						hit.MarkerID, hit.SinkType, hit.StackTrace)
					upgraded++
				}
			}
		}
		if len(hits) > 0 || upgraded > 0 {
			fmt.Fprintf(os.Stderr, "[*] IAST: %d sink hits, %d findings upgraded to confirmed\n",
				len(hits), upgraded)
		}
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

