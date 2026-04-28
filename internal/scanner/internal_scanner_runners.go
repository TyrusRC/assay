package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// emit forwards findings from a detector goroutine to the shared channel.
// The collector goroutine in InternalScanner.Scan is GUARANTEED to be
// draining findingsChan until close() runs — close happens after all
// wg.Wait() calls return, so no producer can outlive the collector. A
// ctx-guarded send was tried and reverted: it dropped already-collected
// findings on timeout, which is strictly worse than letting the buffered
// channel absorb the trailing batch.
func emit(_ context.Context, ch chan<- *core.Finding, findings []*core.Finding) {
	for _, f := range findings {
		ch <- f
	}
}

// runTemplateTests executes nuclei-compatible templates against a target.
// proxyURL, when non-empty, routes all template traffic through the given proxy.
// scanCfg, when non-nil, also forwards Headers/Cookies/UserAgent so template
// requests inherit the same authentication and Burp-Suite plumbing as native
// detectors.
func (s *InternalScanner) runTemplateTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, target *core.Target, proxyURL string, scanCfg *Config) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Running template scanner...\n")
		}

		tsCfg := DefaultTemplateScanConfig()
		tsCfg.Verbose = s.config.Verbose
		tsCfg.ProxyURL = proxyURL
		if scanCfg != nil {
			tsCfg.Headers = scanCfg.Headers
			tsCfg.Cookies = scanCfg.Cookies
			tsCfg.UserAgent = scanCfg.UserAgent
			tsCfg.Insecure = scanCfg.Insecure
		}

		// Use first path as directory; additional paths as individual files
		if len(s.config.TemplatePaths) == 1 {
			tsCfg.TemplatesDir = s.config.TemplatePaths[0]
		} else {
			tsCfg.TemplatesDir = s.config.TemplatePaths[0]
			tsCfg.TemplatePaths = s.config.TemplatePaths[1:]
		}

		if len(s.config.TemplateTags) > 0 {
			tsCfg.IncludeTags = s.config.TemplateTags
		}

		ts, err := NewTemplateScanner(tsCfg)
		if err != nil {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] Template scanner creation failed: %v\n", err)
			}
			return
		}

		tsResult, err := ts.ScanWithLoad(ctx, target)
		if err != nil {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] Template scan error: %v\n", err)
			}
			return
		}

		emit(ctx, findingsChan, tsResult.Findings)

		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[+] Template scanner completed: %d findings from %d/%d templates\n",
				len(tsResult.Findings), tsResult.TemplatesRun, tsResult.TemplatesLoaded)
		}
	}()
}

// runParameterTests launches goroutines for all parameter-level injection tests.
func (s *InternalScanner) runParameterTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, params []core.Parameter, targetURL, method string, scanClient *http.Client) {
	for _, param := range params {
		wg.Add(1)
		go func(p core.Parameter) {
			defer wg.Done()
			s.runParamDetectors(ctx, findingsChan, targetURL, p, method, scanClient)
		}(param)
	}
}

// paramTest represents a named, enabled detector test for a parameter.
type paramTest struct {
	name    string
	enabled bool
	run     func() []*core.Finding
}

// applicableTests returns which detectors should run based on parameter location.
// This prevents running irrelevant detectors (e.g., LFI on a cookie parameter).
func (s *InternalScanner) applicableTests(param core.Parameter) []paramTest {
	// Build the full test registry (without closures - just names and enabled flags)
	allTests := []struct {
		name    string
		enabled bool
	}{
		{"sqli", s.config.EnableSQLi},
		{"xss", s.config.EnableXSS},
		{"cmdi", s.config.EnableCMDI},
		{"ssrf", s.config.EnableSSRF},
		{"lfi", s.config.EnableLFI},
		{"xxe", s.config.EnableXXE},
		{"nosql", s.config.EnableNoSQL},
		{"ssti", s.config.EnableSSTI},
		{"redirect", s.config.EnableRedirect},
		{"crlf", s.config.EnableCRLF},
		{"ldap", s.config.EnableLDAP},
		{"xpath", s.config.EnableXPath},
		{"headerinj", s.config.EnableHeaderInj},
		{"csti", s.config.EnableCSTI},
		{"rfi", s.config.EnableRFI},
		{"csvinj", s.config.EnableCSVInj},
	}

	// Define which tests apply per location
	var applicableNames map[string]bool

	switch param.Location {
	case core.ParamLocationQuery, core.ParamLocationBody:
		// All injection detectors apply
		applicableNames = nil // nil means all
	case core.ParamLocationCookie:
		applicableNames = map[string]bool{
			"sqli": true, "xss": true, "crlf": true,
			"headerinj": true, "nosql": true,
		}
	case core.ParamLocationHeader:
		applicableNames = map[string]bool{
			"crlf": true, "headerinj": true, "ssti": true, "ssrf": true,
		}
	case core.ParamLocationPath:
		applicableNames = map[string]bool{
			"sqli": true, "lfi": true, "cmdi": true, "nosql": true, "xpath": true,
		}
	case core.ParamLocationLocalStorage, core.ParamLocationSessionStorage:
		applicableNames = map[string]bool{
			"xss": true,
		}
	default:
		applicableNames = nil // unknown location, run all
	}

	var result []paramTest
	for _, t := range allTests {
		if !t.enabled {
			continue
		}
		if applicableNames != nil && !applicableNames[t.name] {
			continue
		}
		result = append(result, paramTest{
			name:    t.name,
			enabled: t.enabled,
		})
	}
	return result
}

// runParamDetectors runs location-appropriate detectors for a single parameter.
func (s *InternalScanner) runParamDetectors(ctx context.Context, findingsChan chan<- *core.Finding, targetURL string, param core.Parameter, method string, scanClient *http.Client) {
	// Build a name -> runner map
	runners := map[string]func() []*core.Finding{
		"sqli":      func() []*core.Finding { return s.testSQLiWithClient(ctx, targetURL, param, method, scanClient) },
		"xss":       func() []*core.Finding { return s.testXSS(ctx, targetURL, param, method) },
		"cmdi":      func() []*core.Finding { return s.testCMDI(ctx, targetURL, param, method) },
		"ssrf":      func() []*core.Finding { return s.testSSRF(ctx, targetURL, param, method) },
		"lfi":       func() []*core.Finding { return s.testLFI(ctx, targetURL, param, method) },
		"xxe":       func() []*core.Finding { return s.testXXEInParam(ctx, targetURL, param, method) },
		"nosql":     func() []*core.Finding { return s.testNoSQL(ctx, targetURL, param, method) },
		"ssti":      func() []*core.Finding { return s.testSSTI(ctx, targetURL, param, method) },
		"redirect":  func() []*core.Finding { return s.testRedirect(ctx, targetURL, param, method) },
		"crlf":      func() []*core.Finding { return s.testCRLF(ctx, targetURL, param, method) },
		"ldap":      func() []*core.Finding { return s.testLDAP(ctx, targetURL, param, method) },
		"xpath":     func() []*core.Finding { return s.testXPath(ctx, targetURL, param, method) },
		"headerinj": func() []*core.Finding { return s.testHeaderInj(ctx, targetURL, param, method) },
		"csti":      func() []*core.Finding { return s.testCSTI(ctx, targetURL, param, method) },
		"rfi":       func() []*core.Finding { return s.testRFI(ctx, targetURL, param, method) },
		"csvinj":    func() []*core.Finding { return s.testCSVInj(ctx, targetURL, param, method) },
	}

	applicable := s.applicableTests(param)
	for _, t := range applicable {
		if s.confirmed.shouldSkip(param.Name, t.name) {
			continue
		}
		runner, ok := runners[t.name]
		if !ok {
			continue
		}
		findings := runner()
		if len(findings) > 0 {
			s.confirmed.confirm(param.Name, t.name)
			emit(ctx, findingsChan, findings)
		}
	}
}

// runURLLevelTests launches goroutines for URL-level tests (IDOR, CORS, and friends).
// Each enabled detector runs in its own goroutine to maximize parallelism — they all
// hit a shared findingsChan that the caller drains.
func (s *InternalScanner) runURLLevelTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	if s.config.EnableIDOR {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testIDOR(ctx, targetURL))
		}()
	}

	if s.config.EnableCORS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testCORS(ctx, targetURL))
		}()
	}

	if s.config.EnableJNDI {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testJNDI(ctx, targetURL))
		}()
	}

	if s.config.EnableSecHeaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testSecHeaders(ctx, targetURL))
		}()
	}

	if s.config.EnableExposure {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testExposure(ctx, targetURL))
		}()
	}

	if s.config.EnableCloud {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testCloud(ctx, targetURL))
		}()
	}

	if s.config.EnableSubTakeover && len(s.config.Subdomains) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testSubTakeover(ctx))
		}()
	}

	if s.config.EnableTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testTLS(ctx, targetURL))
		}()
	}

	if s.config.EnableAuth && s.config.LoginURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testAuth(ctx, s.config.LoginURL))
		}()
	}

	if s.config.EnableGraphQL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testGraphQL(ctx, targetURL))
		}()
	}

	if s.config.EnableSmuggling {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testSmuggling(ctx, targetURL))
		}()
	}

	if s.config.EnableStorageInj && s.storageInjDetector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testStorageInj(ctx, targetURL))
		}()
	}

	if s.config.EnableLogInj {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testLogInj(ctx, targetURL))
		}()
	}

	if s.config.EnableFileUpload {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testFileUpload(ctx, targetURL))
		}()
	}

	if s.config.EnableVerbTamper {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testVerbTamper(ctx, targetURL))
		}()
	}

	if s.config.EnablePathNorm {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testPathNorm(ctx, targetURL))
		}()
	}

	if s.config.EnableRaceCond {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testRaceCond(ctx, targetURL))
		}()
	}

	if s.config.EnableWS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testWS(ctx, targetURL))
		}()
	}

	if s.config.EnableHostHdr {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testHostHdr(ctx, targetURL))
		}()
	}

	if s.config.EnableOAuth {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emit(ctx, findingsChan, s.testOAuth(ctx, targetURL))
		}()
	}
}

// runOOBTests launches goroutines for OOB detection tests.
func (s *InternalScanner) runOOBTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, result *InternalScanResult, params []core.Parameter, targetURL, method string, scanClient *http.Client) {
	if !s.config.EnableOOB {
		return
	}

	if s.waitForOOBClient(10 * time.Second) {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Running OOB tests...\n")
		}
		for _, param := range params {
			wg.Add(1)
			go func(p core.Parameter) {
				defer wg.Done()
				emit(ctx, findingsChan, s.testOOBWithClient(ctx, targetURL, p, method, scanClient))
			}(param)
		}
	} else {
		result.Errors = append(result.Errors, "OOB testing skipped: initialization failed or timed out")
	}
}
