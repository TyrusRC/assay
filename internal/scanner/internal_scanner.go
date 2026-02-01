package scanner

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cmdi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cors"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/crlf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/idor"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/injection"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/jwt"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/lfi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/nosql"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/oob"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/redirect"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssrf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssti"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/techstack"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xss"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xxe"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// InternalScanner provides built-in vulnerability detection capabilities.
// It complements external tools by providing detection for common vulnerabilities
// using the internal detection modules.
type InternalScanner struct {
	client           *http.Client
	sqliDetector     *injection.SQLiDetector
	xssDetector      *xss.Detector
	cmdiDetector     *cmdi.Detector
	ssrfDetector     *ssrf.Detector
	lfiDetector      *lfi.Detector
	xxeDetector      *xxe.Detector
	techDetector     *techstack.Detector
	nosqlDetector    *nosql.Detector
	sstiDetector     *ssti.Detector
	idorDetector     *idor.Detector
	jwtDetector      *jwt.Detector
	redirectDetector *redirect.Detector
	corsDetector     *cors.Detector
	crlfDetector     *crlf.Detector
	oobClient        *oob.Client
	oobReady         chan struct{} // signals when OOB client is ready
	oobInitErr       error         // error from OOB initialization
	config           *InternalScanConfig
	mu               sync.Mutex
}

// InternalScanConfig configures the internal scanner behavior.
type InternalScanConfig struct {
	// Enable/disable specific checks
	EnableSQLi     bool
	EnableXSS      bool
	EnableCMDI     bool
	EnableSSRF     bool
	EnableLFI      bool
	EnableXXE      bool
	EnableTechScan bool
	EnableOOB      bool
	EnableNoSQL    bool
	EnableSSTI     bool
	EnableIDOR     bool
	EnableJWT      bool
	EnableRedirect bool
	EnableCORS     bool
	EnableCRLF     bool

	// Scan intensity
	MaxPayloadsPerParam int
	IncludeWAFBypass    bool

	// Timeouts
	RequestTimeout time.Duration
	OOBPollTimeout time.Duration

	// Verbosity
	Verbose bool
}

// DefaultInternalConfig returns a reasonable default configuration.
func DefaultInternalConfig() *InternalScanConfig {
	return &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           true,
		EnableCMDI:          true,
		EnableSSRF:          true,
		EnableLFI:           true,
		EnableXXE:           true,
		EnableTechScan:      true,
		EnableOOB:           true, // OOB enabled by default - runs async to not block main scan
		EnableNoSQL:         true,
		EnableSSTI:          true,
		EnableIDOR:          true,
		EnableJWT:           false, // JWT requires token extraction, disable by default
		EnableRedirect:      true,
		EnableCORS:          true,
		EnableCRLF:          true,
		MaxPayloadsPerParam: 30,
		IncludeWAFBypass:    true,
		RequestTimeout:      10 * time.Second,
		OOBPollTimeout:      10 * time.Second,
		Verbose:             false,
	}
}

// NewInternalScanner creates a new internal scanner.
func NewInternalScanner(config *InternalScanConfig) (*InternalScanner, error) {
	if config == nil {
		config = DefaultInternalConfig()
	}

	// Create HTTP client
	httpClient := http.NewClient().WithTimeout(config.RequestTimeout)

	// Create tech detector (may fail if wappalyzer can't initialize)
	techDetector, techErr := techstack.NewDetector()
	if techErr != nil && config.Verbose {
		fmt.Printf("[!] Tech stack detection unavailable: %v\n", techErr)
	}

	scanner := &InternalScanner{
		client:           httpClient,
		sqliDetector:     injection.NewSQLiDetector(),
		xssDetector:      xss.New(httpClient),
		cmdiDetector:     cmdi.New(httpClient),
		ssrfDetector:     ssrf.New(httpClient),
		lfiDetector:      lfi.New(httpClient),
		xxeDetector:      xxe.New(httpClient),
		techDetector:     techDetector,
		nosqlDetector:    nosql.New(httpClient),
		sstiDetector:     ssti.New(httpClient),
		idorDetector:     idor.New(httpClient),
		jwtDetector:      jwt.NewDetector(),
		redirectDetector: redirect.New(httpClient),
		corsDetector:     cors.New(httpClient),
		crlfDetector:     crlf.New(httpClient),
		config:           config,
	}

	// OOB client will be initialized lazily during scan if needed
	// This prevents blocking scanner creation

	return scanner, nil
}

// startOOBClientAsync starts OOB client initialization in the background.
// It signals completion via the oobReady channel.
func (s *InternalScanner) startOOBClientAsync() {
	if !s.config.EnableOOB {
		return
	}

	s.mu.Lock()
	if s.oobReady != nil {
		s.mu.Unlock()
		return // Already started
	}
	s.oobReady = make(chan struct{})
	s.mu.Unlock()

	go func() {
		defer close(s.oobReady)

		oobClient, err := oob.NewClient()
		s.mu.Lock()
		defer s.mu.Unlock()

		if err != nil {
			s.oobInitErr = err
			if s.config.Verbose {
				fmt.Printf("[!] OOB testing unavailable: %v\n", err)
			}
		} else {
			s.oobClient = oobClient
			if s.config.Verbose {
				fmt.Printf("[+] OOB testing enabled with URL: %s\n", oobClient.GetURL())
			}
		}
	}()
}

// waitForOOBClient waits for OOB client to be ready with a timeout.
// Returns true if OOB client is available, false otherwise.
func (s *InternalScanner) waitForOOBClient(timeout time.Duration) bool {
	if s.oobReady == nil {
		return false
	}

	select {
	case <-s.oobReady:
		s.mu.Lock()
		available := s.oobClient != nil
		s.mu.Unlock()
		return available
	case <-time.After(timeout):
		if s.config.Verbose {
			fmt.Printf("[!] OOB initialization timeout after %v\n", timeout)
		}
		return false
	}
}

// Close releases resources.
func (s *InternalScanner) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.oobClient != nil {
		s.oobClient.Close()
	}
}

// InternalScanResult contains results from internal scanning.
type InternalScanResult struct {
	Findings     core.Findings
	Technologies *techstack.DetectionResult
	Errors       []string
}

// Scan performs internal vulnerability scanning on a target.
func (s *InternalScanner) Scan(ctx context.Context, target *core.Target, scanConfig *Config) (*InternalScanResult, error) {
	result := &InternalScanResult{
		Findings: make(core.Findings, 0),
	}

	targetURL := target.URL()

	if s.config.Verbose {
		fmt.Printf("[*] Internal scanner starting for: %s\n", targetURL)
	}

	// Start OOB initialization in background immediately (non-blocking)
	// This gives OOB time to initialize while we run other tests
	if s.config.EnableOOB {
		s.startOOBClientAsync()
		if s.config.Verbose {
			fmt.Printf("[*] OOB initialization started in background...\n")
		}
	}

	// Create a scan-specific client to avoid race conditions when modifying settings.
	// Each scan gets its own client instance with the scan-specific configuration.
	scanClient := http.NewClient().WithTimeout(s.config.RequestTimeout)

	// Configure the scan-specific HTTP client with scan settings
	if scanConfig != nil {
		scanClient = scanClient.
			WithHeaders(scanConfig.Headers).
			WithCookies(scanConfig.Cookies)
		if scanConfig.ProxyURL != "" {
			scanClient = scanClient.WithProxy(scanConfig.ProxyURL)
		}
		if scanConfig.Insecure {
			scanClient = scanClient.WithInsecure(true)
		}
	}

	// 1. Technology detection (fast, provides context)
	if s.config.EnableTechScan && s.techDetector != nil {
		if s.config.Verbose {
			fmt.Printf("[*] Running tech stack detection...\n")
		}
		techResult := s.detectTechnologiesWithClient(ctx, targetURL, scanClient)
		result.Technologies = techResult
		if s.config.Verbose && techResult != nil {
			fmt.Printf("[+] Detected %d technologies\n", len(techResult.Technologies))
		}
	}

	// 2. Extract parameters from target
	params := s.extractParameters(target)
	if len(params) == 0 {
		result.Errors = append(result.Errors, "no parameters found to test")
		if s.config.Verbose {
			fmt.Printf("[!] No parameters found to test\n")
		}
		return result, nil
	}

	if s.config.Verbose {
		fmt.Printf("[*] Testing %d parameters: %v\n", len(params), params)
	}

	// 3. Test each parameter for vulnerabilities (SQLi and XSS first, then OOB)
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

	// Phase 1: Run all injection tests (don't wait for OOB)
	s.runParameterTests(ctx, &wg, findingsChan, params, targetURL, method, scanClient)

	// Wait for parameter-based tests to complete
	wg.Wait()

	// Phase 1.5: URL-level tests (IDOR, CORS) - run once per URL, not per parameter
	s.runURLLevelTests(ctx, &wg, findingsChan, targetURL)

	// Wait for URL-level tests
	wg.Wait()

	// Phase 2: OOB detection (after SQLi/XSS, wait for OOB client with timeout)
	s.runOOBTests(ctx, &wg, findingsChan, result, params, targetURL, method, scanClient)

	wg.Wait()

	// Close channel and wait for collector to finish
	close(findingsChan)
	collectWg.Wait()

	// Deduplicate findings
	result.Findings = collectedFindings.Deduplicate()

	return result, nil
}

// detectTechnologiesWithClient detects web technologies using the provided client.
func (s *InternalScanner) detectTechnologiesWithClient(ctx context.Context, targetURL string, client *http.Client) *techstack.DetectionResult {
	// Make a request to get headers and body
	resp, err := client.Get(ctx, targetURL)
	if err != nil {
		return nil
	}

	// Response headers are already map[string]string
	return s.techDetector.Analyze(targetURL, resp.Headers, resp.Body)
}

// extractParameters extracts testable parameters from the target.
func (s *InternalScanner) extractParameters(target *core.Target) []string {
	var params []string
	seen := make(map[string]bool)

	// Parse URL to get query parameters
	parsedURL, err := url.Parse(target.URL())
	if err != nil {
		return params
	}

	// Get query parameters
	for key := range parsedURL.Query() {
		if !seen[key] {
			params = append(params, key)
			seen[key] = true
		}
	}

	return params
}

// runParameterTests launches goroutines for all parameter-level injection tests.
func (s *InternalScanner) runParameterTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, params []string, targetURL, method string, scanClient *http.Client) {
	for _, param := range params {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			s.runParamDetectors(ctx, findingsChan, targetURL, p, method, scanClient)
		}(param)
	}
}

// runParamDetectors runs all parameter-based detectors for a single parameter.
func (s *InternalScanner) runParamDetectors(ctx context.Context, findingsChan chan<- *core.Finding, targetURL, param, method string, scanClient *http.Client) {
	type paramTest struct {
		enabled bool
		run     func() []*core.Finding
	}

	tests := []paramTest{
		{s.config.EnableSQLi, func() []*core.Finding { return s.testSQLiWithClient(ctx, targetURL, param, method, scanClient) }},
		{s.config.EnableXSS, func() []*core.Finding { return s.testXSS(ctx, targetURL, param, method) }},
		{s.config.EnableCMDI, func() []*core.Finding { return s.testCMDI(ctx, targetURL, param, method) }},
		{s.config.EnableSSRF, func() []*core.Finding { return s.testSSRF(ctx, targetURL, param, method) }},
		{s.config.EnableLFI, func() []*core.Finding { return s.testLFI(ctx, targetURL, param, method) }},
		{s.config.EnableXXE, func() []*core.Finding { return s.testXXEInParam(ctx, targetURL, param, method) }},
		{s.config.EnableNoSQL, func() []*core.Finding { return s.testNoSQL(ctx, targetURL, param, method) }},
		{s.config.EnableSSTI, func() []*core.Finding { return s.testSSTI(ctx, targetURL, param, method) }},
		{s.config.EnableRedirect, func() []*core.Finding { return s.testRedirect(ctx, targetURL, param, method) }},
		{s.config.EnableCRLF, func() []*core.Finding { return s.testCRLF(ctx, targetURL, param, method) }},
	}

	for _, t := range tests {
		if !t.enabled {
			continue
		}
		for _, f := range t.run() {
			findingsChan <- f
		}
	}
}

// runURLLevelTests launches goroutines for URL-level tests (IDOR, CORS).
func (s *InternalScanner) runURLLevelTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	if s.config.EnableIDOR {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testIDOR(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableCORS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testCORS(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}
}

// runOOBTests launches goroutines for OOB detection tests.
func (s *InternalScanner) runOOBTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, result *InternalScanResult, params []string, targetURL, method string, scanClient *http.Client) {
	if !s.config.EnableOOB {
		return
	}

	if s.waitForOOBClient(10 * time.Second) {
		if s.config.Verbose {
			fmt.Printf("[*] Running OOB tests...\n")
		}
		for _, param := range params {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				for _, f := range s.testOOBWithClient(ctx, targetURL, p, method, scanClient) {
					findingsChan <- f
				}
			}(param)
		}
	} else {
		result.Errors = append(result.Errors, "OOB testing skipped: initialization failed or timed out")
	}
}
