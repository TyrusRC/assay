package scanner

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/auth"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/behavior"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cloud"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cmdi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/cors"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/crlf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/csvinj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/csti"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/exposure"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/fileupload"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/graphql"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/headerinj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/idor"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/injection"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/jndi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/jwt"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/loginj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ldap"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/lfi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/nosql"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/oob"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/pathnorm"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/racecond"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/redirect"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/rfi"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/secheaders"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/smuggling"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssrf"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/ssti"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/storageinj"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/subtakeover"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/verbtamper"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/techstack"
	tlsdetect "github.com/swiss-knife-for-web-security/skws/internal/detection/tls"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xpath"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xss"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/xxe"
	"github.com/swiss-knife-for-web-security/skws/internal/discovery"
	"github.com/swiss-knife-for-web-security/skws/internal/headless"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// TechHint captures technology names detected during scanning.
type TechHint struct {
	Technologies   []string // lowercase normalized names
	LFIWrappers    bool     // PHP wrappers (php://, phar://)
	JavaDeser      bool     // Java deserialization
	NodeProto      bool     // Prototype pollution
	TemplateEngine string   // Detected template engine name
}

// InternalScanner provides built-in vulnerability detection capabilities.
// It complements external tools by providing detection for common vulnerabilities
// using the internal detection modules.
type InternalScanner struct {
	client              *http.Client
	sqliDetector        *injection.SQLiDetector
	xssDetector         *xss.Detector
	cmdiDetector        *cmdi.Detector
	ssrfDetector        *ssrf.Detector
	lfiDetector         *lfi.Detector
	xxeDetector         *xxe.Detector
	techDetector        *techstack.Detector
	nosqlDetector       *nosql.Detector
	sstiDetector        *ssti.Detector
	idorDetector        *idor.Detector
	jwtDetector         *jwt.Detector
	redirectDetector    *redirect.Detector
	corsDetector        *cors.Detector
	crlfDetector        *crlf.Detector
	ldapDetector        *ldap.Detector
	xpathDetector       *xpath.Detector
	headerInjDetector   *headerinj.Detector
	cstiDetector        *csti.Detector
	rfiDetector         *rfi.Detector
	jndiDetector        *jndi.Detector
	secHeadersDetector  *secheaders.Detector
	exposureDetector    *exposure.Detector
	cloudDetector       *cloud.Detector
	subTakeoverDetector *subtakeover.Detector
	tlsAnalyzer         *tlsdetect.Analyzer
	authDetector        *auth.Detector
	graphqlDetector     *graphql.Detector
	smugglingDetector   *smuggling.Detector
	behaviorDetector    *behavior.Detector
	storageInjDetector  *storageinj.Detector
	logInjDetector      *loginj.Detector
	fileUploadDetector  *fileupload.Detector
	verbTamperDetector  *verbtamper.Detector
	pathNormDetector    *pathnorm.Detector
	raceCondDetector    *racecond.Detector
	csvInjDetector      *csvinj.Detector
	discoveryPipeline   *discovery.Pipeline
	headlessPool        *headless.Pool
	oobClient           *oob.Client
	oobReady            chan struct{} // signals when OOB client is ready
	oobInitErr          error         // error from OOB initialization
	techHint            *TechHint
	config              *InternalScanConfig
	confirmed           *confirmedFindings
	mu                  sync.Mutex
}

// InternalScanConfig configures the internal scanner behavior.
type InternalScanConfig struct {
	// Enable/disable specific checks
	EnableSQLi        bool
	EnableXSS         bool
	EnableCMDI        bool
	EnableSSRF        bool
	EnableLFI         bool
	EnableXXE         bool
	EnableTechScan    bool
	EnableOOB         bool
	EnableNoSQL       bool
	EnableSSTI        bool
	EnableIDOR        bool
	EnableJWT         bool
	EnableRedirect    bool
	EnableCORS        bool
	EnableCRLF        bool
	EnableLDAP        bool
	EnableXPath       bool
	EnableHeaderInj   bool
	EnableCSTI        bool
	EnableRFI         bool
	EnableJNDI        bool
	EnableSecHeaders  bool
	EnableExposure    bool
	EnableCloud       bool
	EnableSubTakeover bool
	EnableTLS         bool
	EnableAuth        bool
	EnableGraphQL     bool
	EnableSmuggling   bool
	EnableBehavior    bool
	EnableLogInj      bool
	EnableFileUpload  bool
	EnableVerbTamper  bool
	EnablePathNorm    bool
	EnableRaceCond    bool
	EnableCSVInj      bool

	// Template scanning
	EnableTemplates bool     // Enable template-based scanning (default false)
	TemplatePaths   []string // Paths to template files or directories
	TemplateTags    []string // Tags to filter templates by

	// Discovery and headless browser settings
	EnableDiscovery     bool   // Auto-discover injectable points (default true)
	EnableStorageInj    bool   // Test storage injection (default false, needs Chrome)
	HeadlessMaxBrowsers int    // Max browser contexts (default 3)
	ChromePath          string // Explicit Chrome binary path

	// Additional configuration for specific detectors
	Subdomains []subtakeover.SubdomainInfo // Subdomain list for takeover detection
	LoginURL   string                      // Login URL for auth testing

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
		EnableLDAP:          true,
		EnableXPath:         true,
		EnableHeaderInj:     true,
		EnableCSTI:          true,
		EnableRFI:           true,
		EnableJNDI:          true,
		EnableSecHeaders:    true,
		EnableExposure:      true,
		EnableCloud:         true,
		EnableSubTakeover:   false, // Requires subdomain list
		EnableTLS:           true,
		EnableAuth:          false, // Requires login URL
		EnableGraphQL:       true,
		EnableSmuggling:     true,
		EnableBehavior:      true,
		EnableLogInj:        true,
		EnableFileUpload:    true,
		EnableVerbTamper:    true,
		EnablePathNorm:      true,
		EnableRaceCond:      false, // Aggressive, sends many parallel requests
		EnableCSVInj:        true,
		EnableDiscovery:     true,
		EnableStorageInj:    false, // Requires Chrome
		HeadlessMaxBrowsers: 3,
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
		client:              httpClient,
		sqliDetector:        injection.NewSQLiDetector(),
		xssDetector:         xss.New(httpClient),
		cmdiDetector:        cmdi.New(httpClient),
		ssrfDetector:        ssrf.New(httpClient),
		lfiDetector:         lfi.New(httpClient),
		xxeDetector:         xxe.New(httpClient),
		techDetector:        techDetector,
		nosqlDetector:       nosql.New(httpClient),
		sstiDetector:        ssti.New(httpClient),
		idorDetector:        idor.New(httpClient),
		jwtDetector:         jwt.NewDetector(),
		redirectDetector:    redirect.New(httpClient),
		corsDetector:        cors.New(httpClient),
		crlfDetector:        crlf.New(httpClient),
		ldapDetector:        ldap.New(httpClient),
		xpathDetector:       xpath.New(httpClient),
		headerInjDetector:   headerinj.New(httpClient),
		cstiDetector:        csti.New(httpClient),
		rfiDetector:         rfi.New(httpClient),
		jndiDetector:        jndi.New(httpClient),
		secHeadersDetector:  secheaders.New(httpClient),
		exposureDetector:    exposure.New(httpClient),
		cloudDetector:       cloud.New(httpClient),
		subTakeoverDetector: subtakeover.New(httpClient),
		tlsAnalyzer:         tlsdetect.New(httpClient),
		authDetector:        auth.New(httpClient),
		graphqlDetector:     graphql.New(httpClient),
		smugglingDetector:   smuggling.NewDetector(),
		behaviorDetector:    behavior.New(httpClient),
		logInjDetector:      loginj.New(httpClient),
		fileUploadDetector:  fileupload.New(httpClient),
		verbTamperDetector:  verbtamper.New(httpClient),
		pathNormDetector:    pathnorm.New(httpClient),
		raceCondDetector:    racecond.New(httpClient),
		csvInjDetector:      csvinj.New(httpClient),
		config:              config,
		confirmed:           newConfirmedFindings(),
	}

	// Initialize discovery pipeline with all discoverers
	if config.EnableDiscovery {
		pipeline := discovery.NewPipeline(httpClient)
		pipeline.Register(discovery.NewFormDiscoverer())
		pipeline.Register(discovery.NewCookieDiscoverer())
		pipeline.Register(discovery.NewHeaderDiscoverer())
		pipeline.Register(discovery.NewJSONBodyDiscoverer())
		pipeline.Register(discovery.NewPathSegmentDiscoverer())
		pipeline.Register(discovery.NewJSStorageDiscoverer())
		pipeline.Register(discovery.NewXMLBodyDiscoverer())
		pipeline.Register(discovery.NewRobotsSitemapDiscoverer())
		pipeline.Register(discovery.NewHTMLCommentDiscoverer())
		pipeline.Register(discovery.NewJSRouteDiscoverer())
		pipeline.Register(discovery.NewMultipartDiscoverer())
		pipeline.Register(discovery.NewOpenAPIDiscoverer())
		pipeline.Register(discovery.NewGraphQLIntrospectionDiscoverer())
		scanner.discoveryPipeline = pipeline
	}

	// Initialize headless browser pool if storage injection is enabled
	if config.EnableStorageInj {
		maxBrowsers := config.HeadlessMaxBrowsers
		if maxBrowsers <= 0 {
			maxBrowsers = 3
		}
		poolConfig := headless.PoolConfig{
			MaxBrowsers:     maxBrowsers,
			NavigateTimeout: config.RequestTimeout,
			ExecPath:        config.ChromePath,
			Headless:        true,
		}
		pool, poolErr := headless.NewPool(poolConfig)
		if poolErr != nil {
			if config.Verbose {
				fmt.Printf("[!] Headless browser unavailable: %v (storage injection will be skipped)\n", poolErr)
			}
		} else {
			scanner.headlessPool = pool
			scanner.storageInjDetector = storageinj.New(pool).WithVerbose(config.Verbose)
		}
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
	if s.headlessPool != nil {
		s.headlessPool.Close()
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

		// Derive tech-aware hints for downstream detectors
		s.techHint = s.techAwareConfig(techResult)
	}

	// 2. Run discovery pipeline to auto-discover injectable points
	var discoveredParams []core.Parameter
	if s.config.EnableDiscovery && s.discoveryPipeline != nil {
		if s.config.Verbose {
			fmt.Printf("[*] Running auto-discovery pipeline...\n")
		}
		discoveryResult, discoveryErr := s.discoveryPipeline.Run(ctx, targetURL)
		if discoveryErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("discovery: %v", discoveryErr))
		} else if discoveryResult != nil {
			discoveredParams = discoveryResult.Parameters
			if s.config.Verbose {
				fmt.Printf("[+] Discovery found %d parameters from %d sources\n",
					len(discoveredParams), len(discoveryResult.Sources))
			}
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

	if len(params) == 0 {
		result.Errors = append(result.Errors, "no parameters found to test")
		if s.config.Verbose {
			fmt.Printf("[!] No parameters found to test\n")
		}
		return result, nil
	}

	// Extract parameter names for logging
	paramNames := make([]string, 0, len(params))
	for _, p := range params {
		paramNames = append(paramNames, p.Name+"("+p.Location+")")
	}

	if s.config.Verbose {
		fmt.Printf("[*] Testing %d parameters: %v\n", len(params), paramNames)
	}

	// 3. Test each parameter for vulnerabilities (SQLi and XSS first, then OOB)
	var wg sync.WaitGroup
	findingsChan := make(chan *core.Finding, 100)

	method := "GET"
	if scanConfig != nil && scanConfig.Method != "" {
		method = scanConfig.Method
	}

	// Classify parameters (detect reflection, set content type)
	ClassifyParameters(ctx, scanClient, targetURL, params, method)

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

	// Phase 1.5: URL-level tests (IDOR, CORS, StorageInj) - run once per URL, not per parameter
	s.runURLLevelTests(ctx, &wg, findingsChan, targetURL)

	// Wait for URL-level tests
	wg.Wait()

	// Phase 1.75: Template scanning (after URL-level tests, before OOB)
	if s.config.EnableTemplates && len(s.config.TemplatePaths) > 0 {
		proxyURL := ""
		if scanConfig != nil {
			proxyURL = scanConfig.ProxyURL
		}
		s.runTemplateTests(ctx, &wg, findingsChan, target, proxyURL)
		wg.Wait()
	}

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

// techAwareConfig adjusts scan configuration based on detected technologies.
// It enables/disables detectors and sets priority hints.
func (s *InternalScanner) techAwareConfig(techResult *techstack.DetectionResult) *TechHint {
	hint := &TechHint{
		Technologies: make([]string, 0),
	}

	if techResult == nil {
		return hint
	}

	for _, tech := range techResult.Technologies {
		normalized := strings.ToLower(tech.Name)
		hint.Technologies = append(hint.Technologies, normalized)
	}

	// Derive framework-specific hints from detected technologies
	templateEngines := map[string]string{
		"jinja2":     "jinja2",
		"twig":       "twig",
		"freemarker": "freemarker",
		"django":     "django",
		"erb":        "erb",
		"smarty":     "smarty",
	}

	for _, tech := range hint.Technologies {
		switch {
		case tech == "php":
			hint.LFIWrappers = true
		case tech == "java" || tech == "spring" || tech == "tomcat":
			hint.JavaDeser = true
		case tech == "node" || tech == "express" || tech == "next":
			hint.NodeProto = true
		}

		if engine, ok := templateEngines[tech]; ok && hint.TemplateEngine == "" {
			hint.TemplateEngine = engine
		}
	}

	return hint
}

// uuidPattern matches UUID-like strings in path segments.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// numericPattern matches purely numeric path segments.
var numericPattern = regexp.MustCompile(`^[0-9]+$`)

// extractParameters extracts testable parameters from the target URL.
// It returns query parameters and path segments that look like IDs.
func (s *InternalScanner) extractParameters(target *core.Target) []core.Parameter {
	return s.extractParametersWithConfig(target, nil)
}

// extractParametersWithConfig extracts testable parameters from the target URL
// and scan configuration. It identifies query params, cookie params, and
// path segments that look like IDs (numeric or UUID).
func (s *InternalScanner) extractParametersWithConfig(target *core.Target, scanConfig *Config) []core.Parameter {
	var params []core.Parameter
	seen := make(map[string]bool)

	// Parse URL to get query parameters
	parsedURL, err := url.Parse(target.URL())
	if err != nil {
		return params
	}

	// Extract query parameters
	for key, values := range parsedURL.Query() {
		seenKey := "query:" + key
		if !seen[seenKey] {
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			params = append(params, core.Parameter{
				Name:     key,
				Location: core.ParamLocationQuery,
				Value:    value,
				Type:     "string",
			})
			seen[seenKey] = true
		}
	}

	// Extract cookie parameters from config
	if scanConfig != nil && scanConfig.Cookies != "" {
		cookies := strings.Split(scanConfig.Cookies, ";")
		for _, cookie := range cookies {
			cookie = strings.TrimSpace(cookie)
			if cookie == "" {
				continue
			}
			parts := strings.SplitN(cookie, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			seenKey := "cookie:" + name
			if !seen[seenKey] {
				params = append(params, core.Parameter{
					Name:     name,
					Location: core.ParamLocationCookie,
					Value:    value,
					Type:     "string",
				})
				seen[seenKey] = true
			}
		}
	}

	// Extract path segments that look like IDs (numeric or UUID)
	pathSegments := strings.Split(parsedURL.Path, "/")
	segmentIdx := 0
	for _, seg := range pathSegments {
		if seg == "" {
			continue
		}
		if numericPattern.MatchString(seg) {
			seenKey := fmt.Sprintf("path:%d", segmentIdx)
			if !seen[seenKey] {
				params = append(params, core.Parameter{
					Name:     fmt.Sprintf("path_%d", segmentIdx),
					Location: core.ParamLocationPath,
					Value:    seg,
					Type:     "number",
				})
				seen[seenKey] = true
			}
		} else if uuidPattern.MatchString(seg) {
			seenKey := fmt.Sprintf("path:%d", segmentIdx)
			if !seen[seenKey] {
				params = append(params, core.Parameter{
					Name:     fmt.Sprintf("path_%d", segmentIdx),
					Location: core.ParamLocationPath,
					Value:    seg,
					Type:     "string",
				})
				seen[seenKey] = true
			}
		}
		segmentIdx++
	}

	return params
}

// runTemplateTests executes nuclei-compatible templates against a target.
// proxyURL, when non-empty, routes all template traffic through the given proxy.
func (s *InternalScanner) runTemplateTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, target *core.Target, proxyURL string) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		if s.config.Verbose {
			fmt.Printf("[*] Running template scanner...\n")
		}

		tsCfg := DefaultTemplateScanConfig()
		tsCfg.Verbose = s.config.Verbose
		tsCfg.ProxyURL = proxyURL

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
				fmt.Printf("[!] Template scanner creation failed: %v\n", err)
			}
			return
		}

		tsResult, err := ts.ScanWithLoad(ctx, target)
		if err != nil {
			if s.config.Verbose {
				fmt.Printf("[!] Template scan error: %v\n", err)
			}
			return
		}

		for _, f := range tsResult.Findings {
			findingsChan <- f
		}

		if s.config.Verbose {
			fmt.Printf("[+] Template scanner completed: %d findings from %d/%d templates\n",
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
			for _, f := range findings {
				findingsChan <- f
			}
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

	if s.config.EnableJNDI {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testJNDI(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableSecHeaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testSecHeaders(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableExposure {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testExposure(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableCloud {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testCloud(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableSubTakeover && len(s.config.Subdomains) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testSubTakeover(ctx) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testTLS(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableAuth && s.config.LoginURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testAuth(ctx, s.config.LoginURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableGraphQL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testGraphQL(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableSmuggling {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testSmuggling(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableStorageInj && s.storageInjDetector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testStorageInj(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableLogInj {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testLogInj(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableFileUpload {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testFileUpload(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableVerbTamper {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testVerbTamper(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnablePathNorm {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testPathNorm(ctx, targetURL) {
				findingsChan <- f
			}
		}()
	}

	if s.config.EnableRaceCond {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range s.testRaceCond(ctx, targetURL) {
				findingsChan <- f
			}
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
			fmt.Printf("[*] Running OOB tests...\n")
		}
		for _, param := range params {
			wg.Add(1)
			go func(p core.Parameter) {
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
