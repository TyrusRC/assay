package scanner

import (
	"fmt"
	nethttp "net/http"
	"os"
	"sync"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/auth"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/behavior"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cachedeception"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cachepoisoning"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cloud"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cmdi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cors"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/crlf"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cssinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/csti"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/csvinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/deser"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/domclobber"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/emailinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/exposure"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/fileupload"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/graphql"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/headerinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/hosthdr"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/hpp"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/htmlinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/adminpath"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/apispec"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/apiversion"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/contenttype"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/csrf"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/depconfusion"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/grpcreflect"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/h2reset"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ormleak"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/promptinjection"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/redos"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/samlinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/sse"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/tabnabbing"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/tokenentropy"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/typejuggling"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xslt"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/dataexposure"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/idor"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/injection"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/jndi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/jsdep"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ratelimit"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/jwt"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ldap"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/lfi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/loginj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/massassign"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/nosql"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/oauth"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/oob"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/pathnorm"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/postmsg"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/protopollution"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/racecond"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/redirect"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/rfi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/secheaders"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/secondorder"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/smuggling"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ssi"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ssrf"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ssti"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/storage"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/storageinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/subtakeover"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/techstack"
	tlsdetect "github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/tls"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/verbtamper"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ws"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xpath"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xss"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/xxe"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/discovery"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
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
	wsDetector          *ws.Detector
	hostHdrDetector     *hosthdr.Detector
	oauthDetector       *oauth.Detector
	jsdepDetector       *jsdep.Detector
	dataExposureDetector *dataexposure.Detector
	adminPathDetector   *adminpath.Detector
	apiVersionDetector  *apiversion.Detector
	rateLimitDetector   *ratelimit.Detector
	apiSpecRunner       *apispec.Runner
	contentTypeDetector *contenttype.Detector
	sseDetector         *sse.Detector
	grpcReflectDetector *grpcreflect.Detector
	h2ResetDetector     *h2reset.Detector
	csrfDetector        *csrf.Detector
	tabnabbingDetector  *tabnabbing.Detector
	redosDetector       *redos.Detector
	promptInjDetector   *promptinjection.Detector
	xsltDetector        *xslt.Detector
	samlInjDetector     *samlinj.Detector
	ormLeakDetector     *ormleak.Detector
	typeJugglingDetector *typejuggling.Detector
	depConfusionDetector *depconfusion.Detector
	tokenEntropyDetector *tokenentropy.Detector
	cacheDeceptionDetector  *cachedeception.Detector
	cachePoisoningDetector  *cachepoisoning.Detector
	cssInjDetector          *cssinj.Detector
	deserDetector           *deser.Detector
	domClobberDetector      *domclobber.Detector
	emailInjDetector        *emailinj.Detector
	hppDetector             *hpp.Detector
	htmlInjDetector         *htmlinj.Detector
	massAssignDetector      *massassign.Detector
	protoPollutionDetector  *protopollution.Detector
	secondOrderDetector     *secondorder.Detector
	ssiDetector             *ssi.Detector
	storageDetector         *storage.Detector
	postMsgDetector         *postmsg.Detector
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
		fmt.Fprintf(os.Stderr, "[!] Tech stack detection unavailable: %v\n", techErr)
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
		wsDetector:          ws.New(httpClient),
		hostHdrDetector:     hosthdr.New(httpClient),
		oauthDetector:       oauth.New(httpClient),
		jsdepDetector:        jsdep.New(httpClient, config.NVDAPIKey),
		dataExposureDetector: dataexposure.New(httpClient),
		adminPathDetector:    adminpath.New(httpClient),
		apiVersionDetector:   apiversion.New(httpClient),
		rateLimitDetector:    ratelimit.New(httpClient),
		apiSpecRunner:        apispec.NewRunner(httpClient),
		contentTypeDetector:  contenttype.New(httpClient),
		sseDetector:          sse.New(httpClient),
		grpcReflectDetector:  grpcreflect.New(httpClient),
		h2ResetDetector:      h2reset.New(),
		csrfDetector:         csrf.New(httpClient),
		tabnabbingDetector:   tabnabbing.New(httpClient),
		redosDetector:        redos.New(httpClient),
		promptInjDetector:    promptinjection.New(httpClient),
		xsltDetector:         xslt.New(httpClient),
		samlInjDetector:      samlinj.New(httpClient),
		ormLeakDetector:      ormleak.New(httpClient),
		typeJugglingDetector: typejuggling.New(httpClient),
		depConfusionDetector: depconfusion.New(httpClient),
		tokenEntropyDetector: tokenentropy.New(httpClient),
		cacheDeceptionDetector: cachedeception.New(httpClient),
		cachePoisoningDetector: cachepoisoning.New(httpClient),
		cssInjDetector:         cssinj.New(httpClient),
		deserDetector:          deser.New(httpClient),
		domClobberDetector:     domclobber.New(httpClient),
		emailInjDetector:       emailinj.New(httpClient),
		hppDetector:            hpp.New(httpClient),
		htmlInjDetector:        htmlinj.New(httpClient),
		massAssignDetector:     massassign.New(httpClient),
		protoPollutionDetector: protopollution.New(httpClient),
		secondOrderDetector:    secondorder.New(httpClient),
		ssiDetector:            ssi.New(httpClient),
		storageDetector:        storage.New(&nethttp.Client{Timeout: config.RequestTimeout}),
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

	// Initialize headless browser pool if any DOM-aware detector is enabled.
	// Storage injection, DOM XSS, prototype pollution, and DOM-based open
	// redirect all need a real browser; we share one pool across them.
	needHeadless := config.EnableStorageInj || config.EnableDOMXSS ||
		config.EnableProtoPoll || config.EnableDOMRedirect ||
		config.EnablePostMsg
	if needHeadless {
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
				fmt.Fprintf(os.Stderr, "[!] Headless browser unavailable: %v (DOM-aware detectors will be skipped)\n", poolErr)
			}
		} else {
			scanner.headlessPool = pool
			if config.EnableStorageInj {
				scanner.storageInjDetector = storageinj.New(pool).WithVerbose(config.Verbose)
			}
			if config.EnablePostMsg {
				scanner.postMsgDetector = postmsg.New(pool).WithVerbose(config.Verbose)
			}
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
				fmt.Fprintf(os.Stderr, "[!] OOB testing unavailable: %v\n", err)
			}
		} else {
			s.oobClient = oobClient
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[+] OOB testing enabled with URL: %s\n", oobClient.GetURL())
			}
		}
	}()
}

// waitForOOBClient waits for OOB client to be ready with a timeout.
// Returns true if OOB client is available, false otherwise.
func (s *InternalScanner) waitForOOBClient(timeout time.Duration) bool {
	s.mu.Lock()
	oobReady := s.oobReady
	s.mu.Unlock()
	if oobReady == nil {
		return false
	}

	select {
	case <-oobReady:
		s.mu.Lock()
		available := s.oobClient != nil
		s.mu.Unlock()
		return available
	case <-time.After(timeout):
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] OOB initialization timeout after %v\n", timeout)
		}
		return false
	}
}

// Close releases resources. Safe to call multiple times.
func (s *InternalScanner) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.oobClient != nil {
		s.oobClient.Close()
		s.oobClient = nil
	}
	if s.headlessPool != nil {
		s.headlessPool.Close()
		s.headlessPool = nil
	}
}

// InternalScanResult contains results from internal scanning.
type InternalScanResult struct {
	Findings     core.Findings
	Technologies *techstack.DetectionResult
	Errors       []string
}

// applyScanConfig writes per-scan settings (proxy, headers, cookies, UA,
// insecure) onto the shared http.Client used by every detector. Without
// this, only a handful of detectors that took an explicit *http.Client
// argument (SQLi, ClassifyParameters, OOB) saw the user's --proxy / -H /
// --user-agent flags — the rest silently bypassed Burp Suite and
// authentication.
func applyScanConfig(client *http.Client, cfg *Config) {
	if client == nil || cfg == nil {
		return
	}
	if len(cfg.Headers) > 0 {
		client.WithHeaders(cfg.Headers)
	}
	if cfg.Cookies != "" {
		client.WithCookies(cfg.Cookies)
	}
	if cfg.UserAgent != "" {
		client.WithUserAgent(cfg.UserAgent)
	}
	if cfg.ProxyURL != "" {
		client.WithProxy(cfg.ProxyURL)
	}
	if cfg.Insecure {
		client.WithInsecure(true)
	}
}
