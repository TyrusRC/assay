package scanner

import (
	"fmt"
	"os"
	"sync"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/adminpath"
	"github.com/TyrusRC/assay/internal/detection/apispec"
	"github.com/TyrusRC/assay/internal/detection/apiversion"
	"github.com/TyrusRC/assay/internal/detection/auth"
	"github.com/TyrusRC/assay/internal/detection/authbypass403"
	"github.com/TyrusRC/assay/internal/detection/behavior"
	"github.com/TyrusRC/assay/internal/detection/cachedeception"
	"github.com/TyrusRC/assay/internal/detection/cachekey"
	"github.com/TyrusRC/assay/internal/detection/cachepoisoning"
	"github.com/TyrusRC/assay/internal/detection/cloud"
	"github.com/TyrusRC/assay/internal/detection/cmdi"
	"github.com/TyrusRC/assay/internal/detection/contenttype"
	"github.com/TyrusRC/assay/internal/detection/cors"
	"github.com/TyrusRC/assay/internal/detection/crlf"
	"github.com/TyrusRC/assay/internal/detection/csrf"
	"github.com/TyrusRC/assay/internal/detection/cssinj"
	"github.com/TyrusRC/assay/internal/detection/csti"
	"github.com/TyrusRC/assay/internal/detection/csvinj"
	"github.com/TyrusRC/assay/internal/detection/dataexposure"
	"github.com/TyrusRC/assay/internal/detection/depconfusion"
	"github.com/TyrusRC/assay/internal/detection/deser"
	"github.com/TyrusRC/assay/internal/detection/dnsrebinding"
	"github.com/TyrusRC/assay/internal/detection/domclobber"
	"github.com/TyrusRC/assay/internal/detection/emailinj"
	"github.com/TyrusRC/assay/internal/detection/exposure"
	"github.com/TyrusRC/assay/internal/detection/fileupload"
	"github.com/TyrusRC/assay/internal/detection/graphql"
	"github.com/TyrusRC/assay/internal/detection/graphqladvanced"
	"github.com/TyrusRC/assay/internal/detection/graphqldos"
	"github.com/TyrusRC/assay/internal/detection/grpcreflect"
	"github.com/TyrusRC/assay/internal/detection/h2reset"
	"github.com/TyrusRC/assay/internal/detection/headerinj"
	"github.com/TyrusRC/assay/internal/detection/hosthdr"
	"github.com/TyrusRC/assay/internal/detection/hpp"
	"github.com/TyrusRC/assay/internal/detection/htmlinj"
	"github.com/TyrusRC/assay/internal/detection/http2advanced"
	"github.com/TyrusRC/assay/internal/detection/http2desync"
	"github.com/TyrusRC/assay/internal/detection/http2race"
	"github.com/TyrusRC/assay/internal/detection/idor"
	"github.com/TyrusRC/assay/internal/detection/injection"
	"github.com/TyrusRC/assay/internal/detection/jkuabuse"
	"github.com/TyrusRC/assay/internal/detection/jndi"
	"github.com/TyrusRC/assay/internal/detection/jsdep"
	"github.com/TyrusRC/assay/internal/detection/jwt"
	"github.com/TyrusRC/assay/internal/detection/jwtadvanced"
	"github.com/TyrusRC/assay/internal/detection/ldap"
	"github.com/TyrusRC/assay/internal/detection/lfi"
	"github.com/TyrusRC/assay/internal/detection/loginj"
	"github.com/TyrusRC/assay/internal/detection/massassign"
	"github.com/TyrusRC/assay/internal/detection/mfabypass"
	"github.com/TyrusRC/assay/internal/detection/nosql"
	"github.com/TyrusRC/assay/internal/detection/oauth"
	"github.com/TyrusRC/assay/internal/detection/oauthflow"
	"github.com/TyrusRC/assay/internal/detection/oob"
	"github.com/TyrusRC/assay/internal/detection/openapisemantic"
	"github.com/TyrusRC/assay/internal/detection/ormleak"
	"github.com/TyrusRC/assay/internal/detection/paddingoracle"
	"github.com/TyrusRC/assay/internal/detection/passwordreset"
	"github.com/TyrusRC/assay/internal/detection/pathnorm"
	"github.com/TyrusRC/assay/internal/detection/postmsg"
	"github.com/TyrusRC/assay/internal/detection/promptinjection"
	"github.com/TyrusRC/assay/internal/detection/protopollution"
	"github.com/TyrusRC/assay/internal/detection/racecond"
	"github.com/TyrusRC/assay/internal/detection/ratelimit"
	"github.com/TyrusRC/assay/internal/detection/redirect"
	"github.com/TyrusRC/assay/internal/detection/redos"
	"github.com/TyrusRC/assay/internal/detection/rfi"
	"github.com/TyrusRC/assay/internal/detection/samesitelax"
	"github.com/TyrusRC/assay/internal/detection/iistilde"
	"github.com/TyrusRC/assay/internal/detection/longpwd"
	"github.com/TyrusRC/assay/internal/detection/samesitescript"
	"github.com/TyrusRC/assay/internal/detection/wafdetect"
	"github.com/TyrusRC/assay/internal/detection/xfs"
	"github.com/TyrusRC/assay/internal/payloads/esi"
	"github.com/TyrusRC/assay/internal/payloads/vhost"
	"github.com/TyrusRC/assay/internal/detection/samlinj"
	"github.com/TyrusRC/assay/internal/detection/secheaders"
	"github.com/TyrusRC/assay/internal/detection/secondorder"
	"github.com/TyrusRC/assay/internal/detection/sessionfixation"
	"github.com/TyrusRC/assay/internal/detection/sessionlifecycle"
	"github.com/TyrusRC/assay/internal/detection/smuggling"
	"github.com/TyrusRC/assay/internal/detection/sse"
	"github.com/TyrusRC/assay/internal/detection/ssi"
	"github.com/TyrusRC/assay/internal/detection/ssrf"
	"github.com/TyrusRC/assay/internal/detection/ssti"
	"github.com/TyrusRC/assay/internal/detection/stacktrace"
	"github.com/TyrusRC/assay/internal/detection/storage"
	"github.com/TyrusRC/assay/internal/detection/storageinj"
	"github.com/TyrusRC/assay/internal/detection/subtakeover"
	"github.com/TyrusRC/assay/internal/detection/tabnabbing"
	"github.com/TyrusRC/assay/internal/detection/techstack"
	tlsdetect "github.com/TyrusRC/assay/internal/detection/tls"
	"github.com/TyrusRC/assay/internal/detection/tokenentropy"
	"github.com/TyrusRC/assay/internal/detection/typejuggling"
	"github.com/TyrusRC/assay/internal/detection/verbtamper"
	"github.com/TyrusRC/assay/internal/detection/ws"
	"github.com/TyrusRC/assay/internal/detection/xpath"
	"github.com/TyrusRC/assay/internal/detection/xsleaks"
	"github.com/TyrusRC/assay/internal/detection/xslt"
	"github.com/TyrusRC/assay/internal/detection/xss"
	"github.com/TyrusRC/assay/internal/detection/xxe"
	"github.com/TyrusRC/assay/internal/discovery"
	"github.com/TyrusRC/assay/internal/headless"
	"github.com/TyrusRC/assay/internal/http"
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
	client                 *http.Client
	sqliDetector           *injection.SQLiDetector
	xssDetector            *xss.Detector
	cmdiDetector           *cmdi.Detector
	ssrfDetector           *ssrf.Detector
	lfiDetector            *lfi.Detector
	xxeDetector            *xxe.Detector
	techDetector           *techstack.Detector
	nosqlDetector          *nosql.Detector
	sstiDetector           *ssti.Detector
	idorDetector           *idor.Detector
	jwtDetector            *jwt.Detector
	redirectDetector       *redirect.Detector
	corsDetector           *cors.Detector
	crlfDetector           *crlf.Detector
	ldapDetector           *ldap.Detector
	xpathDetector          *xpath.Detector
	headerInjDetector      *headerinj.Detector
	cstiDetector           *csti.Detector
	rfiDetector            *rfi.Detector
	jndiDetector           *jndi.Detector
	secHeadersDetector     *secheaders.Detector
	exposureDetector       *exposure.Detector
	cloudDetector          *cloud.Detector
	subTakeoverDetector    *subtakeover.Detector
	tlsAnalyzer            *tlsdetect.Analyzer
	authDetector           *auth.Detector
	graphqlDetector        *graphql.Detector
	smugglingDetector      *smuggling.Detector
	behaviorDetector       *behavior.Detector
	storageInjDetector     *storageinj.Detector
	logInjDetector         *loginj.Detector
	fileUploadDetector     *fileupload.Detector
	verbTamperDetector     *verbtamper.Detector
	pathNormDetector       *pathnorm.Detector
	raceCondDetector       *racecond.Detector
	csvInjDetector         *csvinj.Detector
	wsDetector             *ws.Detector
	hostHdrDetector        *hosthdr.Detector
	oauthDetector          *oauth.Detector
	jsdepDetector          *jsdep.Detector
	dataExposureDetector   *dataexposure.Detector
	adminPathDetector      *adminpath.Detector
	apiVersionDetector     *apiversion.Detector
	rateLimitDetector      *ratelimit.Detector
	apiSpecRunner          *apispec.Runner
	contentTypeDetector    *contenttype.Detector
	sseDetector            *sse.Detector
	grpcReflectDetector    *grpcreflect.Detector
	h2ResetDetector        *h2reset.Detector
	csrfDetector           *csrf.Detector
	tabnabbingDetector     *tabnabbing.Detector
	redosDetector          *redos.Detector
	promptInjDetector      *promptinjection.Detector
	xsltDetector           *xslt.Detector
	samlInjDetector        *samlinj.Detector
	ormLeakDetector        *ormleak.Detector
	typeJugglingDetector   *typejuggling.Detector
	depConfusionDetector   *depconfusion.Detector
	tokenEntropyDetector   *tokenentropy.Detector
	cacheDeceptionDetector *cachedeception.Detector
	cachePoisoningDetector *cachepoisoning.Detector
	cssInjDetector         *cssinj.Detector
	deserDetector          *deser.Detector
	domClobberDetector     *domclobber.Detector
	emailInjDetector       *emailinj.Detector
	hppDetector            *hpp.Detector
	htmlInjDetector        *htmlinj.Detector
	massAssignDetector     *massassign.Detector
	protoPollutionDetector *protopollution.Detector
	secondOrderDetector    *secondorder.Detector
	ssiDetector            *ssi.Detector
	storageDetector        *storage.Detector
	postMsgDetector        *postmsg.Detector
	// Wave-G — stateful auth flow detectors (default-on but URL-gated)
	passwordResetDetector    *passwordreset.Detector
	sessionLifecycleDetector *sessionlifecycle.Detector
	oauthFlowDetector        *oauthflow.Detector
	dnsRebindingDetector     *dnsrebinding.Detector
	openAPISemanticDetector  *openapisemantic.Detector
	http2AdvancedDetector    *http2advanced.Detector
	// Wave-H — coverage gaps from OWASP API/Top10/WSTG mapping audit
	sessionFixationDetector *sessionfixation.Detector
	stackTraceDetector      *stacktrace.Detector
	mfaBypassDetector       *mfabypass.Detector
	paddingOracleDetector   *paddingoracle.Detector
	xsleaksDetector         *xsleaks.Detector
	jwtAdvancedDetector     *jwtadvanced.Detector
	graphqlAdvancedDetector *graphqladvanced.Detector
	http2DesyncDetector     *http2desync.Detector
	cachekeyDetector        *cachekey.Detector
	authBypass403Detector   *authbypass403.Detector
	http2RaceDetector       *http2race.Detector
	graphqlDosDetector      *graphqldos.Detector
	jkuAbuseDetector        *jkuabuse.Detector
	sameSiteLaxDetector     *samesitelax.Detector
	wafDetector             *wafdetect.Detector
	xfsDetector             *xfs.Detector
	iisTildeDetector        *iistilde.Detector
	sameSiteScriptDetector  *samesitescript.Detector
	longPwdDetector         *longpwd.Detector
	vhostDetector           *vhost.Detector
	esiDetector             *esi.Detector
	discoveryPipeline       *discovery.Pipeline
	headlessPool            *headless.Pool
	oobClient               *oob.Client
	oobReady                chan struct{} // signals when OOB client is ready
	oobInitErr              error         // error from OOB initialization
	techHint                *TechHint
	config                  *InternalScanConfig
	confirmed               *confirmedFindings
	mu                      sync.Mutex
}

// NewInternalScanner creates a new internal scanner. The constructor
// instantiates every detector eagerly and brings up the discovery
// pipeline / headless pool when their feature flags request them. OOB
// initialization is deferred to scan time (startOOBClientAsync) so the
// constructor never blocks on network.
func NewInternalScanner(config *InternalScanConfig) (*InternalScanner, error) {
	if config == nil {
		config = DefaultInternalConfig()
	}

	httpClient := http.NewClient().WithTimeout(config.RequestTimeout)

	techDetector, techErr := techstack.NewDetector()
	if techErr != nil && config.Verbose {
		fmt.Fprintf(os.Stderr, "[!] Tech stack detection unavailable: %v\n", techErr)
	}

	scanner := &InternalScanner{}
	scanner.initDetectors(httpClient, config, techDetector)

	if config.EnableDiscovery {
		scanner.initDiscovery(httpClient)
	}
	if config.needsHeadless() {
		scanner.initHeadless(config)
	}
	// OOB client will be initialized lazily during scan if needed
	// (startOOBClientAsync); this prevents blocking scanner creation.
	return scanner, nil
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
