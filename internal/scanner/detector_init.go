package scanner

import (
	"fmt"
	nethttp "net/http"
	"os"

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
	"github.com/TyrusRC/assay/internal/payloads/arginject"
	"github.com/TyrusRC/assay/internal/payloads/esi"
	"github.com/TyrusRC/assay/internal/payloads/fileops"
	"github.com/TyrusRC/assay/internal/payloads/javareflect"
	"github.com/TyrusRC/assay/internal/payloads/nodejsinject"
	"github.com/TyrusRC/assay/internal/payloads/phpinject"
	"github.com/TyrusRC/assay/internal/payloads/solrinject"
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

// initDetectors instantiates every per-target detector and attaches it to
// s. Called once during NewInternalScanner. Detectors with target-scoped
// constructors (http2advanced, http2desync, h2reset) get a placeholder
// here and are lazily replaced per scan in their test* helpers.
func (s *InternalScanner) initDetectors(httpClient *http.Client, config *InternalScanConfig, techDetector *techstack.Detector) {
	s.client = httpClient
	s.sqliDetector = injection.NewSQLiDetector()
	s.xssDetector = xss.New(httpClient)
	s.cmdiDetector = cmdi.New(httpClient)
	s.ssrfDetector = ssrf.New(httpClient)
	s.lfiDetector = lfi.New(httpClient)
	s.xxeDetector = xxe.New(httpClient)
	s.techDetector = techDetector
	s.nosqlDetector = nosql.New(httpClient)
	s.sstiDetector = ssti.New(httpClient)
	s.idorDetector = idor.New(httpClient)
	s.jwtDetector = jwt.NewDetector()
	s.redirectDetector = redirect.New(httpClient)
	s.corsDetector = cors.New(httpClient)
	s.crlfDetector = crlf.New(httpClient)
	s.ldapDetector = ldap.New(httpClient)
	s.xpathDetector = xpath.New(httpClient)
	s.headerInjDetector = headerinj.New(httpClient)
	s.cstiDetector = csti.New(httpClient)
	s.rfiDetector = rfi.New(httpClient)
	s.jndiDetector = jndi.New(httpClient)
	s.secHeadersDetector = secheaders.New(httpClient)
	s.exposureDetector = exposure.New(httpClient)
	s.cloudDetector = cloud.New(httpClient)
	s.subTakeoverDetector = subtakeover.New(httpClient)
	s.tlsAnalyzer = tlsdetect.New(httpClient)
	s.authDetector = auth.New(httpClient)
	s.graphqlDetector = graphql.New(httpClient)
	s.smugglingDetector = smuggling.NewDetector()
	s.behaviorDetector = behavior.New(httpClient)
	s.logInjDetector = loginj.New(httpClient)
	s.fileUploadDetector = fileupload.New(httpClient)
	s.verbTamperDetector = verbtamper.New(httpClient)
	s.pathNormDetector = pathnorm.New(httpClient)
	s.raceCondDetector = racecond.New(httpClient)
	s.csvInjDetector = csvinj.New(httpClient)
	s.wsDetector = ws.New(httpClient)
	s.hostHdrDetector = hosthdr.New(httpClient)
	s.oauthDetector = oauth.New(httpClient)
	s.jsdepDetector = jsdep.New(httpClient, config.NVDAPIKey)
	s.dataExposureDetector = dataexposure.New(httpClient)
	s.adminPathDetector = adminpath.New(httpClient)
	s.apiVersionDetector = apiversion.New(httpClient)
	s.rateLimitDetector = ratelimit.New(httpClient)
	s.apiSpecRunner = apispec.NewRunner(httpClient)
	s.contentTypeDetector = contenttype.New(httpClient)
	s.sseDetector = sse.New(httpClient)
	s.grpcReflectDetector = grpcreflect.New(httpClient)
	s.h2ResetDetector = h2reset.New()
	s.csrfDetector = csrf.New(httpClient)
	s.tabnabbingDetector = tabnabbing.New(httpClient)
	s.redosDetector = redos.New(httpClient)
	s.promptInjDetector = promptinjection.New(httpClient)
	s.xsltDetector = xslt.New(httpClient)
	s.samlInjDetector = samlinj.New(httpClient)
	s.ormLeakDetector = ormleak.New(httpClient)
	s.typeJugglingDetector = typejuggling.New(httpClient)
	s.depConfusionDetector = depconfusion.New(httpClient)
	s.tokenEntropyDetector = tokenentropy.New(httpClient)
	s.cacheDeceptionDetector = cachedeception.New(httpClient)
	s.cachePoisoningDetector = cachepoisoning.New(httpClient)
	s.cssInjDetector = cssinj.New(httpClient)
	s.deserDetector = deser.New(httpClient)
	s.domClobberDetector = domclobber.New(httpClient)
	s.emailInjDetector = emailinj.New(httpClient)
	s.hppDetector = hpp.New(httpClient)
	s.htmlInjDetector = htmlinj.New(httpClient)
	s.massAssignDetector = massassign.New(httpClient)
	s.protoPollutionDetector = protopollution.New(httpClient)
	s.secondOrderDetector = secondorder.New(httpClient)
	s.ssiDetector = ssi.New(httpClient)
	s.storageDetector = storage.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.passwordResetDetector = passwordreset.New(httpClient)
	s.sessionLifecycleDetector = sessionlifecycle.New(httpClient)
	s.oauthFlowDetector = oauthflow.New(httpClient)
	s.dnsRebindingDetector = dnsrebinding.New(httpClient)
	s.openAPISemanticDetector = openapisemantic.New(httpClient)
	// http2AdvancedDetector is target-scoped; lazily replaced per scan in
	// testHTTP2Advanced because http2advanced.New takes a target string,
	// not an *http.Client.
	s.http2AdvancedDetector = http2advanced.New("")
	s.sessionFixationDetector = sessionfixation.New(httpClient)
	s.stackTraceDetector = stacktrace.New(httpClient)
	s.mfaBypassDetector = mfabypass.New(httpClient)
	s.paddingOracleDetector = paddingoracle.New(httpClient)
	s.xsleaksDetector = xsleaks.New(httpClient)
	s.jwtAdvancedDetector = jwtadvanced.New(httpClient)
	s.graphqlAdvancedDetector = graphqladvanced.New(httpClient)
	s.http2DesyncDetector = http2desync.New()
	s.cachekeyDetector = cachekey.New(httpClient)
	s.authBypass403Detector = authbypass403.New(httpClient)
	s.http2RaceDetector = http2race.New(httpClient)
	s.graphqlDosDetector = graphqldos.New(httpClient)
	s.jkuAbuseDetector = jkuabuse.New(httpClient)
	s.sameSiteLaxDetector = samesitelax.New(httpClient)
	s.wafDetector = wafdetect.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.xfsDetector = xfs.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.iisTildeDetector = iistilde.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.sameSiteScriptDetector = samesitescript.New()
	s.longPwdDetector = longpwd.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.vhostDetector = vhost.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.esiDetector = esi.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.solrInjectDetector = solrinject.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.phpInjectDetector = phpinject.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.javaReflectDetector = javareflect.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.nodejsInjectDetector = nodejsinject.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.argInjectDetector = arginject.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.fileOpsDetector = fileops.New(&nethttp.Client{Timeout: config.RequestTimeout})
	s.config = config
	s.confirmed = newConfirmedFindings()
}

// initDiscovery wires the discovery pipeline with every concrete
// discoverer. Called from NewInternalScanner when config.EnableDiscovery
// is true.
func (s *InternalScanner) initDiscovery(httpClient *http.Client) {
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
	s.discoveryPipeline = pipeline
}

// initHeadless brings up a shared headless-browser pool whenever any
// DOM-aware detector is enabled. Failures are logged (when verbose) and
// the relevant detectors stay nil; the runner skips them at launch time.
func (s *InternalScanner) initHeadless(config *InternalScanConfig) {
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
		return
	}
	s.headlessPool = pool
	if config.EnableStorageInj {
		s.storageInjDetector = storageinj.New(pool).WithVerbose(config.Verbose)
	}
	if config.EnablePostMsg {
		s.postMsgDetector = postmsg.New(pool).WithVerbose(config.Verbose)
	}
}

// needsHeadless reports whether any DOM-aware detector requires a
// shared headless browser pool.
func (c *InternalScanConfig) needsHeadless() bool {
	return c.EnableStorageInj || c.EnableDOMXSS ||
		c.EnableProtoPoll || c.EnableDOMRedirect ||
		c.EnablePostMsg
}
