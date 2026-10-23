package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// urlTestTimeout caps any single URL-level detector. Headless-browser
// probes on API-only targets (no HTML to render) can block indefinitely;
// this ensures the scan always finishes and writes results.
const urlTestTimeout = 60 * time.Second

// launchIf is sugar around InternalScanner.launch that gates on a
// boolean before scheduling, so the URL-level orchestrator stays one
// line per detector instead of seven.
func (s *InternalScanner) launchIf(wg *sync.WaitGroup, cond bool, fn func()) {
	if !cond {
		return
	}
	s.launch(wg, fn)
}

// launchIfTimed is launchIf with a per-detector timeout. The detector
// receives a child context that is cancelled after urlTestTimeout so
// headless-browser probes on API-only targets cannot stall the scan.
func (s *InternalScanner) launchIfTimed(ctx context.Context, wg *sync.WaitGroup, cond bool, fn func(context.Context)) {
	if !cond {
		return
	}
	s.launch(wg, func() {
		tctx, cancel := context.WithTimeout(ctx, urlTestTimeout)
		defer cancel()
		fn(tctx)
	})
}

// runURLLevelTests launches goroutines for URL-level tests (IDOR, CORS, and friends).
// Each enabled detector runs in its own goroutine to maximize parallelism — they all
// hit a shared findingsChan that the caller drains.
//
// Split into category methods purely for readability: the orchestration
// semantics are identical to the previous monolithic body.
func (s *InternalScanner) runURLLevelTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string, scanCfg *Config) {
	s.launchURLClassic(ctx, wg, findingsChan, targetURL)
	s.launchURLAccess(ctx, wg, findingsChan, targetURL)
	s.launchURLNetwork(ctx, wg, findingsChan, targetURL)
	s.launchURLDOM(ctx, wg, findingsChan, targetURL)
	s.launchURLAPI(ctx, wg, findingsChan, targetURL)
	s.launchURLModern(ctx, wg, findingsChan, targetURL, scanCfg)
	s.launchURLAuthFlow(ctx, wg, findingsChan, targetURL)
}

// launchURLAuthFlow dispatches the Wave-G stateful-auth probes. Each one is
// gated on both its enable flag AND the presence of the URL it needs — an
// OAuth-flow probe with no AuthzURL can't do anything useful, so silently
// drop it rather than burn a goroutine on a no-op.
func (s *InternalScanner) launchURLAuthFlow(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIf(wg, c.EnableTimingEnum && c.LoginURL != "",
		func() { emit(ctx, findingsChan, s.testTimingEnum(ctx, c.LoginURL)) })
	s.launchIf(wg, c.EnableLongPwdDoS && c.LoginURL != "",
		func() { emit(ctx, findingsChan, s.testLongPwdDoS(ctx, c.LoginURL)) })
	s.launchIf(wg, c.EnablePasswordReset && c.PasswordResetURL != "",
		func() { emit(ctx, findingsChan, s.testPasswordReset(ctx, c.PasswordResetURL)) })
	s.launchIf(wg, c.EnableSessionLifecycle && c.LoginURL != "" && c.ProtectedURL != "",
		func() { emit(ctx, findingsChan, s.testSessionLifecycle(ctx)) })
	s.launchIf(wg, c.EnableOAuthFlow && c.OAuthAuthzURL != "",
		func() { emit(ctx, findingsChan, s.testOAuthFlow(ctx)) })
	s.launchIf(wg, c.EnableDNSRebinding,
		func() { emit(ctx, findingsChan, s.testDNSRebinding(ctx, targetURL)) })
	s.launchIf(wg, c.EnableOpenAPISemantic && c.APISpecURL != "",
		func() { emit(ctx, findingsChan, s.testOpenAPISemantic(ctx)) })
	s.launchIf(wg, c.EnableHTTP2Advanced,
		func() { emit(ctx, findingsChan, s.testHTTP2Advanced(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSessionFixation && c.LoginURL != "" && c.ProtectedURL != "",
		func() { emit(ctx, findingsChan, s.testSessionFixation(ctx)) })
	s.launchIf(wg, c.EnableStackTrace,
		func() { emit(ctx, findingsChan, s.testStackTrace(ctx, targetURL)) })
	s.launchIf(wg, c.EnableMFABypass && c.MFASubmitURL != "" && c.ProtectedURL != "",
		func() { emit(ctx, findingsChan, s.testMFABypass(ctx)) })
	s.launchIf(wg, c.EnablePaddingOracle && c.PaddingOracleToken != "" && c.PaddingOracleParam != "",
		func() { emit(ctx, findingsChan, s.testPaddingOracle(ctx, targetURL)) })
	// WSTG gap-fill detectors
	s.launchIf(wg, c.EnableSessTimeout,
		func() { emit(ctx, findingsChan, s.testSessTimeout(ctx, targetURL)) })
	s.launchIf(wg, c.EnableAutocomplete,
		func() { emit(ctx, findingsChan, s.testAutocomplete(ctx, targetURL)) })
	s.launchIf(wg, c.EnableWeakPwd && c.RegistrationURL != "",
		func() { emit(ctx, findingsChan, s.testWeakPwd(ctx)) })
	s.launchIf(wg, c.EnableDupReg && c.RegistrationURL != "",
		func() { emit(ctx, findingsChan, s.testDupReg(ctx)) })
}

// launchURLClassic dispatches the classic OWASP-Top-10 URL-level probes:
// IDOR (single + two-identity), CORS, JNDI, security headers, exposure,
// cloud, subtakeover, TLS, login auth, GraphQL, smuggling.
func (s *InternalScanner) launchURLClassic(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIf(wg, c.EnableIDOR, func() { emit(ctx, findingsChan, s.testIDOR(ctx, targetURL)) })
	s.launchIf(wg, c.AuthA.HasAuth() && c.AuthB.HasAuth(),
		func() { emit(ctx, findingsChan, s.testCrossIdentityIDOR(ctx, targetURL)) })
	s.launchIf(wg, c.EnableBAC && c.AuthA.HasAuth(),
		func() { emit(ctx, findingsChan, s.testBAC(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCORS, func() { emit(ctx, findingsChan, s.testCORS(ctx, targetURL)) })
	s.launchIf(wg, c.EnableJNDI, func() { emit(ctx, findingsChan, s.testJNDI(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSecHeaders, func() { emit(ctx, findingsChan, s.testSecHeaders(ctx, targetURL)) })
	s.launchIf(wg, c.EnableWAFDetect, func() { emit(ctx, findingsChan, s.testWAFDetect(ctx, targetURL)) })
	s.launchIf(wg, c.EnableXFS, func() { emit(ctx, findingsChan, s.testXFS(ctx, targetURL)) })
	s.launchIf(wg, c.EnableIISTilde, func() { emit(ctx, findingsChan, s.testIISTilde(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSameSiteScript, func() { emit(ctx, findingsChan, s.testSameSiteScript(ctx, targetURL)) })
	s.launchIf(wg, c.EnableVHostEnum, func() { emit(ctx, findingsChan, s.testVHostEnum(ctx, targetURL)) })
	s.launchIf(wg, c.EnableESI, func() { emit(ctx, findingsChan, s.testESI(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSolrInject, func() { emit(ctx, findingsChan, s.testSolrInject(ctx, targetURL)) })
	s.launchIf(wg, c.EnablePHPInject, func() { emit(ctx, findingsChan, s.testPHPInject(ctx, targetURL)) })
	s.launchIf(wg, c.EnableJavaReflect, func() { emit(ctx, findingsChan, s.testJavaReflect(ctx, targetURL)) })
	s.launchIf(wg, c.EnableNodeJSInject, func() { emit(ctx, findingsChan, s.testNodeJSInject(ctx, targetURL)) })
	s.launchIf(wg, c.EnableArgInject, func() { emit(ctx, findingsChan, s.testArgInject(ctx, targetURL)) })
	s.launchIf(wg, c.EnableFileOps, func() { emit(ctx, findingsChan, s.testFileOps(ctx, targetURL)) })
	s.launchIf(wg, c.EnableRSCInject, func() { emit(ctx, findingsChan, s.testRSCInject(ctx, targetURL)) })
	s.launchIf(wg, c.EnableWebAuthn, func() { emit(ctx, findingsChan, s.testWebAuthn(ctx, targetURL)) })
	s.launchIf(wg, c.EnableHTTP3Desync, func() { emit(ctx, findingsChan, s.testHTTP3Desync(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCSPAudit, func() { emit(ctx, findingsChan, s.testCSPAudit(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCookieToss, func() { emit(ctx, findingsChan, s.testCookieToss(ctx, targetURL)) })
	s.launchIf(wg, c.EnableWebhookSig, func() { emit(ctx, findingsChan, s.testWebhookSig(ctx, targetURL)) })
	s.launchIf(wg, c.EnableExposure, func() { emit(ctx, findingsChan, s.testExposure(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCloud, func() { emit(ctx, findingsChan, s.testCloud(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSubTakeover && len(c.Subdomains) > 0,
		func() { emit(ctx, findingsChan, s.testSubTakeover(ctx)) })
	s.launchIf(wg, c.EnableTLS, func() { emit(ctx, findingsChan, s.testTLS(ctx, targetURL)) })
	s.launchIf(wg, c.EnableAuth && c.LoginURL != "",
		func() { emit(ctx, findingsChan, s.testAuth(ctx, c.LoginURL)) })
	s.launchIf(wg, c.EnableGraphQL, func() { emit(ctx, findingsChan, s.testGraphQL(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSmuggling, func() { emit(ctx, findingsChan, s.testSmuggling(ctx, targetURL)) })
}

// launchURLAccess dispatches authentication- / access-control-shaped
// URL-level probes: log-injection, file upload, verb tampering, path
// normalization, race conditions, host header, OAuth, XXE-POST, CSRF,
// type-juggling.
func (s *InternalScanner) launchURLAccess(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIf(wg, c.EnableLogInj, func() { emit(ctx, findingsChan, s.testLogInj(ctx, targetURL)) })
	s.launchIf(wg, c.EnableFileUpload, func() { emit(ctx, findingsChan, s.testFileUpload(ctx, targetURL)) })
	s.launchIf(wg, c.EnableVerbTamper, func() { emit(ctx, findingsChan, s.testVerbTamper(ctx, targetURL)) })
	s.launchIf(wg, c.EnablePathNorm, func() { emit(ctx, findingsChan, s.testPathNorm(ctx, targetURL)) })
	s.launchIf(wg, c.EnableRaceCond, func() { emit(ctx, findingsChan, s.testRaceCond(ctx, targetURL)) })
	s.launchIf(wg, c.EnableHostHdr, func() { emit(ctx, findingsChan, s.testHostHdr(ctx, targetURL)) })
	s.launchIf(wg, c.EnableOAuth, func() { emit(ctx, findingsChan, s.testOAuth(ctx, targetURL)) })
	s.launchIf(wg, c.EnableXXE, func() { emit(ctx, findingsChan, s.testXXEPost(ctx, targetURL)) })
}

// launchURLNetwork dispatches network / protocol probes: WebSocket,
// SSE, gRPC reflection, HTTP/2 rapid-reset.
// WS and SSE use launchIfTimed: both hold an open connection that can
// block indefinitely on targets that don't speak the protocol.
func (s *InternalScanner) launchURLNetwork(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIfTimed(ctx, wg, c.EnableWS, func(tctx context.Context) { emit(tctx, findingsChan, s.testWS(tctx, targetURL)) })
	s.launchIfTimed(ctx, wg, c.EnableSSE, func(tctx context.Context) { emit(tctx, findingsChan, s.testSSE(tctx, targetURL)) })
	s.launchIf(wg, c.EnableGRPCReflect, func() { emit(ctx, findingsChan, s.testGRPCReflect(ctx, targetURL)) })
	s.launchIf(wg, c.EnableH2Reset, func() { emit(ctx, findingsChan, s.testH2Reset(ctx, targetURL)) })
	s.launchIf(wg, c.EnableH2Continue, func() { emit(ctx, findingsChan, s.testH2Continuation(ctx, targetURL)) })
	s.launchIf(wg, c.EnableH2MadeReset, func() { emit(ctx, findingsChan, s.testH2MadeYouReset(ctx, targetURL)) })
}

// launchURLDOM dispatches headless-browser-backed probes: storage
// injection, DOM-XSS, client-side prototype pollution, DOM-based
// open redirect, postMessage origin validation.
// All use launchIfTimed: headless probes hang on API-only targets
// (no HTML to render), so the 60s cap ensures the scan finishes.
func (s *InternalScanner) launchURLDOM(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIfTimed(ctx, wg, c.EnableStorageInj && s.storageInjDetector != nil,
		func(tctx context.Context) {
			emit(tctx, findingsChan, s.testStorageInj(tctx, targetURL))
		})
	s.launchIfTimed(ctx, wg, c.EnableDOMXSS && s.headlessPool != nil,
		func(tctx context.Context) {
			emit(tctx, findingsChan, s.testDOMXSS(tctx, targetURL))
		})
	s.launchIfTimed(ctx, wg, c.EnableProtoPoll && s.headlessPool != nil,
		func(tctx context.Context) {
			emit(tctx, findingsChan, s.testProtoPollutionDOM(tctx, targetURL))
		})
	s.launchIfTimed(ctx, wg, c.EnableDOMRedirect && s.headlessPool != nil,
		func(tctx context.Context) {
			emit(tctx, findingsChan, s.testDOMRedirect(tctx, targetURL))
		})
	s.launchIfTimed(ctx, wg, c.EnablePostMsg && s.postMsgDetector != nil,
		func(tctx context.Context) {
			emit(tctx, findingsChan, s.testPostMsg(tctx, targetURL))
		})
}

// launchURLAPI dispatches API-surface probes: JS dependency CVE,
// data exposure, admin path, API version enumeration, rate limit,
// OpenAPI spec, content-type confusion.
func (s *InternalScanner) launchURLAPI(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIf(wg, c.EnableJSDep, func() { emit(ctx, findingsChan, s.testJSDep(ctx, targetURL)) })
	s.launchIf(wg, c.EnableDataExposure, func() { emit(ctx, findingsChan, s.testDataExposure(ctx, targetURL)) })
	s.launchIf(wg, c.EnableAdminPath, func() { emit(ctx, findingsChan, s.testAdminPath(ctx, targetURL)) })
	s.launchIf(wg, c.EnableAPIVersion, func() { emit(ctx, findingsChan, s.testAPIVersion(ctx, targetURL)) })
	s.launchIf(wg, c.EnableRateLimit, func() { emit(ctx, findingsChan, s.testRateLimit(ctx, targetURL)) })
	s.launchIf(wg, c.APISpecURL != "", func() { emit(ctx, findingsChan, s.testAPISpec(ctx, targetURL)) })
	s.launchIf(wg, c.EnableContentType, func() { emit(ctx, findingsChan, s.testContentType(ctx, targetURL)) })
}

// launchURLModern dispatches modern / niche URL-level probes that
// don't fit the classic / access / network / DOM / API buckets:
// CSRF, tabnabbing, ReDoS, prompt-injection, XSLT, SAML envelope,
// ORM leak, type-juggling, dependency-confusion, token entropy,
// cache deception, second-order injection, cookie / session storage.
func (s *InternalScanner) launchURLModern(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string, scanCfg *Config) {
	c := s.config
	s.launchIf(wg, c.EnableCSRF, func() { emit(ctx, findingsChan, s.testCSRF(ctx, targetURL, scanCfg)) })
	s.launchIf(wg, c.EnableTabnabbing, func() { emit(ctx, findingsChan, s.testTabnabbing(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCSPT, func() { emit(ctx, findingsChan, s.testCSPT(ctx, targetURL)) })
	s.launchIf(wg, c.EnableReDoS, func() { emit(ctx, findingsChan, s.testReDoS(ctx, targetURL)) })
	s.launchIf(wg, c.EnablePromptInj, func() { emit(ctx, findingsChan, s.testPromptInjection(ctx, targetURL)) })
	s.launchIf(wg, c.EnableXSLT, func() { emit(ctx, findingsChan, s.testXSLT(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSAMLInj, func() { emit(ctx, findingsChan, s.testSAMLInj(ctx, targetURL)) })
	s.launchIf(wg, c.EnableORMLeak, func() { emit(ctx, findingsChan, s.testORMLeak(ctx, targetURL)) })
	s.launchIf(wg, c.EnableTypeJuggling, func() { emit(ctx, findingsChan, s.testTypeJuggling(ctx, targetURL, scanCfg)) })
	s.launchIf(wg, c.EnableDepConfusion, func() { emit(ctx, findingsChan, s.testDepConfusion(ctx, targetURL)) })
	s.launchIf(wg, c.EnableTokenEntropy, func() { emit(ctx, findingsChan, s.testTokenEntropy(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCacheDeception, func() { emit(ctx, findingsChan, s.testCacheDeception(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSecondOrder, func() { emit(ctx, findingsChan, s.testSecondOrder(ctx, targetURL)) })
	s.launchIf(wg, c.EnableStorage, func() { emit(ctx, findingsChan, s.testStorageMgmt(ctx, targetURL)) })
	s.launchIf(wg, c.EnableXSLeaks, func() { emit(ctx, findingsChan, s.testXSLeaks(ctx, targetURL)) })
	s.launchIf(wg, c.EnableJWTAdvanced && c.JWTAdvancedToken != "",
		func() { emit(ctx, findingsChan, s.testJWTAdvanced(ctx, targetURL)) })
	s.launchIf(wg, c.EnableGraphQLAdvanced,
		func() { emit(ctx, findingsChan, s.testGraphQLAdvanced(ctx, targetURL)) })
	s.launchIf(wg, c.EnableHTTP2Desync,
		func() { emit(ctx, findingsChan, s.testHTTP2Desync(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCacheKey,
		func() { emit(ctx, findingsChan, s.testCacheKey(ctx, targetURL)) })
	s.launchIf(wg, c.EnableAuthBypass403,
		func() { emit(ctx, findingsChan, s.testAuthBypass403(ctx, targetURL)) })
	s.launchIf(wg, c.EnableHTTP2Race && c.HTTP2RaceURL != "",
		func() { emit(ctx, findingsChan, s.testHTTP2Race(ctx, targetURL)) })
	s.launchIf(wg, c.EnableGraphQLDoS,
		func() { emit(ctx, findingsChan, s.testGraphQLDoS(ctx, targetURL)) })
	s.launchIf(wg, c.EnableJKUAbuse && c.JWTAdvancedToken != "",
		func() { emit(ctx, findingsChan, s.testJKUAbuse(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSameSiteLax,
		func() { emit(ctx, findingsChan, s.testSameSiteLax(ctx, targetURL)) })
}
