package scanner

import (
	"context"
	"sync"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// launchIf is sugar around InternalScanner.launch that gates on a
// boolean before scheduling, so the URL-level orchestrator stays one
// line per detector instead of seven.
func (s *InternalScanner) launchIf(wg *sync.WaitGroup, cond bool, fn func()) {
	if !cond {
		return
	}
	s.launch(wg, fn)
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
}

// launchURLClassic dispatches the classic OWASP-Top-10 URL-level probes:
// IDOR (single + two-identity), CORS, JNDI, security headers, exposure,
// cloud, subtakeover, TLS, login auth, GraphQL, smuggling.
func (s *InternalScanner) launchURLClassic(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIf(wg, c.EnableIDOR, func() { emit(ctx, findingsChan, s.testIDOR(ctx, targetURL)) })
	s.launchIf(wg, c.AuthA.HasAuth() && c.AuthB.HasAuth(),
		func() { emit(ctx, findingsChan, s.testCrossIdentityIDOR(ctx, targetURL)) })
	s.launchIf(wg, c.EnableCORS, func() { emit(ctx, findingsChan, s.testCORS(ctx, targetURL)) })
	s.launchIf(wg, c.EnableJNDI, func() { emit(ctx, findingsChan, s.testJNDI(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSecHeaders, func() { emit(ctx, findingsChan, s.testSecHeaders(ctx, targetURL)) })
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
func (s *InternalScanner) launchURLNetwork(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIf(wg, c.EnableWS, func() { emit(ctx, findingsChan, s.testWS(ctx, targetURL)) })
	s.launchIf(wg, c.EnableSSE, func() { emit(ctx, findingsChan, s.testSSE(ctx, targetURL)) })
	s.launchIf(wg, c.EnableGRPCReflect, func() { emit(ctx, findingsChan, s.testGRPCReflect(ctx, targetURL)) })
	s.launchIf(wg, c.EnableH2Reset, func() { emit(ctx, findingsChan, s.testH2Reset(ctx, targetURL)) })
}

// launchURLDOM dispatches headless-browser-backed probes: storage
// injection, DOM-XSS, client-side prototype pollution, DOM-based
// open redirect, postMessage origin validation.
func (s *InternalScanner) launchURLDOM(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, targetURL string) {
	c := s.config
	s.launchIf(wg, c.EnableStorageInj && s.storageInjDetector != nil,
		func() { emit(ctx, findingsChan, s.testStorageInj(ctx, targetURL)) })
	s.launchIf(wg, c.EnableDOMXSS && s.headlessPool != nil,
		func() { emit(ctx, findingsChan, s.testDOMXSS(ctx, targetURL)) })
	s.launchIf(wg, c.EnableProtoPoll && s.headlessPool != nil,
		func() { emit(ctx, findingsChan, s.testProtoPollutionDOM(ctx, targetURL)) })
	s.launchIf(wg, c.EnableDOMRedirect && s.headlessPool != nil,
		func() { emit(ctx, findingsChan, s.testDOMRedirect(ctx, targetURL)) })
	s.launchIf(wg, c.EnablePostMsg && s.postMsgDetector != nil,
		func() { emit(ctx, findingsChan, s.testPostMsg(ctx, targetURL)) })
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
}
