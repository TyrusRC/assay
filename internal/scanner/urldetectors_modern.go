package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/authbypass403"
	"github.com/TyrusRC/assay/internal/detection/cachedeception"
	"github.com/TyrusRC/assay/internal/detection/cachekey"
	"github.com/TyrusRC/assay/internal/detection/graphqladvanced"
	"github.com/TyrusRC/assay/internal/detection/graphqldos"
	"github.com/TyrusRC/assay/internal/detection/http2desync"
	"github.com/TyrusRC/assay/internal/detection/http2race"
	"github.com/TyrusRC/assay/internal/detection/jkuabuse"
	"github.com/TyrusRC/assay/internal/detection/jwtadvanced"
	"github.com/TyrusRC/assay/internal/detection/oob"
	"github.com/TyrusRC/assay/internal/detection/postmsg"
	"github.com/TyrusRC/assay/internal/detection/samesitelax"
	"github.com/TyrusRC/assay/internal/detection/secondorder"
	"github.com/TyrusRC/assay/internal/detection/storage"
	"github.com/TyrusRC/assay/internal/detection/xsleaks"
)

// testCacheDeception probes for web cache deception (Omer Gil, 2017): a
// deceptive URL extension or path-normalization variant that causes a
// downstream cache to store the authenticated user's private response
// under a public-looking key. Requires auth state on the shared client.
func (s *InternalScanner) testCacheDeception(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing cache deception on '%s'...\n", targetURL)
	}
	s.cacheDeceptionDetector.WithVerbose(s.config.Verbose)
	result, err := s.cacheDeceptionDetector.Detect(ctx, targetURL, cachedeception.DefaultOptions())
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testSecondOrder probes for second-order injection: payload stored in
// one request, observed reflected in a different response (e.g., admin
// dashboard, log viewer). When OOB is up, callbacks confirm blind cases.
func (s *InternalScanner) testSecondOrder(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing second-order injection on '%s'...\n", targetURL)
	}
	opts := secondorder.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	if s.oobClient != nil {
		opts.CallbackDomain = s.oobClient.GetURL()
	}
	result, err := s.secondOrderDetector.Detect(ctx, targetURL, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testPostMsg dispatches a synthetic MessageEvent from an attacker-
// origin into the page and reports listeners that mutated DOM/storage
// without validating event.origin. No-op when the headless pool isn't
// available — the postmsg detector handles that gracefully.
func (s *InternalScanner) testPostMsg(ctx context.Context, targetURL string) []*core.Finding {
	if s.postMsgDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing postMessage origin validation on '%s'...\n", targetURL)
	}
	opts := postmsg.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.postMsgDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testCacheKey probes for cache-key parser-divergence quirks
// (semicolon param cloaking, duplicate-param pollution, encoded-slash
// normalization). Paired-request differential — no destructive side
// effects, safe to leave on by default.
func (s *InternalScanner) testCacheKey(ctx context.Context, targetURL string) []*core.Finding {
	if s.cachekeyDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing cache-key parser divergence on '%s'...\n", targetURL)
	}
	opts := cachekey.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.cachekeyDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testHTTP2Race fires a concurrent burst at the configured race-test
// URL and reports when more than one request landed in the
// pre-state-change window. Skipped when no URL is configured because
// the probe sends real state-changing requests and must be pointed at
// a known-safe coupon/redeem/vote endpoint.
func (s *InternalScanner) testHTTP2Race(ctx context.Context, _ string) []*core.Finding {
	if s.http2RaceDetector == nil || s.config.HTTP2RaceURL == "" {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HTTP/2 single-packet race on '%s'...\n", s.config.HTTP2RaceURL)
	}
	opts := http2race.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	if s.config.HTTP2RaceMethod != "" {
		opts.Method = s.config.HTTP2RaceMethod
	}
	opts.Body = s.config.HTTP2RaceBody
	opts.ContentType = s.config.HTTP2RaceContentType
	res, err := s.http2RaceDetector.Detect(ctx, s.config.HTTP2RaceURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testAuthBypass403 probes for 401/403 access-control bypass via
// reverse-proxy trust headers (X-Original-URL, X-Rewrite-URL,
// X-Forwarded-For=127.0.0.1, X-Custom-IP-Authorization) and path
// tricks (;jsessionid=, /..;/, trailing-slash flip). Self-gates on a
// 401/403 baseline — public URLs are a single-request no-op.
func (s *InternalScanner) testAuthBypass403(ctx context.Context, targetURL string) []*core.Finding {
	if s.authBypass403Detector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing 401/403 access-control bypass on '%s'...\n", targetURL)
	}
	opts := authbypass403.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.authBypass403Detector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testHTTP2Desync probes for CL.0 desync (Content-Length: 0 with body)
// and h2c upgrade acceptance over raw TCP. Off by default because it
// sends malformed-on-purpose desync payloads.
func (s *InternalScanner) testHTTP2Desync(ctx context.Context, targetURL string) []*core.Finding {
	if s.http2DesyncDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HTTP/2 desync (CL.0, h2c upgrade) on '%s'...\n", targetURL)
	}
	opts := http2desync.DefaultOptions()
	opts.ProbeTimeout = s.config.RequestTimeout
	res, err := s.http2DesyncDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testGraphQLDoS probes for GraphQL resource-exhaustion attack surface
// — alias amplification, deeply-nested query depth bombs, and batched-
// query acceptance. Self-gates on a GraphQL response shape so non-
// GraphQL URLs cost exactly one request.
func (s *InternalScanner) testGraphQLDoS(ctx context.Context, targetURL string) []*core.Finding {
	if s.graphqlDosDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing GraphQL DoS probes on '%s'...\n", targetURL)
	}
	opts := graphqldos.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.graphqlDosDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testGraphQLAdvanced probes a GraphQL endpoint for field-suggestion
// schema recovery, APQ bypass, and mutation-over-GET CSRF. The probe
// self-gates on a GraphQL-shaped response, so running against non-
// GraphQL URLs is a single-request no-op.
func (s *InternalScanner) testGraphQLAdvanced(ctx context.Context, targetURL string) []*core.Finding {
	if s.graphqlAdvancedDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing GraphQL advanced probes on '%s'...\n", targetURL)
	}
	opts := graphqladvanced.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.graphqlAdvancedDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testJKUAbuse forges a JWT whose header points jku at the OOB
// callback URL and reports when the target's JWT library fetches it
// before signature validation. The fetch alone is the bug — what the
// library does with whatever JWKS it finds at the URL is a follow-up.
// No-op when JWTAdvancedToken is empty or the OOB client isn't ready.
func (s *InternalScanner) testJKUAbuse(ctx context.Context, targetURL string) []*core.Finding {
	if s.jkuAbuseDetector == nil || s.config.JWTAdvancedToken == "" || s.oobClient == nil {
		return nil
	}
	payload := s.oobClient.GeneratePayload("jkuabuse")
	if payload == nil || payload.URL == "" {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing JKU/X5U URL trust on '%s' via callback '%s'...\n", targetURL, payload.URL)
	}
	opts := jkuabuse.DefaultOptions()
	opts.Token = s.config.JWTAdvancedToken
	opts.TokenParam = s.config.JWTAdvancedParam
	opts.CallbackURL = payload.URL
	opts.Callback = &oobInteractionChecker{client: s.oobClient}
	opts.Timeout = s.config.RequestTimeout
	res, err := s.jkuAbuseDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testSameSiteLax inspects auth-cookie SameSite attributes and (when
// SameSiteLaxProbeGET is enabled) confirms exploitable GET-logout
// behavior against well-known logout paths.
func (s *InternalScanner) testSameSiteLax(ctx context.Context, targetURL string) []*core.Finding {
	if s.sameSiteLaxDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Inspecting SameSite cookie attributes on '%s'...\n", targetURL)
	}
	opts := samesitelax.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.ProbeLogoutPaths = s.config.SameSiteLaxProbeGET
	res, err := s.sameSiteLaxDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// oobInteractionChecker adapts the scanner's oob.Client to the
// jkuabuse.CallbackChecker interface — interactsh's HasInteraction
// already does a substring match across received payloads.
type oobInteractionChecker struct {
	client *oob.Client
}

func (o *oobInteractionChecker) HasInteraction(id string) bool {
	if o == nil || o.client == nil {
		return false
	}
	return o.client.HasInteraction(id)
}

// testJWTAdvanced actively replays forged JWTs (alg=none, empty
// signature, kid traversal, duplicate alg, truncated sig) against the
// target URL and reports any forgery the server accepts as authentic.
// Requires a known-good token in s.config.JWTAdvancedToken; otherwise
// the probe is skipped — there's no diff signal without a baseline.
func (s *InternalScanner) testJWTAdvanced(ctx context.Context, targetURL string) []*core.Finding {
	if s.jwtAdvancedDetector == nil || s.config.JWTAdvancedToken == "" {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing JWT forgery acceptance on '%s'...\n", targetURL)
	}
	opts := jwtadvanced.DefaultOptions()
	opts.Token = s.config.JWTAdvancedToken
	opts.TokenParam = s.config.JWTAdvancedParam
	opts.Timeout = s.config.RequestTimeout
	res, err := s.jwtAdvancedDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testXSLeaks audits the response for combinations of isolation-policy
// gaps (COOP/COEP/CORP, X-Frame-Options, CSP frame-ancestors) and
// SameSite cookie behavior that expose cross-site leak primitives.
// Only emits findings when primitives correlate into an exploitable
// combination — single missing headers are left to secheaders/.
func (s *InternalScanner) testXSLeaks(ctx context.Context, targetURL string) []*core.Finding {
	if s.xsleaksDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing cross-site leak primitives on '%s'...\n", targetURL)
	}
	opts := xsleaks.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	res, err := s.xsleaksDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testStorageMgmt audits cookie attributes (Secure, HttpOnly, SameSite,
// overly broad Domain) and session-management entropy. Distinct from
// testStorageInj which probes client-side storage XSS via headless.
func (s *InternalScanner) testStorageMgmt(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing cookie / session management on '%s'...\n", targetURL)
	}
	opts := storage.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.storageDetector.Detect(ctx, targetURL, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}
