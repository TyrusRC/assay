package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/cachedeception"
	"github.com/TyrusRC/assay/internal/detection/graphqladvanced"
	"github.com/TyrusRC/assay/internal/detection/http2desync"
	"github.com/TyrusRC/assay/internal/detection/jwtadvanced"
	"github.com/TyrusRC/assay/internal/detection/postmsg"
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
