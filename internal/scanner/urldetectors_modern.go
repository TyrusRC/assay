package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cachedeception"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/postmsg"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/secondorder"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/storage"
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
