package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/domdetect"
)

// acquireDOMRunner pulls one Page off the headless pool. The caller must
// release it via the returned cleanup func; on failure both runner and
// cleanup are nil so the caller can early-return without nil-checks.
func (s *InternalScanner) acquireDOMRunner(ctx context.Context) (domdetect.Runner, func()) {
	if s.headlessPool == nil {
		return nil, nil
	}
	page, err := s.headlessPool.Acquire(ctx)
	if err != nil || page == nil {
		return nil, nil
	}
	return page, func() { s.headlessPool.Release(page) }
}

// testDOMXSS runs the headless DOM-XSS probe on every query parameter of
// targetURL. No-op when no headless pool is available.
func (s *InternalScanner) testDOMXSS(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing DOM XSS on '%s'...\n", targetURL)
	}
	runner, release := s.acquireDOMRunner(ctx)
	if runner == nil {
		return nil
	}
	defer release()

	res, err := domdetect.DetectXSS(ctx, runner, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testProtoPollutionDOM runs the headless client-side prototype-pollution
// probe on targetURL. No-op when no headless pool is available.
func (s *InternalScanner) testProtoPollutionDOM(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing client-side prototype pollution on '%s'...\n", targetURL)
	}
	runner, release := s.acquireDOMRunner(ctx)
	if runner == nil {
		return nil
	}
	defer release()

	res, err := domdetect.DetectProtoPollution(ctx, runner, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testDOMRedirect runs the headless DOM-based open-redirect probe on
// targetURL. No-op when no headless pool is available.
func (s *InternalScanner) testDOMRedirect(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing DOM-based open redirect on '%s'...\n", targetURL)
	}
	runner, release := s.acquireDOMRunner(ctx)
	if runner == nil {
		return nil
	}
	defer release()

	res, err := domdetect.DetectDOMRedirect(ctx, runner, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}
