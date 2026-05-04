package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/apispec"
)

// testDataExposure walks the JSON response for sensitive field names
// (OWASP API3:2023, read-side excessive data exposure).
func (s *InternalScanner) testDataExposure(ctx context.Context, targetURL string) []*core.Finding {
	if s.dataExposureDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing excessive data exposure on '%s'...\n", targetURL)
	}
	res, err := s.dataExposureDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testAdminPath probes the host for admin / debug / internal endpoints
// reachable without authentication (OWASP API5:2023, A05:2025).
func (s *InternalScanner) testAdminPath(ctx context.Context, targetURL string) []*core.Finding {
	if s.adminPathDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing admin / debug paths on '%s'...\n", targetURL)
	}
	res, err := s.adminPathDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testAPIVersion probes sibling versions of the URL's /vN/ segment
// (OWASP API9:2023 Improper Inventory Management).
func (s *InternalScanner) testAPIVersion(ctx context.Context, targetURL string) []*core.Finding {
	if s.apiVersionDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Probing sibling API versions for '%s'...\n", targetURL)
	}
	res, err := s.apiVersionDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testRateLimit sends a controlled burst to detect missing rate limits
// (OWASP API4:2023). Off by default to avoid load-bearing probes.
func (s *InternalScanner) testRateLimit(ctx context.Context, targetURL string) []*core.Finding {
	if s.rateLimitDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Burst-probing rate limit on '%s'...\n", targetURL)
	}
	res, err := s.rateLimitDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}

// testAPISpec drives the OpenAPI spec runner against the target. Loads
// the spec on first call; only active when APISpecURL is configured.
func (s *InternalScanner) testAPISpec(ctx context.Context, targetURL string) []*core.Finding {
	if s.apiSpecRunner == nil || s.config.APISpecURL == "" {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Loading OpenAPI spec from '%s'...\n", s.config.APISpecURL)
	}
	spec, err := apispec.LoadFromURL(ctx, s.client, s.config.APISpecURL)
	if err != nil || spec == nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] OpenAPI spec load failed: %v\n", err)
		}
		return nil
	}
	res, err := s.apiSpecRunner.Run(ctx, spec, targetURL)
	if err != nil || res == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[+] OpenAPI runner: probed %d endpoints, %d findings\n",
			res.EndpointsProbed, len(res.Findings))
	}
	return res.Findings
}

// testORMLeak probes for ORM expansion / over-fetch leaks
// (OWASP API3:2023).
func (s *InternalScanner) testORMLeak(ctx context.Context, targetURL string) []*core.Finding {
	if s.ormLeakDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing ORM expansion leaks on '%s'...\n", targetURL)
	}
	res, err := s.ormLeakDetector.Detect(ctx, targetURL)
	if err != nil || res == nil {
		return nil
	}
	return res.Findings
}
