package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cachepoisoning"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/cssinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/deser"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/domclobber"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/emailinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/hpp"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/htmlinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/massassign"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/protopollution"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ssi"
)

// testCachePoisoning probes a parameter for unkeyed-input cache poisoning.
func (s *InternalScanner) testCachePoisoning(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing cache poisoning on param '%s'...\n", param.Name)
	}
	opts := cachepoisoning.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.cachePoisoningDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testCSSInj probes a parameter for CSS injection.
func (s *InternalScanner) testCSSInj(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CSS injection on param '%s'...\n", param.Name)
	}
	opts := cssinj.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.cssInjDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testDeser probes a parameter for insecure deserialization.
func (s *InternalScanner) testDeser(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing deserialization on param '%s'...\n", param.Name)
	}
	opts := deser.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.deserDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testDOMClobber probes a parameter for DOM-clobbering injection points.
func (s *InternalScanner) testDOMClobber(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing DOM clobbering on param '%s'...\n", param.Name)
	}
	opts := domclobber.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.domClobberDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testEmailInj probes a parameter for email-header injection (CRLF in mail headers).
func (s *InternalScanner) testEmailInj(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing email injection on param '%s'...\n", param.Name)
	}
	opts := emailinj.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.emailInjDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testHPP probes a parameter for HTTP Parameter Pollution.
func (s *InternalScanner) testHPP(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HPP on param '%s'...\n", param.Name)
	}
	opts := hpp.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.hppDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testHTMLInj probes a parameter for HTML injection (non-XSS tag injection).
func (s *InternalScanner) testHTMLInj(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HTML injection on param '%s'...\n", param.Name)
	}
	opts := htmlinj.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.htmlInjDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testMassAssign probes a parameter for mass-assignment vulnerabilities.
func (s *InternalScanner) testMassAssign(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing mass-assignment on param '%s'...\n", param.Name)
	}
	opts := massassign.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.massAssignDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testProtoPollServer probes a parameter for server-side prototype pollution.
func (s *InternalScanner) testProtoPollServer(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing server-side prototype pollution on param '%s'...\n", param.Name)
	}
	opts := protopollution.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.protoPollutionDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testSSI probes a parameter for Server-Side Includes injection.
func (s *InternalScanner) testSSI(ctx context.Context, targetURL string, param core.Parameter, method string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing SSI on param '%s'...\n", param.Name)
	}
	opts := ssi.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	result, err := s.ssiDetector.Detect(ctx, targetURL, param.Name, method, opts)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}
