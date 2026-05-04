package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/fileupload"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/hosthdr"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/loginj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/oauth"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/pathnorm"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/racecond"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/storageinj"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/verbtamper"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/ws"
)

// testStorageInj tests for client-side storage injection vulnerabilities.
func (s *InternalScanner) testStorageInj(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing storage injection on '%s'...\n", targetURL)
	}
	result, err := s.storageInjDetector.Detect(ctx, targetURL, storageinj.DetectOptions{
		Timeout:        s.config.RequestTimeout,
		CheckSensitive: true,
		MaxPayloads:    s.config.MaxPayloadsPerParam,
	})
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Storage injection test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testLogInj tests for log injection vulnerabilities via HTTP headers.
func (s *InternalScanner) testLogInj(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing log injection on '%s'...\n", targetURL)
	}
	result, err := s.logInjDetector.Detect(ctx, targetURL, "", "GET", loginj.DefaultOptions())
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Log injection test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testFileUpload tests for file upload vulnerabilities.
func (s *InternalScanner) testFileUpload(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing file upload on '%s'...\n", targetURL)
	}
	result, err := s.fileUploadDetector.Detect(ctx, targetURL, "", "POST", fileupload.DetectOptions{
		MaxPayloads:       s.config.MaxPayloadsPerParam,
		IncludeMIMEBypass: s.config.IncludeWAFBypass,
		IncludeDoubleExt:  true,
		IncludeNullByte:   true,
		Timeout:           s.config.RequestTimeout,
	})
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] File upload test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testVerbTamper tests for HTTP verb tampering bypass vulnerabilities.
func (s *InternalScanner) testVerbTamper(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing verb tampering on '%s'...\n", targetURL)
	}
	result, err := s.verbTamperDetector.Detect(ctx, targetURL, "", "GET", verbtamper.DetectOptions{
		MaxPayloads:          s.config.MaxPayloadsPerParam,
		IncludeOverrideTests: true,
		Timeout:              s.config.RequestTimeout,
	})
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Verb tampering test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testPathNorm tests for path normalization bypass vulnerabilities.
func (s *InternalScanner) testPathNorm(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing path normalization on '%s'...\n", targetURL)
	}
	result, err := s.pathNormDetector.Detect(ctx, targetURL, "", "GET", pathnorm.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Path normalization test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testRaceCond tests for race condition vulnerabilities.
func (s *InternalScanner) testRaceCond(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing race conditions on '%s'...\n", targetURL)
	}
	result, err := s.raceCondDetector.Detect(ctx, targetURL, "", "GET", racecond.DetectOptions{
		ConcurrentRequests: 10,
		Timeout:            s.config.RequestTimeout,
	})
	if err != nil {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Race condition test error: %v\n", err)
		}
		return nil
	}
	if !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testWS audits WebSocket endpoints reachable from the target URL —
// CSWSH (Origin-bypass), missing-auth handshake, and message reflection.
// All dials honor the global proxy/headers/cookies/UA/insecure plumbing.
func (s *InternalScanner) testWS(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing WebSocket security on '%s'...\n", targetURL)
	}
	s.wsDetector.WithVerbose(s.config.Verbose)
	result, err := s.wsDetector.Detect(ctx, targetURL, ws.DefaultOptions())
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testHostHdr audits Host / X-Forwarded-Host header trust on the target —
// the path to password-reset hijack and cache-poisoning ATO. All requests
// honor the global proxy/headers/cookies/UA/insecure plumbing.
func (s *InternalScanner) testHostHdr(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Host header injection on '%s'...\n", targetURL)
	}
	result, err := s.hostHdrDetector.Detect(ctx, targetURL, hosthdr.DefaultOptions())
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testOAuth audits OAuth/OIDC discovery for missing PKCE, alg=none,
// implicit-flow advertisement, and redirect_uri exact-match bypass.
// Honors the global proxy/headers/cookies/UA/insecure plumbing.
func (s *InternalScanner) testOAuth(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing OAuth/OIDC on '%s'...\n", targetURL)
	}
	result, err := s.oauthDetector.Detect(ctx, targetURL, oauth.DefaultOptions())
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}
