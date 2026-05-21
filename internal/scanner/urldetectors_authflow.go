package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/auth"
	"github.com/TyrusRC/assay/internal/detection/dnsrebinding"
	"github.com/TyrusRC/assay/internal/detection/http2advanced"
	"github.com/TyrusRC/assay/internal/detection/mfabypass"
	"github.com/TyrusRC/assay/internal/detection/oauthflow"
	"github.com/TyrusRC/assay/internal/detection/openapisemantic"
	"github.com/TyrusRC/assay/internal/detection/paddingoracle"
	"github.com/TyrusRC/assay/internal/detection/passwordreset"
	"github.com/TyrusRC/assay/internal/detection/sessionfixation"
	"github.com/TyrusRC/assay/internal/detection/sessionlifecycle"
	"github.com/TyrusRC/assay/internal/detection/stacktrace"
)

// testTimingEnum runs the statistical paired-arm timing oracle on the
// configured LoginURL. It needs a known-valid username (read from
// AuthA.Username if set, else "admin") and a known-invalid one ("zzz_no_user").
func (s *InternalScanner) testTimingEnum(ctx context.Context, loginURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing timing-based account enumeration on '%s'...\n", loginURL)
	}
	validUser := s.config.AuthA.Username
	if validUser == "" {
		validUser = "admin"
	}
	result, err := s.authDetector.DetectTimingEnumeration(ctx, loginURL, auth.TimingEnumOptions{
		ValidUser:   validUser,
		InvalidUser: "zzz_no_user_" + nonceLite(),
		Samples:     8,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testPasswordReset exercises the three reset-flow probes: host-header
// poisoning, cross-user token acceptance, and reset-token replay.
func (s *InternalScanner) testPasswordReset(ctx context.Context, resetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing password reset flow on '%s'...\n", resetURL)
	}
	userA := s.config.AuthA.Username
	userB := s.config.AuthB.Username
	if userA == "" {
		userA = "alice@example.com"
	}
	if userB == "" {
		userB = "bob@example.com"
	}
	results, err := s.passwordResetDetector.DetectAll(ctx, resetURL, passwordreset.DetectOptions{
		UserA:   userA,
		UserB:   userB,
		Timeout: s.config.RequestTimeout,
	})
	if err != nil {
		return nil
	}
	var findings []*core.Finding
	for _, r := range results {
		if r != nil {
			findings = append(findings, r.Findings...)
		}
	}
	return findings
}

// testSessionLifecycle runs refresh-rotation, logout-invalidation, and
// concurrent-session probes. Needs LoginURL + ProtectedURL at minimum.
func (s *InternalScanner) testSessionLifecycle(ctx context.Context) []*core.Finding {
	c := s.config
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing session lifecycle (login=%s)...\n", c.LoginURL)
	}
	result, err := s.sessionLifecycleDetector.DetectAll(ctx, sessionlifecycle.DetectOptions{
		LoginURL:              c.LoginURL,
		RefreshURL:            c.RefreshURL,
		LogoutURL:             c.LogoutURL,
		ProtectedURL:          c.ProtectedURL,
		Username:              c.AuthA.Username,
		Password:              c.AuthA.Password,
		SingleSessionRequired: false,
		Timeout:               c.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testOAuthFlow runs the four OAuth/OIDC flow probes against the configured
// authorize endpoint. PKCE downgrade and alg=none require TokenURL too.
func (s *InternalScanner) testOAuthFlow(ctx context.Context) []*core.Finding {
	c := s.config
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing OAuth/OIDC flow (authz=%s)...\n", c.OAuthAuthzURL)
	}
	result, err := s.oauthFlowDetector.DetectAll(ctx, oauthflow.DetectOptions{
		ClientID:              c.OAuthClientID,
		RegisteredRedirectURI: c.OAuthRedirectURI,
		AuthzURL:              c.OAuthAuthzURL,
		TokenURL:              c.OAuthTokenURL,
		Timeout:               c.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testDNSRebinding looks for short-TTL multi-IP hostnames in the target,
// then probes SSRF allowlist bypass via well-known rebinding hosts when
// SSRFParam is configured.
func (s *InternalScanner) testDNSRebinding(ctx context.Context, targetURL string) []*core.Finding {
	c := s.config
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing DNS rebinding susceptibility on '%s'...\n", targetURL)
	}
	result, err := s.dnsRebindingDetector.DetectAll(ctx, targetURL, c.SSRFParam, dnsrebinding.DetectOptions{
		SSRFParam:         c.SSRFParam,
		RebindingTestHost: c.DNSRebindingHost,
		Timeout:           c.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testOpenAPISemantic fetches the configured OpenAPI spec and runs the four
// semantic-bypass probes (type coercion, discriminator confusion, nullable
// leak, additionalProperties bypass).
func (s *InternalScanner) testOpenAPISemantic(ctx context.Context) []*core.Finding {
	c := s.config
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing OpenAPI semantic exploits (spec=%s)...\n", c.APISpecURL)
	}
	result, err := s.openAPISemanticDetector.DetectAll(ctx, openapisemantic.DetectOptions{
		SpecURL: c.APISpecURL,
		BaseURL: "", // inferred from spec.servers[0].url
		Timeout: c.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testHTTP2Advanced exercises HPACK-pollution / SETTINGS-flood / flow-control
// exhaustion probes against the target's HTTP/2 endpoint. Destructive variants
// stay gated behind opts.AllowDestructive.
func (s *InternalScanner) testHTTP2Advanced(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HTTP/2 advanced abuse on '%s'...\n", targetURL)
	}
	// http2advanced is target-scoped; clone with this scan's target.
	det := http2advanced.New(targetURL)
	result, err := det.DetectAll(ctx, http2advanced.DetectOptions{
		Target:           targetURL,
		AllowDestructive: false, // safe default; opt-in via flag if ever exposed
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testSessionFixation runs the pre-auth cookie + query-string session checks
// against the configured login + protected URLs.
func (s *InternalScanner) testSessionFixation(ctx context.Context) []*core.Finding {
	c := s.config
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing session fixation (login=%s)...\n", c.LoginURL)
	}
	result, err := s.sessionFixationDetector.DetectAll(ctx, sessionfixation.DetectOptions{
		LoginURL:     c.LoginURL,
		ProtectedURL: c.ProtectedURL,
		Username:     c.AuthA.Username,
		Password:     c.AuthA.Password,
		Timeout:      c.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testStackTrace probes the target with malformed input designed to trigger
// framework errors, then matches the response body against the framework
// stack-trace pattern catalog.
func (s *InternalScanner) testStackTrace(ctx context.Context, targetURL string) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing stack-trace disclosure on '%s'...\n", targetURL)
	}
	result, err := s.stackTraceDetector.DetectFromBaseline(ctx, targetURL, stacktrace.DetectOptions{
		Timeout: s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testMFABypass runs the four MFA-bypass probes against the configured
// MFA submission endpoint.
func (s *InternalScanner) testMFABypass(ctx context.Context) []*core.Finding {
	c := s.config
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing MFA bypass (mfa=%s)...\n", c.MFASubmitURL)
	}
	result, err := s.mfaBypassDetector.DetectAll(ctx, mfabypass.DetectOptions{
		LoginURL:     c.LoginURL,
		MFASubmitURL: c.MFASubmitURL,
		ProtectedURL: c.ProtectedURL,
		Username:     c.AuthA.Username,
		Password:     c.AuthA.Password,
		Timeout:      c.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// testPaddingOracle runs a CBC padding-oracle probe against a configured
// encrypted token. Caller must supply both the token sample and the param
// name carrying it (cookie or query string).
func (s *InternalScanner) testPaddingOracle(ctx context.Context, targetURL string) []*core.Finding {
	c := s.config
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CBC padding oracle (param=%s)...\n", c.PaddingOracleParam)
	}
	result, err := s.paddingOracleDetector.DetectFromToken(ctx, targetURL, c.PaddingOracleParam, c.PaddingOracleToken, paddingoracle.DetectOptions{
		Timeout: c.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

// nonceLite returns a short, non-secret time-based suffix used in generated
// usernames so repeated scans don't accidentally collide on the same
// "invalid" user string across runs against the same target.
func nonceLite() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()%100000)
}
