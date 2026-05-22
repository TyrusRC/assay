package scanner

import (
	"time"

	"github.com/TyrusRC/assay/internal/detection/subtakeover"
)

// InternalScanConfig configures the internal scanner behavior.
type InternalScanConfig struct {
	// Enable/disable specific checks
	EnableSQLi         bool
	EnableXSS          bool
	EnableCMDI         bool
	EnableSSRF         bool
	EnableLFI          bool
	EnableXXE          bool
	EnableTechScan     bool
	EnableOOB          bool
	EnableNoSQL        bool
	EnableSSTI         bool
	EnableIDOR         bool
	EnableJWT          bool
	EnableRedirect     bool
	EnableCORS         bool
	EnableCRLF         bool
	EnableLDAP         bool
	EnableXPath        bool
	EnableHeaderInj    bool
	EnableCSTI         bool
	EnableRFI          bool
	EnableJNDI         bool
	EnableSecHeaders   bool
	EnableExposure     bool
	EnableCloud        bool
	EnableSubTakeover  bool
	EnableTLS          bool
	EnableAuth         bool
	EnableGraphQL      bool
	EnableSmuggling    bool
	EnableBehavior     bool
	EnableLogInj       bool
	EnableFileUpload   bool
	EnableVerbTamper   bool
	EnablePathNorm     bool
	EnableRaceCond     bool
	EnableCSVInj       bool
	EnableWS           bool
	EnableHostHdr      bool
	EnableOAuth        bool
	EnableJSDep        bool   // Detect vulnerable JS libraries via NVD lookup
	NVDAPIKey          string // Optional NVD API key (raises rate limit ~5→50/30s)
	EnableDataExposure bool   // Walk JSON responses for sensitive field names (API3:2023)
	EnableAdminPath    bool   // Probe admin/debug/internal paths (API5:2023, A05:2025)
	EnableAPIVersion   bool   // Probe sibling API versions (API9:2023)
	EnableRateLimit    bool   // Burst-probe for missing server-side rate limits (API4:2023)
	APISpecURL         string // Optional OpenAPI / Swagger JSON URL; empty disables spec-driven runner
	EnableContentType  bool   // Probe JSON endpoints for content-type confusion
	EnableSSE          bool   // Probe text/event-stream endpoints for missing auth
	EnableGRPCReflect  bool   // Probe gRPC reflection service exposure
	EnableH2Reset      bool   // Probe HTTP/2 rapid-reset (CVE-2023-44487); off by default
	EnableCSRF         bool   // Cross-Site Request Forgery probe
	EnableTabnabbing   bool   // Static HTML scan for target=_blank without rel=noopener
	EnableReDoS        bool   // Pathological-input timing probe for ReDoS surfaces
	EnablePromptInj    bool   // LLM prompt-injection probe
	EnableXSLT         bool   // XSLT injection probe
	EnableSAMLInj      bool   // SAML SP malformed-envelope probe
	EnableORMLeak      bool   // ORM expansion / over-fetch probe
	EnableTypeJuggling bool   // PHP loose-equality auth bypass probe (login-shaped paths)
	EnableDepConfusion bool   // Internal-package manifest leak probe
	EnableTokenEntropy bool   // Statistical entropy on Set-Cookie / CSRF tokens

	// Wave-G — multi-step / stateful flows + advanced auth, all default-off
	// because they need explicit URLs (login, refresh, logout, OAuth authorize,
	// password-reset confirm, SSRF param, OpenAPI spec). Wiring them on without
	// the URLs they need would only emit noise.
	EnableTimingEnum       bool // Statistical timing-based account enumeration on LoginURL
	EnablePasswordReset    bool // Reset-link host-header poisoning, cross-user token, replay
	EnableSessionLifecycle bool // Refresh rotation, logout invalidation, concurrent sessions
	EnableOAuthFlow        bool // OAuth state binding, redirect_uri match, PKCE downgrade, alg=none
	EnableDNSRebinding     bool // Short-TTL multi-IP + SSRF allowlist bypass via hostname resolution
	EnableHTTP2Advanced    bool // HPACK pollution, SETTINGS flood, flow-control exhaustion
	EnableOpenAPISemantic  bool // Type coercion, discriminator confusion, nullable-default leaks

	// URLs required by Wave-G detectors. Empty disables the corresponding probe.
	RefreshURL       string
	LogoutURL        string
	ProtectedURL     string // Authenticated resource for session-lifecycle probes
	PasswordResetURL string
	OAuthAuthzURL    string
	OAuthTokenURL    string
	OAuthClientID    string
	OAuthRedirectURI string
	SSRFParam        string // Parameter name carrying the SSRF target URL
	DNSRebindingHost string // Optional attacker-controlled rebinding host

	// Wave-H — gap closures from OWASP API/Top10/WSTG mapping audit.
	EnableSessionFixation bool   // WSTG-SESS-03 pre-auth cookie + query-string session
	EnableStackTrace      bool   // WSTG-ERRH-02 framework stack trace disclosure
	EnableMFABypass       bool   // WSTG-ATHN-11 MFA step-skip, null-OTP, brute force, status tamper
	EnablePaddingOracle   bool   // WSTG-CRYP-02 CBC padding oracle on encrypted tokens
	MFASubmitURL          string // OTP submission endpoint
	PaddingOracleToken    string // sample encrypted token to probe (e.g. extracted cookie value)
	PaddingOracleParam    string // param name carrying the token (e.g. "auth")

	EnableCacheDeception  bool   // Web cache deception (extension/path strip + unauth replay)
	EnableCachePoisoning  bool   // Unkeyed-header reflection cache poisoning
	EnableCSSInj          bool   // CSS injection probe (param-level)
	EnableDeser           bool   // Insecure deserialization probe (param-level, Java/PHP/Python/.NET)
	EnableDOMClobber      bool   // DOM clobbering via named-element injection (param-level)
	EnableEmailInj        bool   // Email header injection (CRLF in mail headers, param-level)
	EnableHPP             bool   // HTTP Parameter Pollution (param-level)
	EnableHTMLInj         bool   // HTML injection (non-XSS tag injection, param-level)
	EnableMassAssign      bool   // Mass-assignment with re-fetch verification (param-level)
	EnableProtoPollServer bool   // Server-side prototype pollution (param-level)
	EnableSecondOrder     bool   // Second-order injection (inject-then-verify)
	EnableSSI             bool   // Server-Side Includes injection (param-level)
	EnableStorage         bool   // Cookie / session management (Secure, HttpOnly, SameSite, entropy)
	EnablePostMsg         bool   // postMessage origin-validation probe (requires Chrome)
	EnableXSLeaks         bool   // Cross-site leak primitive audit (COOP/COEP/CORP + framing + SameSite correlation)
	EnableJWTAdvanced     bool   // Active JWT forgery replay against authenticated endpoints (requires JWTAdvancedToken)
	JWTAdvancedToken      string // Known-valid JWT to forge from. Empty disables the active probe.
	JWTAdvancedParam      string // Optional query-param name to carry the JWT. When empty, Authorization: Bearer is used.
	EnableGraphQLAdvanced bool   // Field-suggestion recovery, APQ bypass, mutation-over-GET CSRF (probes GraphQL-shaped endpoints only)
	EnableHTTP2Desync     bool   // CL.0 desync timing probe + h2c upgrade acceptance (raw TCP; off by default — sends desync payloads)
	EnableCacheKey        bool   // Cache-key parser divergence (semicolon cloaking, dup-param HPP, encoded-slash) — paired-request differential, safe to leave on
	EnableAuthBypass403   bool   // 401/403 access-control bypass via reverse-proxy trust headers and path-encoding tricks — only fires when baseline is 401/403

	// Template scanning
	EnableTemplates bool     // Enable template-based scanning (default false)
	TemplatePaths   []string // Paths to template files or directories
	TemplateTags    []string // Tags to filter templates by

	// Discovery and headless browser settings
	EnableDiscovery     bool   // Auto-discover injectable points (default true)
	EnableStorageInj    bool   // Test storage injection (default false, needs Chrome)
	EnableDOMXSS        bool   // Test DOM-based XSS via headless browser (needs Chrome)
	EnableProtoPoll     bool   // Test client-side prototype pollution via headless browser (needs Chrome)
	EnableDOMRedirect   bool   // Test DOM-based open redirection via headless browser (needs Chrome)
	HeadlessMaxBrowsers int    // Max browser contexts (default 3)
	ChromePath          string // Explicit Chrome binary path

	// Additional configuration for specific detectors
	Subdomains []subtakeover.SubdomainInfo // Subdomain list for takeover detection
	LoginURL   string                      // Login URL for auth testing

	// Two-identity (BOLA) IDOR probe. When AuthA and AuthB are both
	// non-empty the scanner runs idor.DetectCrossIdentity against
	// IDORTargetURL (or the current scan target if empty), reporting
	// when user-A's resource leaks to user-B.
	AuthA         AuthState // identity A (the "victim")
	AuthB         AuthState // identity B (the "attacker")
	IDORTargetURL string    // optional override for the cross-identity probe URL

	// Scan intensity
	MaxPayloadsPerParam int
	IncludeWAFBypass    bool

	// Timeouts
	RequestTimeout time.Duration
	OOBPollTimeout time.Duration

	// Verbosity
	Verbose bool
}

// DefaultInternalConfig returns a reasonable default configuration.
func DefaultInternalConfig() *InternalScanConfig {
	return &InternalScanConfig{
		EnableSQLi:            true,
		EnableXSS:             true,
		EnableCMDI:            true,
		EnableSSRF:            true,
		EnableLFI:             true,
		EnableXXE:             true,
		EnableTechScan:        true,
		EnableOOB:             true, // OOB enabled by default - runs async to not block main scan
		EnableNoSQL:           true,
		EnableSSTI:            true,
		EnableIDOR:            true,
		EnableJWT:             false, // JWT requires token extraction, disable by default
		EnableRedirect:        true,
		EnableCORS:            true,
		EnableCRLF:            true,
		EnableLDAP:            true,
		EnableXPath:           true,
		EnableHeaderInj:       true,
		EnableCSTI:            true,
		EnableRFI:             true,
		EnableJNDI:            true,
		EnableSecHeaders:      true,
		EnableExposure:        true,
		EnableCloud:           true,
		EnableSubTakeover:     false, // Requires subdomain list
		EnableTLS:             true,
		EnableAuth:            false, // Requires login URL
		EnableGraphQL:         true,
		EnableSmuggling:       true,
		EnableBehavior:        true,
		EnableLogInj:          true,
		EnableFileUpload:      true,
		EnableVerbTamper:      true,
		EnablePathNorm:        true,
		EnableRaceCond:        false, // Aggressive, sends many parallel requests
		EnableCSVInj:          true,
		EnableWS:              true,
		EnableHostHdr:         true,
		EnableOAuth:           true,
		EnableJSDep:           true,
		EnableDataExposure:    true,
		EnableAdminPath:       true,
		EnableAPIVersion:      true,
		EnableRateLimit:       false, // off by default — burst probe is mildly load-bearing
		EnableContentType:     true,
		EnableSSE:             true,
		EnableGRPCReflect:     true,
		EnableH2Reset:         false, // off by default — sends raw H/2 frames
		EnableCSRF:            true,
		EnableTabnabbing:      true,
		EnableReDoS:           false, // off by default — adds latency on every regex-shaped param
		EnablePromptInj:       true,
		EnableXSLT:            true,
		EnableSAMLInj:         true,
		EnableORMLeak:         true,
		EnableTypeJuggling:    true,
		EnableDepConfusion:    true,
		EnableTokenEntropy:    true,
		EnableCacheDeception:  true,
		EnableCachePoisoning:  true,
		EnableCSSInj:          true,
		EnableDeser:           true,
		EnableDOMClobber:      true,
		EnableEmailInj:        true,
		EnableHPP:             true,
		EnableHTMLInj:         true,
		EnableMassAssign:      false, // mutates state — opt-in via --no-mass-assign=false
		EnableProtoPollServer: false, // mutates request shape — opt-in
		EnableSecondOrder:     true,
		EnableSSI:             true,
		EnableStorage:         true,
		EnablePostMsg:         true, // requires Chrome — no-op when unavailable
		EnableXSLeaks:         true,
		EnableJWTAdvanced:     true, // no-op without JWTAdvancedToken — safe everywhere
		EnableGraphQLAdvanced: true, // no-op when the response is not GraphQL-shaped — safe everywhere
		EnableHTTP2Desync:     false, // off by default — sends raw TCP desync payloads
		EnableCacheKey:        true,
		EnableAuthBypass403:   true, // self-gates on 401/403 baseline; harmless on public URLs

		EnableTimingEnum:       true,
		EnablePasswordReset:    true,
		EnableSessionLifecycle: true,
		EnableOAuthFlow:        true,
		EnableDNSRebinding:     true,
		EnableHTTP2Advanced:    false, // off — H/2 frame manipulation can be destructive
		EnableOpenAPISemantic:  true,
		// Wave-H default-on flags but no-op without URLs / tokens; safe everywhere.
		EnableSessionFixation: true,
		EnableStackTrace:      true,
		EnableMFABypass:       true,
		EnablePaddingOracle:   true,
		EnableDiscovery:       true,
		EnableStorageInj:      false, // Requires Chrome
		EnableDOMXSS:          true,  // Requires Chrome (no-op when unavailable)
		EnableProtoPoll:       true,  // Requires Chrome (no-op when unavailable)
		EnableDOMRedirect:     true,  // Requires Chrome (no-op when unavailable)
		HeadlessMaxBrowsers:   3,
		MaxPayloadsPerParam:   30,
		IncludeWAFBypass:      true,
		RequestTimeout:        10 * time.Second,
		OOBPollTimeout:        10 * time.Second,
		Verbose:               false,
	}
}
