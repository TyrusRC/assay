package scanner

import (
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/subtakeover"
)

// InternalScanConfig configures the internal scanner behavior.
type InternalScanConfig struct {
	// Enable/disable specific checks
	EnableSQLi        bool
	EnableXSS         bool
	EnableCMDI        bool
	EnableSSRF        bool
	EnableLFI         bool
	EnableXXE         bool
	EnableTechScan    bool
	EnableOOB         bool
	EnableNoSQL       bool
	EnableSSTI        bool
	EnableIDOR        bool
	EnableJWT         bool
	EnableRedirect    bool
	EnableCORS        bool
	EnableCRLF        bool
	EnableLDAP        bool
	EnableXPath       bool
	EnableHeaderInj   bool
	EnableCSTI        bool
	EnableRFI         bool
	EnableJNDI        bool
	EnableSecHeaders  bool
	EnableExposure    bool
	EnableCloud       bool
	EnableSubTakeover bool
	EnableTLS         bool
	EnableAuth        bool
	EnableGraphQL     bool
	EnableSmuggling   bool
	EnableBehavior    bool
	EnableLogInj      bool
	EnableFileUpload  bool
	EnableVerbTamper  bool
	EnablePathNorm    bool
	EnableRaceCond    bool
	EnableCSVInj      bool
	EnableWS          bool
	EnableHostHdr     bool
	EnableOAuth       bool
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

	EnableCacheDeception  bool // Web cache deception (extension/path strip + unauth replay)
	EnableCachePoisoning  bool // Unkeyed-header reflection cache poisoning
	EnableCSSInj          bool // CSS injection probe (param-level)
	EnableDeser           bool // Insecure deserialization probe (param-level, Java/PHP/Python/.NET)
	EnableDOMClobber      bool // DOM clobbering via named-element injection (param-level)
	EnableEmailInj        bool // Email header injection (CRLF in mail headers, param-level)
	EnableHPP             bool // HTTP Parameter Pollution (param-level)
	EnableHTMLInj         bool // HTML injection (non-XSS tag injection, param-level)
	EnableMassAssign      bool // Mass-assignment with re-fetch verification (param-level)
	EnableProtoPollServer bool // Server-side prototype pollution (param-level)
	EnableSecondOrder     bool // Second-order injection (inject-then-verify)
	EnableSSI             bool // Server-Side Includes injection (param-level)
	EnableStorage         bool // Cookie / session management (Secure, HttpOnly, SameSite, entropy)
	EnablePostMsg         bool // postMessage origin-validation probe (requires Chrome)

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
