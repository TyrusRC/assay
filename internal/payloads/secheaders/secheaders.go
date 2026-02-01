// Package secheaders provides security header definitions and best practices.
package secheaders

// Severity indicates the security impact.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

// HeaderCheck represents a security header check.
type HeaderCheck struct {
	Name          string
	Severity      Severity
	Description   string
	Remediation   string
	Required      bool
	ValidValues   []string // Valid header values (if specific values required)
	InvalidValues []string // Known insecure values
	References    []string
	CWE           []string
}

var headerChecks = []HeaderCheck{
	{
		Name:          "X-Frame-Options",
		Severity:      SeverityMedium,
		Description:   "Protects against clickjacking attacks by controlling whether the page can be embedded in frames",
		Remediation:   "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking attacks",
		Required:      true,
		ValidValues:   []string{"DENY", "SAMEORIGIN"},
		InvalidValues: []string{"ALLOW-FROM"},
		References:    []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"},
		CWE:           []string{"CWE-1021"},
	},
	{
		Name:        "X-Content-Type-Options",
		Severity:    SeverityMedium,
		Description: "Prevents MIME type sniffing attacks",
		Remediation: "Set X-Content-Type-Options to 'nosniff' to prevent MIME type sniffing",
		Required:    true,
		ValidValues: []string{"nosniff"},
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"},
		CWE:         []string{"CWE-16"},
	},
	{
		Name:          "Content-Security-Policy",
		Severity:      SeverityHigh,
		Description:   "Prevents XSS, clickjacking, and other code injection attacks by specifying allowed content sources",
		Remediation:   "Implement a Content-Security-Policy header with strict source restrictions. Avoid 'unsafe-inline' and 'unsafe-eval'",
		Required:      true,
		InvalidValues: []string{"unsafe-inline", "unsafe-eval", "*"},
		References:    []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
		CWE:           []string{"CWE-79"},
	},
	{
		Name:        "Strict-Transport-Security",
		Severity:    SeverityHigh,
		Description: "Enforces HTTPS connections and prevents protocol downgrade attacks",
		Remediation: "Set Strict-Transport-Security with a max-age of at least 31536000 (1 year). Consider adding includeSubDomains and preload",
		Required:    true,
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
		CWE:         []string{"CWE-319"},
	},
	{
		Name:          "X-XSS-Protection",
		Severity:      SeverityLow,
		Description:   "Legacy XSS filter (deprecated in modern browsers but still recommended for older browsers)",
		Remediation:   "Set X-XSS-Protection to '1; mode=block' or '0' (if CSP is properly configured)",
		Required:      false,
		ValidValues:   []string{"1; mode=block", "0"},
		InvalidValues: []string{"1"},
		References:    []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"},
		CWE:           []string{"CWE-79"},
	},
	{
		Name:          "Referrer-Policy",
		Severity:      SeverityMedium,
		Description:   "Controls how much referrer information is sent with requests",
		Remediation:   "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer' to limit referrer information leakage",
		Required:      true,
		ValidValues:   []string{"no-referrer", "no-referrer-when-downgrade", "strict-origin", "strict-origin-when-cross-origin", "same-origin"},
		InvalidValues: []string{"unsafe-url"},
		References:    []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"},
		CWE:           []string{"CWE-200"},
	},
	{
		Name:        "Permissions-Policy",
		Severity:    SeverityMedium,
		Description: "Controls which browser features can be used (formerly Feature-Policy)",
		Remediation: "Implement Permissions-Policy to restrict access to sensitive browser APIs like camera, microphone, geolocation",
		Required:    false,
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"},
		CWE:         []string{"CWE-16"},
	},
	{
		Name:        "Cache-Control",
		Severity:    SeverityMedium,
		Description: "Controls caching behavior to prevent sensitive data from being cached",
		Remediation: "For sensitive pages, set Cache-Control to 'no-store, no-cache, must-revalidate, private'",
		Required:    false,
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"},
		CWE:         []string{"CWE-525"},
	},
	{
		Name:        "Cross-Origin-Embedder-Policy",
		Severity:    SeverityMedium,
		Description: "Prevents loading of cross-origin resources without explicit permission",
		Remediation: "Set Cross-Origin-Embedder-Policy to 'require-corp' for enhanced isolation",
		Required:    false,
		ValidValues: []string{"require-corp", "credentialless"},
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"},
		CWE:         []string{"CWE-16"},
	},
	{
		Name:        "Cross-Origin-Opener-Policy",
		Severity:    SeverityMedium,
		Description: "Controls window interactions between origins",
		Remediation: "Set Cross-Origin-Opener-Policy to 'same-origin' to prevent cross-origin attacks",
		Required:    false,
		ValidValues: []string{"same-origin", "same-origin-allow-popups"},
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"},
		CWE:         []string{"CWE-16"},
	},
	{
		Name:        "Cross-Origin-Resource-Policy",
		Severity:    SeverityMedium,
		Description: "Prevents other origins from loading the resource",
		Remediation: "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site' to prevent unauthorized resource loading",
		Required:    false,
		ValidValues: []string{"same-origin", "same-site", "cross-origin"},
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"},
		CWE:         []string{"CWE-16"},
	},
}

// InsecureHeader represents a header that should NOT be present or has insecure values.
type InsecureHeader struct {
	Name        string
	Severity    Severity
	Description string
	Remediation string
	InsecureIf  []string // Header is insecure if it contains any of these
	References  []string
	CWE         []string
}

var insecureHeaders = []InsecureHeader{
	{
		Name:        "Server",
		Severity:    SeverityLow,
		Description: "Server banner reveals software version information",
		Remediation: "Remove or obfuscate the Server header to prevent information disclosure",
		References:  []string{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"},
		CWE:         []string{"CWE-200"},
	},
	{
		Name:        "X-Powered-By",
		Severity:    SeverityLow,
		Description: "Reveals the technology/framework powering the application",
		Remediation: "Remove the X-Powered-By header to prevent information disclosure",
		References:  []string{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"},
		CWE:         []string{"CWE-200"},
	},
	{
		Name:        "X-AspNet-Version",
		Severity:    SeverityLow,
		Description: "Reveals the ASP.NET version",
		Remediation: "Remove the X-AspNet-Version header in web.config",
		References:  []string{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"},
		CWE:         []string{"CWE-200"},
	},
	{
		Name:        "X-AspNetMvc-Version",
		Severity:    SeverityLow,
		Description: "Reveals the ASP.NET MVC version",
		Remediation: "Remove the X-AspNetMvc-Version header",
		References:  []string{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"},
		CWE:         []string{"CWE-200"},
	},
}

// GetHeaderChecks returns all security header checks.
func GetHeaderChecks() []HeaderCheck {
	return headerChecks
}

// GetRequiredHeaders returns only required security headers.
func GetRequiredHeaders() []HeaderCheck {
	var result []HeaderCheck
	for _, h := range headerChecks {
		if h.Required {
			result = append(result, h)
		}
	}
	return result
}

// GetInsecureHeaders returns headers that indicate information disclosure.
func GetInsecureHeaders() []InsecureHeader {
	return insecureHeaders
}

// GetHeaderCheckByName returns a specific header check by name.
func GetHeaderCheckByName(name string) *HeaderCheck {
	for _, h := range headerChecks {
		if h.Name == name {
			return &h
		}
	}
	return nil
}
