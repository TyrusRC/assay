package techstack

import (
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// CVEEntry represents a known CVE for a technology.
type CVEEntry struct {
	ID          string
	Description string
	Severity    string  // critical, high, medium, low
	CVSS        float64
	FixedIn     string // version where the CVE was fixed (empty = check all)
}

// CorrelateCVEs maps detected technologies to known CVEs and returns findings.
func CorrelateCVEs(result *DetectionResult, targetURL string) []*core.Finding {
	if result == nil {
		return nil
	}
	var findings []*core.Finding
	for _, tech := range result.Technologies {
		key := strings.ToLower(tech.Name)
		entries, ok := techCVEDatabase[key]
		if !ok {
			continue
		}
		for _, cve := range entries {
			sev := mapSeverity(cve.Severity)
			f := core.NewFinding(
				fmt.Sprintf("Known CVE: %s in %s", cve.ID, tech.Name),
				sev,
			)
			f.URL = targetURL
			f.Description = fmt.Sprintf("%s %s — %s (CVSS %.1f)", tech.String(), cve.ID, cve.Description, cve.CVSS)
			f.Tool = "techstack-cve-correlator"
			f.Confidence = core.ConfidenceMedium
			f.CVSS = cve.CVSS
			f.CWE = []string{"CWE-1395"}
			f.References = []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID)}
			f.Remediation = fmt.Sprintf("Upgrade %s to a patched version.", tech.Name)
			f.WithOWASPMapping(
				[]string{"WSTG-INFO-02"},
				[]string{"A06:2025"},
				[]string{"CWE-1395"},
			)
			findings = append(findings, f)
		}
	}
	return findings
}

func mapSeverity(s string) core.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return core.SeverityCritical
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	default:
		return core.SeverityMedium
	}
}

// techCVEDatabase maps lowercase technology names to known CVEs.
// Covers the most impactful web-technology CVEs across 35+ stacks.
var techCVEDatabase = map[string][]CVEEntry{
	// ── Web Servers ──
	"nginx": {
		{ID: "CVE-2021-23017", Description: "DNS resolver off-by-one heap write", Severity: "critical", CVSS: 9.4},
		{ID: "CVE-2022-41741", Description: "Memory corruption in mp4 module", Severity: "high", CVSS: 7.8},
		{ID: "CVE-2024-7347", Description: "Worker process crash via mp4 module", Severity: "medium", CVSS: 4.7},
	},
	"apache": {
		{ID: "CVE-2021-41773", Description: "Path traversal and file disclosure in 2.4.49", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2021-42013", Description: "Path traversal and RCE in 2.4.50", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2023-25690", Description: "HTTP request smuggling via mod_proxy", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2024-38476", Description: "SSRF via mod_rewrite with unsafe RewriteRules", Severity: "critical", CVSS: 9.8},
	},
	"apache http server": {
		{ID: "CVE-2021-41773", Description: "Path traversal and file disclosure in 2.4.49", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2021-42013", Description: "Path traversal and RCE in 2.4.50", Severity: "critical", CVSS: 9.8},
	},
	"iis": {
		{ID: "CVE-2021-31166", Description: "HTTP protocol stack RCE (wormable)", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2022-21907", Description: "HTTP protocol stack RCE via trailer", Severity: "critical", CVSS: 9.8},
	},
	"microsoft iis": {
		{ID: "CVE-2021-31166", Description: "HTTP protocol stack RCE (wormable)", Severity: "critical", CVSS: 9.8},
	},

	// ── Frameworks — Python ──
	"flask": {
		{ID: "CVE-2023-30861", Description: "Cookie parsing vulnerability leaks session data", Severity: "high", CVSS: 7.5},
		{ID: "CVE-2024-49767", Description: "Denial of service via multipart form data", Severity: "high", CVSS: 7.5},
	},
	"django": {
		{ID: "CVE-2023-36053", Description: "ReDoS via EmailValidator and URLValidator", Severity: "high", CVSS: 7.5},
		{ID: "CVE-2024-24680", Description: "DoS via intcomma template filter", Severity: "high", CVSS: 7.5},
		{ID: "CVE-2024-39614", Description: "DoS via get_supported_language_variant", Severity: "high", CVSS: 7.5},
	},
	"werkzeug": {
		{ID: "CVE-2023-25577", Description: "Debugger console arbitrary code execution when exposed", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2023-23934", Description: "Cookie parsing vulnerability allows value injection", Severity: "medium", CVSS: 3.5},
	},
	"tornado": {
		{ID: "CVE-2023-28370", Description: "Open redirect via header injection", Severity: "medium", CVSS: 6.1},
	},

	// ── Frameworks — JavaScript ──
	"express": {
		{ID: "CVE-2024-29041", Description: "Open redirect in res.location and res.redirect", Severity: "medium", CVSS: 6.1},
	},
	"next.js": {
		{ID: "CVE-2024-34351", Description: "SSRF via Server Actions", Severity: "high", CVSS: 7.5},
		{ID: "CVE-2025-29927", Description: "Authorization bypass via x-middleware-subrequest header", Severity: "critical", CVSS: 9.1},
	},
	"nuxt": {
		{ID: "CVE-2023-3224", Description: "RCE via server API route", Severity: "critical", CVSS: 9.8},
	},
	"angular": {
		{ID: "CVE-2024-38996", Description: "Prototype pollution via merge operation", Severity: "critical", CVSS: 9.8},
	},
	"vue.js": {
		{ID: "CVE-2024-6783", Description: "XSS via v-bind with user input", Severity: "medium", CVSS: 6.1},
	},
	"react": {
		{ID: "CVE-2025-29927", Description: "Applies to Next.js apps using React — auth bypass via middleware header", Severity: "critical", CVSS: 9.1},
	},

	// ── Frameworks — Java ──
	"spring": {
		{ID: "CVE-2022-22965", Description: "Spring4Shell — RCE via class loader manipulation", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2022-22963", Description: "Spring Cloud Function RCE via routing", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2024-22243", Description: "Open redirect in UriComponentsBuilder", Severity: "high", CVSS: 8.1},
	},
	"spring boot": {
		{ID: "CVE-2022-22965", Description: "Spring4Shell RCE", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2023-20883", Description: "DoS via Spring Boot welcome page", Severity: "high", CVSS: 7.5},
	},
	"apache struts": {
		{ID: "CVE-2017-5638", Description: "S2-045 OGNL injection RCE via Content-Type", Severity: "critical", CVSS: 10.0},
		{ID: "CVE-2023-50164", Description: "File upload path traversal leading to RCE", Severity: "critical", CVSS: 9.8},
	},
	"apache tomcat": {
		{ID: "CVE-2024-50379", Description: "RCE via partial PUT and case-insensitive paths on Windows", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2024-52316", Description: "Authentication bypass via Jakarta Authentication", Severity: "critical", CVSS: 9.8},
	},

	// ── Frameworks — Ruby ──
	"ruby on rails": {
		{ID: "CVE-2023-22795", Description: "ReDoS via Action Dispatch MIME type", Severity: "high", CVSS: 7.5},
		{ID: "CVE-2024-26143", Description: "XSS via Accept header in development error page", Severity: "medium", CVSS: 6.1},
	},

	// ── Frameworks — PHP ──
	"laravel": {
		{ID: "CVE-2024-29291", Description: "RCE via insecure deserialization in debug mode", Severity: "critical", CVSS: 9.8},
	},
	"php": {
		{ID: "CVE-2024-4577", Description: "CGI argument injection leading to RCE", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2024-2961", Description: "Buffer overflow in iconv glibc linked to PHP", Severity: "high", CVSS: 8.8},
	},

	// ── CMS ──
	"wordpress": {
		{ID: "CVE-2023-2982", Description: "Social Login auth bypass via SQL injection", Severity: "critical", CVSS: 9.8},
		{ID: "CVE-2024-27956", Description: "SQL injection via WP-Automatic plugin", Severity: "critical", CVSS: 9.9},
	},
	"drupal": {
		{ID: "CVE-2018-7600", Description: "Drupalgeddon2 — RCE via AJAX rendering", Severity: "critical", CVSS: 9.8},
	},
	"joomla": {
		{ID: "CVE-2023-23752", Description: "Unauthenticated information disclosure", Severity: "medium", CVSS: 5.3},
	},

	// ── JavaScript Libraries ──
	"jquery": {
		{ID: "CVE-2020-11022", Description: "XSS via HTML manipulation in .html() and .append()", Severity: "medium", CVSS: 6.1},
		{ID: "CVE-2020-11023", Description: "XSS via passing HTML containing option to DOM methods", Severity: "medium", CVSS: 6.1},
	},
	"lodash": {
		{ID: "CVE-2021-23337", Description: "Command injection via template function", Severity: "high", CVSS: 7.2},
		{ID: "CVE-2020-28500", Description: "ReDoS via toNumber and trim", Severity: "medium", CVSS: 5.3},
	},

	// ── Databases ──
	"mongodb": {
		{ID: "CVE-2024-1351", Description: "Authentication bypass via SCRAM-SHA-256", Severity: "critical", CVSS: 9.1},
	},
	"postgresql": {
		{ID: "CVE-2024-10979", Description: "Arbitrary code execution via environment variable", Severity: "high", CVSS: 8.8},
	},
	"mysql": {
		{ID: "CVE-2024-21047", Description: "Server crash via optimizer", Severity: "medium", CVSS: 4.9},
	},
	"redis": {
		{ID: "CVE-2022-0543", Description: "Lua sandbox escape leading to RCE", Severity: "critical", CVSS: 10.0},
		{ID: "CVE-2023-28856", Description: "DoS via HINCRBYFLOAT command", Severity: "medium", CVSS: 6.5},
	},
	"elasticsearch": {
		{ID: "CVE-2023-31419", Description: "Stack overflow via deeply nested query", Severity: "high", CVSS: 7.5},
	},

	// ── Middleware / Services ──
	"graphql": {
		{ID: "CVE-2023-26144", Description: "GraphQL-js ReDoS via deeply nested queries", Severity: "high", CVSS: 7.5},
	},
	"apollo": {
		{ID: "CVE-2023-30558", Description: "Apollo Server CSRF bypass via content-type header", Severity: "medium", CVSS: 5.3},
	},
	"hasura": {
		{ID: "CVE-2023-39508", Description: "Admin secret exposure via error messages", Severity: "critical", CVSS: 8.8},
	},

	// ── Logging / Infra ──
	"log4j": {
		{ID: "CVE-2021-44228", Description: "Log4Shell — RCE via JNDI lookup in log messages", Severity: "critical", CVSS: 10.0},
		{ID: "CVE-2021-45046", Description: "Log4Shell bypass — RCE despite 2.15.0 fix", Severity: "critical", CVSS: 9.0},
	},

	// ── Node.js runtime ──
	"node.js": {
		{ID: "CVE-2024-22019", Description: "HTTP request smuggling via chunk extension parsing", Severity: "high", CVSS: 7.5},
		{ID: "CVE-2024-22025", Description: "DoS via Fetch API", Severity: "medium", CVSS: 6.5},
	},

	// ── Python runtime ──
	"python": {
		{ID: "CVE-2023-24329", Description: "URL parsing bypass via blank URL schemes", Severity: "high", CVSS: 7.5},
	},

	// ── Ruby runtime ──
	"ruby": {
		{ID: "CVE-2024-27281", Description: "Buffer overread in StringIO", Severity: "medium", CVSS: 4.0},
	},
}
