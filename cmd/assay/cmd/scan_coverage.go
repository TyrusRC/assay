package cmd

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

// printCoverageSummary prints what was tested, what was skipped, and why.
// This makes a zero-flag scan trustworthy: the result is never silently
// incomplete — the user sees exactly what coverage they got.
func printCoverageSummary(result *scanner.ScanResult, cfg *scanner.InternalScanConfig) {
	w := os.Stderr

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Coverage Summary")
	fmt.Fprintln(w, "────────────────")

	// Targets and findings
	fmt.Fprintf(w, "  Targets scanned:    %d\n", len(result.Targets))
	findingCounts := result.Findings.CountBySeverity()
	total := result.Findings.Count()
	fmt.Fprintf(w, "  Findings:           %d total", total)
	if total > 0 {
		sevOrder := []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}
		parts := []string{}
		for _, sev := range sevOrder {
			if c, ok := findingCounts[sev]; ok && c > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", c, string(sev)))
			}
		}
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w, "")

	// Tools run
	fmt.Fprintf(w, "  Tools run:          %d", result.ToolsRun)
	if result.ToolsSkipped > 0 {
		fmt.Fprintf(w, " (%d skipped — binary not on PATH)", result.ToolsSkipped)
	}
	fmt.Fprintln(w, "")

	// Active detector classes
	active, skippedOpt, skippedNoURL := classifyCoverage(cfg)
	fmt.Fprintf(w, "  Detector classes:   %d active\n", len(active))

	// Skipped: opt-in (destructive)
	if len(skippedOpt) > 0 {
		fmt.Fprintf(w, "  Skipped (opt-in):   %s\n", strings.Join(skippedOpt, ", "))
	}

	// Skipped: no URL provided
	if len(skippedNoURL) > 0 {
		fmt.Fprintf(w, "  Skipped (no URL):   %s\n", strings.Join(skippedNoURL, ", "))
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "  Errors:             %d\n", len(result.Errors))
	}

	fmt.Fprintln(w, "")
}

// classifyCoverage reads the InternalScanConfig and reports which
// detector classes are active, which are off because they're opt-in
// (destructive/load-bearing), and which are off because they need a
// URL the user didn't provide.
func classifyCoverage(cfg *scanner.InternalScanConfig) (active, skippedOpt, skippedNoURL []string) {
	// Map config fields to human-readable class names.
	type entry struct {
		field   string
		name    string
		optIn   bool   // true = destructive, needs explicit opt-in
		needURL string // non-empty = needs this URL field to be set
	}

	entries := []entry{
		{"EnableSQLi", "sqli", false, ""},
		{"EnableXSS", "xss", false, ""},
		{"EnableCMDI", "cmdi", false, ""},
		{"EnableSSRF", "ssrf", false, ""},
		{"EnableLFI", "lfi", false, ""},
		{"EnableXXE", "xxe", false, ""},
		{"EnableNoSQL", "nosql", false, ""},
		{"EnableSSTI", "ssti", false, ""},
		{"EnableIDOR", "idor", false, ""},
		{"EnableBAC", "bac", false, ""},
		{"EnableJWT", "jwt", false, ""},
		{"EnableRedirect", "open-redirect", false, ""},
		{"EnableCORS", "cors", false, ""},
		{"EnableCRLF", "crlf", false, ""},
		{"EnableLDAP", "ldap", false, ""},
		{"EnableXPath", "xpath", false, ""},
		{"EnableHeaderInj", "header-injection", false, ""},
		{"EnableCSTI", "csti", false, ""},
		{"EnableRFI", "rfi", false, ""},
		{"EnableJNDI", "jndi", false, ""},
		{"EnableSecHeaders", "security-headers", false, ""},
		{"EnableExposure", "exposure", false, ""},
		{"EnableCloud", "cloud", false, ""},
		{"EnableTLS", "tls", false, ""},
		{"EnableGraphQL", "graphql", false, ""},
		{"EnableSmuggling", "smuggling", false, ""},
		{"EnableBehavior", "behavior", false, ""},
		{"EnableLogInj", "log-injection", false, ""},
		{"EnableFileUpload", "file-upload", false, ""},
		{"EnableVerbTamper", "verb-tamper", false, ""},
		{"EnablePathNorm", "path-normalization", false, ""},
		{"EnableCSVInj", "csv-injection", false, ""},
		{"EnableHostHdr", "host-header", false, ""},
		{"EnableOAuth", "oauth", false, ""},
		{"EnableJSDep", "js-dependency-audit", false, ""},
		{"EnableDataExposure", "data-exposure", false, ""},
		{"EnableAdminPath", "admin-path", false, ""},
		{"EnableAPIVersion", "api-version", false, ""},
		{"EnableContentType", "content-type", false, ""},
		{"EnableSSE", "sse", false, ""},
		{"EnableGRPCReflect", "grpc-reflect", false, ""},
		{"EnableCSRF", "csrf", false, ""},
		{"EnableTabnabbing", "tabnabbing", false, ""},
		{"EnableCSPT", "cspt", false, ""},
		{"EnablePromptInj", "prompt-injection", false, ""},
		{"EnableXSLT", "xslt", false, ""},
		{"EnableSAMLInj", "saml", false, ""},
		{"EnableORMLeak", "orm-leak", false, ""},
		{"EnableTypeJuggling", "type-juggling", false, ""},
		{"EnableDepConfusion", "dep-confusion", false, ""},
		{"EnableTokenEntropy", "token-entropy", false, ""},
		{"EnableCacheDeception", "cache-deception", false, ""},
		{"EnableCSSInj", "css-injection", false, ""},
		{"EnableDeser", "deserialization", false, ""},
		{"EnableDOMClob", "dom-clobber", false, ""},
		{"EnableEmailInj", "email-injection", false, ""},
		{"EnableHPP", "hpp", false, ""},
		{"EnableHTMLInj", "html-injection", false, ""},
		{"EnableSecondOrder", "second-order", false, ""},
		{"EnableSSI", "ssi", false, ""},
		{"EnableStorage", "session-mgmt", false, ""},
		{"EnableStoredXSS", "stored-xss", false, ""},
		{"EnableSessionFixation", "session-fixation", false, ""},
		{"EnableStackTrace", "stack-trace", false, ""},
		{"EnablePaddingOracle", "padding-oracle", false, ""},

		// Opt-in (destructive or load-bearing)
		{"EnableRaceCond", "race-condition", true, ""},
		{"EnableCachePoisoning", "cache-poisoning", true, ""},
		{"EnableMassAssign", "mass-assignment", true, ""},
		{"EnableProtoPollServer", "proto-pollution-server", true, ""},
		{"EnableRateLimit", "rate-limit-probe", true, ""},
		{"EnableH2Reset", "h2-rapid-reset", true, ""},
		{"EnableH2Continue", "h2-continuation", true, ""},
		{"EnableH2MadeReset", "h2-madeyoureset", true, ""},
		{"EnableReDoS", "redos", true, ""},

		// Needs a URL
		{"EnableAuth", "auth", false, "LoginURL"},
		{"EnableTimingEnum", "timing-enum", false, "LoginURL"},
		{"EnablePasswordReset", "password-reset", false, "PasswordResetURL"},
		{"EnableSessionLifecycle", "session-lifecycle", false, "RefreshURL"},
		{"EnableOAuthFlow", "oauth-flow", false, "OAuthAuthzURL"},
		{"EnableDNSRebinding", "dns-rebinding", false, "DNSRebindingHost"},
		{"EnableMFABypass", "mfa-bypass", false, "MFASubmitURL"},
		{"EnableSubTakeover", "subdomain-takeover", false, ""},
	}

	v := reflect.ValueOf(cfg).Elem()
	for _, e := range entries {
		field := v.FieldByName(e.field)
		if !field.IsValid() || field.Kind() != reflect.Bool {
			continue
		}
		if field.Bool() {
			active = append(active, e.name)
		} else if e.optIn {
			skippedOpt = append(skippedOpt, e.name)
		} else if e.needURL != "" {
			urlField := v.FieldByName(e.needURL)
			if urlField.IsValid() && urlField.Kind() == reflect.String && urlField.String() == "" {
				skippedNoURL = append(skippedNoURL, e.name)
			}
		}
	}

	sort.Strings(active)
	sort.Strings(skippedOpt)
	sort.Strings(skippedNoURL)
	return
}
