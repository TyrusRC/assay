package cmd

import (
	"time"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan [target URL]",
	Short: "Scan a target URL for vulnerabilities",
	Long: `Scan a target URL using configured security tools.

The scan will run all available tools against the target and aggregate
the results. Findings are mapped to OWASP frameworks for easy classification.

Examples:
  # Basic scan
  assay scan https://example.com/page?id=1

  # Scan with custom headers
  assay scan -H "Authorization: Bearer token" https://example.com

  # Scan POST endpoint
  assay scan -X POST -d "username=admin" https://example.com/login

  # Aggressive scan (level 5, risk 3)
  assay scan --level 5 --risk 3 https://example.com/page?id=1

  # Scan from a target list file
  assay scan -l targets.txt

  # Scan from stdin
  cat targets.txt | assay scan

`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", 30*time.Minute, "Scan timeout")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 3, "Number of concurrent tools")
	scanCmd.Flags().StringArrayVar(&onlyTests, "test", nil, "Run only these detector classes (repeatable: --test sqli --test cmdi)")
	scanCmd.Flags().StringArrayVar(&onlyParams, "param", nil, "Test only these parameter names (repeatable: --param username --param password)")
	scanCmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Custom headers (can be specified multiple times)")
	scanCmd.Flags().StringVar(&cookies, "cookie", "", "Cookie string")
	scanCmd.Flags().StringVarP(&userAgent, "user-agent", "A", "", "Custom User-Agent for ALL scanner traffic")
	scanCmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "Skip TLS certificate verification (needed when --proxy intercepts HTTPS, e.g. Burp Suite)")
	scanCmd.Flags().StringVarP(&data, "data", "d", "", "POST data")
	scanCmd.Flags().StringVarP(&method, "method", "X", "GET", "HTTP method")
	scanCmd.Flags().IntVar(&level, "level", 1, "Scan level (1-5)")
	scanCmd.Flags().IntVar(&risk, "risk", 1, "Risk level (1-3)")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVar(&htmlOutput, "html", false, "Output results as HTML report")
	scanCmd.Flags().StringVar(&formatList, "format", "", "Comma-separated report formats: text,json,html,csv,md,sarif,junit,gitlab")
	scanCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to write report files (required for multiple formats)")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit non-zero (code 2) if any finding is at or above this severity: critical,high,medium,low (default: never fail)")
	scanCmd.Flags().StringVar(&configPath, "config", "", "Path to a YAML config file (auto-detects assay.yaml in the working dir); CLI flags override file values")
	scanCmd.Flags().StringVar(&loginURL, "login-url", "", "URL of an HTML login form; assay logs in and scans with the captured session")
	scanCmd.Flags().StringVar(&loginUser, "login-user", "", "Username to submit to the login form")
	scanCmd.Flags().StringVar(&loginPass, "login-pass", "", "Password to submit to the login form")
	scanCmd.Flags().StringVar(&loginUserField, "login-user-field", "", "Login form username field name (auto-detected if empty)")
	scanCmd.Flags().StringVar(&loginPassField, "login-pass-field", "", "Login form password field name (auto-detected if empty)")
	scanCmd.Flags().StringVar(&loginSuccess, "login-success", "", "Substring expected in the post-login response to confirm success")
	scanCmd.Flags().BoolVar(&loginHeadless, "login-headless", false, "Log in via a real browser (for SPA/JS logins); --login-user-field/--login-pass-field act as CSS selectors")
	scanCmd.Flags().StringVar(&lsrPath, "lsr", "", "Login sequence recording file (JSON) — multi-step login with session-alive detection and URL restrictions")
	scanCmd.Flags().StringVar(&baselinePath, "baseline", "", "Prior assay JSON report to diff against; prints new/fixed findings")
	scanCmd.Flags().BoolVar(&failOnNew, "fail-on-new", false, "With --baseline and --fail-on, gate only on findings new since the baseline")
	scanCmd.Flags().BoolVar(&verifyFindings, "verify", false, "Safely re-exercise findings to confirm them, upgrading reproduced findings to 'confirmed' (proof-based scanning)")
	scanCmd.Flags().StringVar(&complianceSpec, "compliance", "", "Emit a compliance assessment mapping findings to controls: pci-dss,hipaa,iso-27001 (comma-separated or 'all'). Written to --output-dir or stdout")
	scanCmd.Flags().StringVar(&githubRepo, "github-repo", "", "File findings as GitHub issues in owner/name (token from GITHUB_TOKEN)")
	scanCmd.Flags().StringVar(&jiraURL, "jira-url", "", "File findings as Jira issues at this site URL (auth from JIRA_EMAIL/JIRA_TOKEN)")
	scanCmd.Flags().StringVar(&jiraProject, "jira-project", "", "Jira project key for --jira-url (e.g. SEC)")
	scanCmd.Flags().StringVar(&exportMinSev, "export-min-severity", "high", "Minimum severity to export as issues: critical,high,medium,low")
	scanCmd.Flags().BoolVar(&exportDryRun, "export-dry-run", false, "Preview the issues that would be filed without sending them")
	scanCmd.Flags().BoolVar(&disableOOB, "no-oob", false, "Disable Out-of-Band (OOB) testing for blind vulnerabilities")
	scanCmd.Flags().BoolVar(&noDiscovery, "no-discovery", false, "Disable auto-discovery of injectable parameters")
	scanCmd.Flags().BoolVar(&storageInj, "storage-inj", false, "Enable client-side storage injection testing (requires Chrome)")
	scanCmd.Flags().StringVar(&chromePath, "chrome-path", "", "Explicit Chrome/Chromium binary path for headless testing")
	scanCmd.Flags().BoolVar(&crawl, "crawl", false, "Crawl same-origin SPA routes via headless browser and scan them too (requires Chrome)")
	scanCmd.Flags().BoolVar(&crawlStates, "crawl-states", false, "State-aware HTTP crawl (no browser): expand scan targets by following links/forms, deduping by page-state fingerprint")
	scanCmd.Flags().IntVar(&crawlDepth, "crawl-depth", 1, "Max BFS depth from each seed when --crawl is set (0 = seed page only)")
	scanCmd.Flags().IntVar(&crawlPages, "crawl-max-pages", 25, "Max pages to navigate when --crawl is set")
	scanCmd.Flags().BoolVar(&submitForms, "submit-forms", false, "Submit discovered forms with test data during crawl to discover post-auth pages (opt-in, may change application state)")
	scanCmd.Flags().StringVarP(&targetList, "list", "l", "", "File containing target URLs (one per line)")
	scanCmd.Flags().StringArrayVar(&templateDirs, "templates", nil, "Nuclei-style template directory or file (repeatable: pass once per path to load the default store + your custom templates together, e.g. --templates ~/nuclei-templates --templates ~/custom-nuclei-templates)")
	scanCmd.Flags().StringVar(&profile, "profile", "", "Scan profile (quick, normal, thorough, passive)")
	scanCmd.Flags().BoolVar(&noJSDep, "no-jsdep", false, "Disable JS dependency / NVD CVE lookup")
	scanCmd.Flags().StringVar(&nvdAPIKey, "nvd-api-key", "", "NVD CVE API key (raises rate limit ~5→50 req/30s; falls back to NVD_API_KEY env)")
	scanCmd.Flags().BoolVar(&rateLimit, "rate-limit", false, "Burst-probe for missing rate limits (sends ~12 fast requests; off by default)")
	scanCmd.Flags().BoolVar(&noDataExp, "no-data-exposure", false, "Disable JSON sensitive-field analysis")
	scanCmd.Flags().BoolVar(&noAdminPath, "no-admin-path", false, "Disable admin / debug path probing")
	scanCmd.Flags().BoolVar(&noAPIVer, "no-api-version", false, "Disable sibling API version enumeration")
	scanCmd.Flags().StringVar(&apiSpecURL, "api-spec", "", "OpenAPI / Swagger JSON URL — runner exercises every documented endpoint")
	scanCmd.Flags().BoolVar(&noCtypeConf, "no-content-type", false, "Disable content-type confusion probe")
	scanCmd.Flags().BoolVar(&noSSE, "no-sse", false, "Disable SSE / event-stream auth probe")
	scanCmd.Flags().BoolVar(&noGRPCRefl, "no-grpc-reflect", false, "Disable gRPC reflection probe")
	scanCmd.Flags().BoolVar(&h2ResetOpt, "h2-reset", false, "Probe HTTP/2 rapid-reset (CVE-2023-44487); off by default — sends raw HTTP/2 frames")
	scanCmd.Flags().BoolVar(&h2ContinueOpt, "h2-continuation", false, "Probe HTTP/2 CONTINUATION flood (CVE-2024 class); off by default — sends a bounded CONTINUATION-frame burst that stresses the target")
	scanCmd.Flags().BoolVar(&h2MadeResetOpt, "h2-madeyoureset", false, "Probe HTTP/2 MadeYouReset (2025); off by default — induces a bounded burst of server-side stream resets")
	scanCmd.Flags().BoolVar(&noCSRF, "no-csrf", false, "Disable CSRF probe")
	scanCmd.Flags().BoolVar(&noTabnab, "no-tabnabbing", false, "Disable reverse-tabnabbing HTML scan")
	scanCmd.Flags().BoolVar(&noCSPT, "no-cspt", false, "Disable client-side path traversal (CSPT) JavaScript scan")
	scanCmd.Flags().BoolVar(&noBAC, "no-bac", false, "Disable function-level broken-access-control differential (runs when --auth-a-* is set)")
	scanCmd.Flags().BoolVar(&redosOpt, "redos", false, "Enable ReDoS timing probe (off by default — adds latency on regex-shaped params)")
	scanCmd.Flags().BoolVar(&noPromptInj, "no-prompt-injection", false, "Disable LLM prompt-injection probe")
	scanCmd.Flags().BoolVar(&noXSLT, "no-xslt", false, "Disable XSLT injection probe")
	scanCmd.Flags().BoolVar(&noSAMLInj, "no-saml-injection", false, "Disable SAML SP envelope probe")
	scanCmd.Flags().BoolVar(&noORMLeak, "no-orm-leak", false, "Disable ORM expansion / over-fetch probe")
	scanCmd.Flags().BoolVar(&noTypeJug, "no-type-juggling", false, "Disable PHP loose-equality auth bypass probe")
	scanCmd.Flags().BoolVar(&noDepConf, "no-dep-confusion", false, "Disable dependency-confusion manifest probe")
	scanCmd.Flags().BoolVar(&noTokenEnt, "no-token-entropy", false, "Disable Set-Cookie / CSRF token-entropy analysis")
	scanCmd.Flags().BoolVar(&noCacheDec, "no-cache-deception", false, "Disable web cache deception probe")
	scanCmd.Flags().BoolVar(&noCachePois, "no-cache-poisoning", false, "Disable unkeyed-header cache poisoning probe")
	scanCmd.Flags().BoolVar(&noCSSInj, "no-css-injection", false, "Disable CSS injection probe")
	scanCmd.Flags().BoolVar(&noDeser, "no-deserialization", false, "Disable insecure-deserialization probe")
	scanCmd.Flags().BoolVar(&noDOMClob, "no-dom-clobber", false, "Disable DOM clobbering probe")
	scanCmd.Flags().BoolVar(&noEmailInj, "no-email-injection", false, "Disable email-header injection probe")
	scanCmd.Flags().BoolVar(&noHPP, "no-hpp", false, "Disable HTTP Parameter Pollution probe")
	scanCmd.Flags().BoolVar(&noHTMLInj, "no-html-injection", false, "Disable HTML injection probe")
	scanCmd.Flags().BoolVar(&massAssign, "mass-assign", false, "Enable mass-assignment probe (off by default — mutates state via PUT/POST/PATCH)")
	scanCmd.Flags().BoolVar(&protoPollSrv, "proto-pollution-server", false, "Enable server-side prototype-pollution probe (off by default — modifies request shape)")
	scanCmd.Flags().BoolVar(&noSecondOrd, "no-second-order", false, "Disable second-order injection probe")
	scanCmd.Flags().BoolVar(&storedXSSOpt, "stored-xss", false, "Enable stored XSS detection (inject→crawl→match→confirm; auto-enabled at --level 3+)")
	scanCmd.Flags().BoolVar(&noSSIInj, "no-ssi", false, "Disable Server-Side Includes injection probe")
	scanCmd.Flags().BoolVar(&noStorage, "no-storage", false, "Disable cookie / session-management audit")
	scanCmd.Flags().BoolVar(&noNuclei, "no-nuclei", false, "Skip the Nuclei binary even when it's on PATH")
	scanCmd.Flags().BoolVar(&internalOnly, "internal-only", false, "Run only the internal scanner, skip all external tools (sqlmap, dalfox, nuclei, etc.)")
	scanCmd.Flags().StringVar(&nucleiTags, "nuclei-tags", "", "Comma-separated tag filter passed to Nuclei (e.g. cve,rce)")
	scanCmd.Flags().StringVar(&nucleiSev, "nuclei-severity", "", "Comma-separated severity filter for Nuclei (info,low,medium,high,critical)")
	scanCmd.Flags().StringVar(&authACookie, "auth-a-cookie", "", "Cookie header for identity A (two-identity IDOR/BOLA probe)")
	scanCmd.Flags().StringVar(&authBCookie, "auth-b-cookie", "", "Cookie header for identity B (two-identity IDOR/BOLA probe)")
	scanCmd.Flags().StringArrayVar(&authAHdr, "auth-a-header", nil, "Header for identity A (repeatable, 'Key: Value')")
	scanCmd.Flags().StringArrayVar(&authBHdr, "auth-b-header", nil, "Header for identity B (repeatable, 'Key: Value')")
	scanCmd.Flags().StringVar(&idorURL, "idor-url", "", "Override URL for the two-identity IDOR/BOLA probe (defaults to scan target)")
	scanCmd.Flags().BoolVar(&noPostMsg, "no-postmessage", false, "Disable the postMessage origin-validation probe (requires Chrome)")

	scanCmd.Flags().BoolVar(&noScope, "no-scope", false, "Disable scope entirely (request any host). By default the scan is scoped to the target host(s)")
	scanCmd.Flags().StringArrayVar(&scopeHosts, "scope-host", nil, "Override the scoped hosts (repeatable; '*.example.com' wildcard). Default is the target host(s). Cross-host detectors (cloud, subdomain-takeover, external APIs) and OOB use a separate unscoped client")
	scanCmd.Flags().StringArrayVar(&includePaths, "include-path", nil, "When set, only request paths matching one of these regexps (repeatable)")
	scanCmd.Flags().StringArrayVar(&excludePaths, "exclude-path", nil, "Never request paths matching these regexps (repeatable); exclude always wins over include")
	scanCmd.Flags().BoolVar(&noDefaultExcludes, "no-default-excludes", false, "Do not auto-exclude session-destroying paths (/logout, /delete-account, ...) when a scope is active")
	scanCmd.Flags().Float64Var(&ratePerSec, "rate", 0, "Cap outbound requests per second across the whole scan (0 = unlimited). Use it to stay within a target's rate limits")
	scanCmd.Flags().StringVar(&sessionCheckURL, "session-check-url", "", "Authenticated-only URL polled during the scan to detect logout and re-authenticate (defaults to the first target when --login-* is used). --login-success is the authenticated marker")
	scanCmd.Flags().DurationVar(&sessionCheckInterval, "session-check-interval", 60*time.Second, "How often to poll --session-check-url for logout")
	scanCmd.Flags().StringVar(&checkpointPath, "checkpoint", "", "Record scan progress per target to this file so an interrupted scan can resume")
	scanCmd.Flags().StringVar(&resumePath, "resume", "", "Resume from a checkpoint file: skip already-scanned targets and carry their findings forward (usually the same path as --checkpoint)")
	scanCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what the scan would do without sending any traffic")
	scanCmd.Flags().BoolVar(&iastEnabled, "iast", false, "Enable IAST: start the callback server for taint-marker sink confirmation (deploy a sensor to the target first — see 'assay iast deploy')")
	scanCmd.Flags().StringVar(&iastAddr, "iast-addr", ":7880", "IAST callback server listen address")
	scanCmd.Flags().StringVar(&minConfidence, "min-confidence", "", "Filter out findings below this confidence level: confirmed, high, medium, low (default: report all)")
	scanCmd.Flags().StringVar(&coveragePath, "coverage", "", "Write coverage data (tested/skipped params × detectors) to this JSON file")
	scanCmd.Flags().StringVar(&fpDatabasePath, "fp-database", "", "FP feedback database path (.assay-fp.json); known FPs get confidence=low")
	scanCmd.Flags().BoolVar(&incremental, "incremental", false, "With --baseline, skip scanning endpoints whose response matches the baseline")
}
