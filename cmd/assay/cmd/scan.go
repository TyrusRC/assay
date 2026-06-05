package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/reporting"
	"github.com/TyrusRC/assay/internal/scanner"
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
	scanCmd.Flags().IntVar(&crawlDepth, "crawl-depth", 1, "Max BFS depth from each seed when --crawl is set (0 = seed page only)")
	scanCmd.Flags().IntVar(&crawlPages, "crawl-max-pages", 25, "Max pages to navigate when --crawl is set")
	scanCmd.Flags().StringVarP(&targetList, "list", "l", "", "File containing target URLs (one per line)")
	scanCmd.Flags().StringVar(&templateDir, "templates", "", "Path to nuclei-style template directory")
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
	scanCmd.Flags().BoolVar(&noSSIInj, "no-ssi", false, "Disable Server-Side Includes injection probe")
	scanCmd.Flags().BoolVar(&noStorage, "no-storage", false, "Disable cookie / session-management audit")
	scanCmd.Flags().BoolVar(&noNuclei, "no-nuclei", false, "Skip the Nuclei binary even when it's on PATH")
	scanCmd.Flags().StringVar(&nucleiTags, "nuclei-tags", "", "Comma-separated tag filter passed to Nuclei (e.g. cve,rce)")
	scanCmd.Flags().StringVar(&nucleiSev, "nuclei-severity", "", "Comma-separated severity filter for Nuclei (info,low,medium,high,critical)")
	scanCmd.Flags().StringVar(&authACookie, "auth-a-cookie", "", "Cookie header for identity A (two-identity IDOR/BOLA probe)")
	scanCmd.Flags().StringVar(&authBCookie, "auth-b-cookie", "", "Cookie header for identity B (two-identity IDOR/BOLA probe)")
	scanCmd.Flags().StringArrayVar(&authAHdr, "auth-a-header", nil, "Header for identity A (repeatable, 'Key: Value')")
	scanCmd.Flags().StringArrayVar(&authBHdr, "auth-b-header", nil, "Header for identity B (repeatable, 'Key: Value')")
	scanCmd.Flags().StringVar(&idorURL, "idor-url", "", "Override URL for the two-identity IDOR/BOLA probe (defaults to scan target)")
	scanCmd.Flags().BoolVar(&noPostMsg, "no-postmessage", false, "Disable the postMessage origin-validation probe (requires Chrome)")
}

func runScan(cmd *cobra.Command, args []string) error {
	if err := applyConfigFile(cmd); err != nil {
		return err
	}

	targets, err := collectTargets(args)
	if err != nil {
		return err
	}

	for _, target := range targets {
		parsedURL, err := url.Parse(target)
		if err != nil || parsedURL.Host == "" {
			return fmt.Errorf("invalid target URL: %s (must include scheme, e.g. https://example.com)", target)
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("unsupported URL scheme %q: only http and https are supported", parsedURL.Scheme)
		}
	}

	if level < 1 || level > 5 {
		return fmt.Errorf("level must be between 1 and 5, got %d", level)
	}
	if risk < 1 || risk > 3 {
		return fmt.Errorf("risk must be between 1 and 3, got %d", risk)
	}

	headerMap := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed header %q: must be in 'Key: Value' format", h)
		}
		headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	s := scanner.New()
	defer s.Close()

	sessionCookies := cookies
	if loginURL != "" {
		loginCtx, loginCancel := context.WithTimeout(context.Background(), 60*time.Second)
		got, lerr := performLogin(loginCtx)
		loginCancel()
		if lerr != nil {
			return fmt.Errorf("login failed: %w", lerr)
		}
		sessionCookies = mergeCookies(cookies, got)
		if verbose {
			fmt.Fprintln(os.Stderr, "[*] Authenticated: scanning with captured session")
		}
	}

	config := &scanner.Config{
		Timeout:     timeout,
		Concurrency: concurrency,
		Verbose:     verbose,
		Headers:     headerMap,
		Cookies:     sessionCookies,
		UserAgent:   userAgent,
		Data:        data,
		Method:      method,
		ProxyURL:    proxy,
		Insecure:    insecure,
		OutputDir:   output,
	}
	s.SetConfig(config)

	internalConfig := scanner.DefaultInternalConfig()
	if profile != "" {
		p := scanner.GetProfile(profile)
		internalConfig = p.Config
	}
	if err := applyCLIFlags(internalConfig); err != nil {
		return err
	}
	if verbose && internalConfig.EnableJSDep {
		if internalConfig.NVDAPIKey != "" {
			fmt.Fprintln(os.Stderr, "[*] NVD: authenticated tier (~50 req/30s)")
		} else {
			fmt.Fprintln(os.Stderr, "[*] NVD: anonymous tier (~5 req/30s; pass --nvd-api-key or set NVD_API_KEY for higher limit)")
		}
	}
	internalConfig.Verbose = verbose
	if err := s.SetInternalConfig(internalConfig); err != nil && verbose {
		fmt.Fprintf(os.Stderr, "Warning: Failed to configure internal scanner: %v\n", err)
	}

	for _, target := range targets {
		if err := s.AddTarget(target); err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
	}

	registerTools(s)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping scan...")
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sigChan)
	}()

	formats, err := resolveFormats(formatList, jsonOutput, htmlOutput)
	if err != nil {
		return err
	}
	if verr := validateOutput(formats, outputDir); verr != nil {
		return verr
	}

	// Print the human banner only when emitting the default text report to stdout.
	if outputDir == "" && len(formats) == 1 && formats[0] == "text" {
		if len(targets) == 1 {
			printScanHeader(targets[0])
		} else {
			printScanHeader(fmt.Sprintf("%d targets", len(targets)))
		}
	}

	result, err := s.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if verifyFindings {
		runVerification(ctx, result.Findings, headerMap, sessionCookies)
	}

	report := reporting.NewReport(result)
	if err := writeReports(report, formats, outputDir); err != nil {
		return err
	}

	if complianceSpec != "" {
		if err := runCompliance(result.Findings, complianceSpec, outputDir); err != nil {
			return err
		}
	}

	if err := runExport(ctx, result.Findings); err != nil {
		return err
	}

	gateFindings := result.Findings
	if baselinePath != "" {
		baseline, berr := reporting.LoadBaselineFindings(baselinePath)
		if berr != nil {
			return berr
		}
		delta := reporting.DiffFindings(baseline, result.Findings)
		printDelta(delta)
		if failOnNew {
			gateFindings = delta.New
		}
	}

	fail, count, gerr := evaluateGate(gateFindings, failOn)
	if gerr != nil {
		return gerr
	}
	if fail {
		threshold, _ := core.ParseSeverity(failOn)
		return &gateError{Threshold: threshold, Count: count}
	}
	return nil
}
