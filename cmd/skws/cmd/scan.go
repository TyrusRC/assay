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

	"github.com/spf13/cobra"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/reporting"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/scanner"
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
  skws scan https://example.com/page?id=1

  # Scan with custom headers
  skws scan -H "Authorization: Bearer token" https://example.com

  # Scan POST endpoint
  skws scan -X POST -d "username=admin" https://example.com/login

  # Aggressive scan (level 5, risk 3)
  skws scan --level 5 --risk 3 https://example.com/page?id=1

  # Scan from a target list file
  skws scan -l targets.txt

  # Scan from stdin
  cat targets.txt | skws scan

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
	scanCmd.Flags().BoolVar(&disableOOB, "no-oob", false, "Disable Out-of-Band (OOB) testing for blind vulnerabilities")
	scanCmd.Flags().BoolVar(&noDiscovery, "no-discovery", false, "Disable auto-discovery of injectable parameters")
	scanCmd.Flags().BoolVar(&storageInj, "storage-inj", false, "Enable client-side storage injection testing (requires Chrome)")
	scanCmd.Flags().StringVar(&chromePath, "chrome-path", "", "Explicit Chrome/Chromium binary path for headless testing")
	scanCmd.Flags().StringVarP(&targetList, "list", "l", "", "File containing target URLs (one per line)")
	scanCmd.Flags().StringVar(&templateDir, "templates", "", "Path to nuclei-style template directory")
	scanCmd.Flags().StringVar(&profile, "profile", "", "Scan profile (quick, normal, thorough)")
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
	scanCmd.Flags().BoolVar(&noCSRF, "no-csrf", false, "Disable CSRF probe")
	scanCmd.Flags().BoolVar(&noTabnab, "no-tabnabbing", false, "Disable reverse-tabnabbing HTML scan")
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

	config := &scanner.Config{
		Timeout:     timeout,
		Concurrency: concurrency,
		Verbose:     verbose,
		Headers:     headerMap,
		Cookies:     cookies,
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

	if !jsonOutput && !htmlOutput {
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

	report := reporting.NewReport(result)

	if jsonOutput {
		return report.WriteJSON(os.Stdout)
	}
	if htmlOutput {
		return report.WriteHTML(os.Stdout)
	}
	return report.WriteText(os.Stdout)
}
