package cmd

import (
	"bufio"
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
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools/sqlmap"
)

var (
	// Scan flags
	timeout     time.Duration
	concurrency int
	headers     []string
	cookies     string
	userAgent   string
	insecure    bool
	data        string
	method      string
	level       int
	risk        int
	jsonOutput  bool
	htmlOutput  bool
	disableOOB  bool
	noDiscovery bool
	storageInj  bool
	chromePath  string
	targetList  string
	templateDir string
	profile     string
	noJSDep     bool
	nvdAPIKey   string
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

	// Scan-specific flags
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
}

func runScan(cmd *cobra.Command, args []string) error {
	// Collect targets from args, file, or stdin.
	targets, err := collectTargets(args)
	if err != nil {
		return err
	}

	// Validate each target URL.
	for _, target := range targets {
		parsedURL, err := url.Parse(target)
		if err != nil || parsedURL.Host == "" {
			return fmt.Errorf("invalid target URL: %s (must include scheme, e.g. https://example.com)", target)
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("unsupported URL scheme %q: only http and https are supported", parsedURL.Scheme)
		}
	}

	// Validate level and risk bounds
	if level < 1 || level > 5 {
		return fmt.Errorf("level must be between 1 and 5, got %d", level)
	}
	if risk < 1 || risk > 3 {
		return fmt.Errorf("risk must be between 1 and 3, got %d", risk)
	}

	// Parse headers
	headerMap := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed header %q: must be in 'Key: Value' format", h)
		}
		headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	// Create scanner
	s := scanner.New()
	// Release headless browser pool and OOB client when runScan returns,
	// including on error paths and cancellation.
	defer s.Close()

	// Configure scanner with all CLI options
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

	// Configure internal scanner - start with profile if specified
	internalConfig := scanner.DefaultInternalConfig()
	if profile != "" {
		p := scanner.GetProfile(profile)
		internalConfig = p.Config
	}
	if templateDir != "" {
		internalConfig.EnableTemplates = true
		internalConfig.TemplatePaths = []string{templateDir}
	}
	if disableOOB {
		internalConfig.EnableOOB = false
	}
	if noDiscovery {
		internalConfig.EnableDiscovery = false
	}
	if storageInj {
		internalConfig.EnableStorageInj = true
	}
	if chromePath != "" {
		internalConfig.ChromePath = chromePath
	}
	if noJSDep {
		internalConfig.EnableJSDep = false
	}
	// CLI flag wins over env; missing flag falls back to NVD_API_KEY env.
	// Empty after both → public tier (anonymous, ~5 req/30s).
	if nvdAPIKey != "" {
		internalConfig.NVDAPIKey = nvdAPIKey
	} else if env := os.Getenv("NVD_API_KEY"); env != "" {
		internalConfig.NVDAPIKey = env
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

	// Add all targets
	for _, target := range targets {
		if err := s.AddTarget(target); err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
	}

	// Register tools
	registerTools(s)

	// Setup signal handling
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

	// Print scan start
	if !jsonOutput && !htmlOutput {
		if len(targets) == 1 {
			printScanHeader(targets[0])
		} else {
			printScanHeader(fmt.Sprintf("%d targets", len(targets)))
		}
	}

	// Run scan
	result, err := s.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results using the reporting package
	report := reporting.NewReport(result)

	if jsonOutput {
		return report.WriteJSON(os.Stdout)
	}

	if htmlOutput {
		return report.WriteHTML(os.Stdout)
	}

	return report.WriteText(os.Stdout)
}

// collectTargets gathers target URLs from CLI args, a file, or stdin.
func collectTargets(args []string) ([]string, error) {
	// Case 1: target list file specified via --list / -l
	if targetList != "" {
		f, err := os.Open(targetList)
		if err != nil {
			return nil, fmt.Errorf("cannot open target list file: %w", err)
		}
		defer f.Close()
		targets := readTargetsFromReader(f)
		if len(targets) == 0 {
			return nil, fmt.Errorf("no valid targets found in %s", targetList)
		}
		return targets, nil
	}

	// Case 2: target provided as positional argument
	if len(args) > 0 {
		return []string{args[0]}, nil
	}

	// Case 3: read from stdin if piped
	stat, err := os.Stdin.Stat()
	if err == nil && stat.Mode()&os.ModeCharDevice == 0 {
		targets := readTargetsFromReader(os.Stdin)
		if len(targets) > 0 {
			return targets, nil
		}
	}

	return nil, fmt.Errorf("no targets provided: specify a URL argument, use --list, or pipe URLs via stdin")
}

// readTargetsFromReader reads URLs from an io.Reader, one per line.
// Empty lines and lines starting with '#' are skipped.
func readTargetsFromReader(r *os.File) []string {
	var targets []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets
}

func registerTools(s *scanner.Scanner) {
	// Register SQLMap with validated options
	sqlmapTool := sqlmap.New().WithOptions(sqlmap.Options{
		Level:   level,
		Risk:    risk,
		Threads: concurrency,
	})
	s.RegisterTool(sqlmapTool)

	// TODO: Add more tools as they are implemented
	// - nuclei
	// - ffuf
	// - nikto
}

func printScanHeader(target string) {
	fmt.Println("╔════════════════════════════════════════════════════════╗")
	fmt.Println("║    SKWS - Swiss Knife for Web Security Scanner        ║")
	fmt.Println("╚════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Started: %s\n", time.Now().Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Scanning...")
	fmt.Println()
}
