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
	"github.com/swiss-knife-for-web-security/skws/internal/reporting"
	"github.com/swiss-knife-for-web-security/skws/internal/scanner"
	"github.com/swiss-knife-for-web-security/skws/internal/tools/sqlmap"
)

var (
	// Scan flags
	timeout     time.Duration
	concurrency int
	headers     []string
	cookies     string
	data        string
	method      string
	level       int
	risk        int
	jsonOutput  bool
	sarifOutput bool
	disableOOB  bool
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

  # Output as SARIF for CI/CD
  skws scan --sarif https://example.com/page?id=1`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Scan-specific flags
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", 30*time.Minute, "Scan timeout")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 3, "Number of concurrent tools")
	scanCmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Custom headers (can be specified multiple times)")
	scanCmd.Flags().StringVar(&cookies, "cookie", "", "Cookie string")
	scanCmd.Flags().StringVarP(&data, "data", "d", "", "POST data")
	scanCmd.Flags().StringVarP(&method, "method", "X", "GET", "HTTP method")
	scanCmd.Flags().IntVar(&level, "level", 1, "Scan level (1-5)")
	scanCmd.Flags().IntVar(&risk, "risk", 1, "Risk level (1-3)")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVar(&sarifOutput, "sarif", false, "Output results as SARIF (for CI/CD integration)")
	scanCmd.Flags().BoolVar(&disableOOB, "no-oob", false, "Disable Out-of-Band (OOB) testing for blind vulnerabilities")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Validate target URL
	parsedURL, err := url.Parse(target)
	if err != nil || parsedURL.Host == "" {
		return fmt.Errorf("invalid target URL: %s (must include scheme, e.g. https://example.com)", target)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q: only http and https are supported", parsedURL.Scheme)
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

	// Configure scanner with all CLI options
	config := &scanner.Config{
		Timeout:     timeout,
		Concurrency: concurrency,
		Verbose:     verbose,
		Headers:     headerMap,
		Cookies:     cookies,
		Data:        data,
		Method:      method,
		ProxyURL:    proxy,
		OutputDir:   output,
	}
	s.SetConfig(config)

	// Configure internal scanner (OOB enabled by default, can disable with --no-oob)
	internalConfig := scanner.DefaultInternalConfig()
	if disableOOB {
		internalConfig.EnableOOB = false
	}
	internalConfig.Verbose = verbose
	if err := s.SetInternalConfig(internalConfig); err != nil && verbose {
		fmt.Fprintf(os.Stderr, "Warning: Failed to configure internal scanner: %v\n", err)
	}

	// Add target
	if err := s.AddTarget(target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
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
	if !jsonOutput && !sarifOutput {
		printScanHeader(target)
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

	if sarifOutput {
		return report.WriteSARIF(os.Stdout)
	}

	return report.WriteText(os.Stdout)
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
