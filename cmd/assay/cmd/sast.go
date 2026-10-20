package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/reporting"
	"github.com/TyrusRC/assay/internal/sast"
	"github.com/TyrusRC/assay/internal/scanner"
)

var (
	sastSecretsOnly bool
	sastSCAOnly     bool
	sastConfigOnly  bool
	sastExcludeDirs string
	sastConcurrency int
	sastMaxFileSize int64
	sastFormat      string
	sastOutputDir   string
	sastFailOn      string
)

var sastCmd = &cobra.Command{
	Use:   "sast [paths...]",
	Short: "Static application security testing (secrets, SCA, config)",
	Long: `Run static analysis on source code and project files.

Three analysis engines:
  secrets  — scan for hardcoded credentials, API keys, private keys
  sca      — check dependency manifests for known CVEs via OSV.dev
  config   — audit configuration files (Dockerfile, docker-compose, .env, nginx)

All three run by default. Use --secrets-only, --sca-only, or --config-only
to run a single engine.

Examples:
  # Scan the current directory
  assay sast .

  # Scan specific paths
  assay sast ./src ./configs

  # Secrets only, JSON output
  assay sast --secrets-only --format json .

  # SCA with CI gate
  assay sast --sca-only --fail-on high .

  # Multiple output formats
  assay sast --format json,html,sarif --output-dir ./reports .`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSAST,
}

func init() {
	sastCmd.Flags().BoolVar(&sastSecretsOnly, "secrets-only", false, "Run only secret scanning")
	sastCmd.Flags().BoolVar(&sastSCAOnly, "sca-only", false, "Run only Software Composition Analysis")
	sastCmd.Flags().BoolVar(&sastConfigOnly, "config-only", false, "Run only configuration security checks")
	sastCmd.Flags().StringVar(&sastExcludeDirs, "exclude-dirs", "", "Additional directories to exclude (comma-separated)")
	sastCmd.Flags().IntVar(&sastConcurrency, "concurrency", 8, "Number of concurrent file scanners")
	sastCmd.Flags().Int64Var(&sastMaxFileSize, "max-file-size", 1<<20, "Maximum file size for secret scanning (bytes)")
	sastCmd.Flags().StringVar(&sastFormat, "format", "text", "Output format: text,json,html,csv,md,sarif,junit,gitlab (comma-separated)")
	sastCmd.Flags().StringVar(&sastOutputDir, "output-dir", "", "Directory for output files (required for multiple formats)")
	sastCmd.Flags().StringVar(&sastFailOn, "fail-on", "", "Exit with code 2 if findings at this severity or above (critical,high,medium,low)")

	rootCmd.AddCommand(sastCmd)
}

func runSAST(cmd *cobra.Command, args []string) error {
	for _, path := range args {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("target path %q: %w", path, err)
		}
	}

	formats, err := resolveFormats(sastFormat, false, false)
	if err != nil {
		return err
	}
	if verr := validateOutput(formats, sastOutputDir); verr != nil {
		return verr
	}

	var excludeDirs []string
	if sastExcludeDirs != "" {
		for _, d := range strings.Split(sastExcludeDirs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				excludeDirs = append(excludeDirs, d)
			}
		}
	}

	cfg := &sast.Config{
		Targets:     args,
		Verbose:     verbose,
		Concurrency: sastConcurrency,
		ExcludeDirs: excludeDirs,
		MaxFileSize: sastMaxFileSize,
		SecretsOnly: sastSecretsOnly,
		SCAOnly:     sastSCAOnly,
		ConfigOnly:  sastConfigOnly,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping SAST scan...")
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sigChan)
	}()

	fmt.Fprintln(os.Stderr, "[*] Starting SAST scan...")
	result, err := sast.Scan(ctx, cfg)
	if err != nil {
		return fmt.Errorf("SAST scan failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[+] SAST scan completed in %s: %d files scanned, %d findings\n",
		result.Duration.Round(time.Millisecond), result.FilesScanned, len(result.Findings))

	counts := result.Findings.CountBySeverity()
	fmt.Fprintf(os.Stderr, "    Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])

	scanResult := &scanner.ScanResult{
		Targets:   args,
		Findings:  result.Findings,
		ToolsRun:  3,
		StartTime: time.Now().Add(-result.Duration),
		EndTime:   time.Now(),
		Duration:  result.Duration,
	}
	report := reporting.NewReport(scanResult)
	if err := writeReports(report, formats, sastOutputDir); err != nil {
		return err
	}

	if sastFailOn != "" {
		fail, count, gerr := evaluateGate(result.Findings, sastFailOn)
		if gerr != nil {
			return gerr
		}
		if fail {
			return &gateError{Threshold: mustParseSeverity(sastFailOn), Count: count}
		}
	}

	return nil
}

func mustParseSeverity(s string) core.Severity {
	sev, _ := core.ParseSeverity(s)
	return sev
}
