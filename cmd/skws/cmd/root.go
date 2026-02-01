package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version information
	version = "dev"
	commit  = "none"
	date    = "unknown"

	// Global flags
	verbose bool
	output  string
	proxy   string
)

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use:   "skws",
	Short: "Swiss Knife for Web Security - Context-aware web vulnerability scanner",
	Long: `SKWS (Swiss Knife for Web Security) is a CLI-based web security scanner
that uses context-aware and behavior-based detection to identify vulnerabilities.

It integrates multiple security tools and maps findings to OWASP frameworks
including WSTG, Top 10, API Security Top 10, and ASVS.

Examples:
  # Scan a single URL
  skws scan https://example.com/page?id=1

  # Scan with verbose output
  skws scan -v https://example.com

  # Scan through a proxy
  skws scan --proxy http://127.0.0.1:8080 https://example.com

  # List available tools
  skws tools list`,
	Version: version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global persistent flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Output file for results (default: stdout)")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")

	// Set version template
	rootCmd.SetVersionTemplate(fmt.Sprintf("{{.Name}} version {{.Version}} (commit: %s, built: %s)\n", commit, date))
}
