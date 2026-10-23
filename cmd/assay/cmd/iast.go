package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TyrusRC/assay/internal/iast"
	"github.com/spf13/cobra"
)

var iastCmd = &cobra.Command{
	Use:   "iast",
	Short: "IAST sensor management",
	Long: `Manage assay's lightweight IAST (Interactive Application Security Testing)
sensors. Deploy a sensor to the target application so assay can confirm
that DAST payloads reach dangerous sinks (SQL query, system command,
file open, etc.).

Supported languages: php, node (js), python (py).`,
}

var iastDeployCmd = &cobra.Command{
	Use:   "deploy <language> [output-dir]",
	Short: "Export a sensor file for deployment to the target application",
	Long: `Export the IAST sensor source for the given language.

Languages:
  php     PHP sensor (deploy via php.ini auto_prepend_file)
  node    Node.js sensor (deploy via NODE_OPTIONS="--require sensor.js")
  python  Python sensor (deploy as sitecustomize.py or PYTHONSTARTUP)

The sensor reports taint-marker hits to the assay callback server at
the address configured by ASSAY_CALLBACK_URL (default :7880). Start the
callback server with --iast on the scan command.

Examples:
  assay iast deploy php ./target-app/
  assay iast deploy node /tmp/
  assay iast deploy python`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runIASTDeploy,
}

var iastListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available sensor languages",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("Available IAST sensors:")
		fmt.Println()
		fmt.Println("  php      PHP (auto_prepend_file)")
		fmt.Println("           php.ini: auto_prepend_file = /path/to/sensor.php")
		fmt.Println()
		fmt.Println("  node     Node.js (require hook)")
		fmt.Println("           NODE_OPTIONS=\"--require /path/to/sensor.js\" node app.js")
		fmt.Println()
		fmt.Println("  python   Python (sitecustomize / startup)")
		fmt.Println("           cp sensor.py <venv>/lib/pythonX.Y/sitecustomize.py")
		fmt.Println("           or: PYTHONSTARTUP=/path/to/sensor.py python app.py")
		fmt.Println()
		fmt.Println("All sensors read ASSAY_CALLBACK_URL (default http://host.docker.internal:7880/api/v1/sink)")
	},
}

func init() {
	rootCmd.AddCommand(iastCmd)
	iastCmd.AddCommand(iastDeployCmd)
	iastCmd.AddCommand(iastListCmd)
}

func runIASTDeploy(_ *cobra.Command, args []string) error {
	lang := args[0]
	content, ok := iast.SensorContent(lang)
	if !ok {
		return fmt.Errorf("unknown language %q — run 'assay iast list' for options", lang)
	}

	fname := iast.SensorLanguages[lang]
	if fname == "" {
		fname = "sensor." + lang
	}

	if len(args) > 1 {
		outDir := args[1]
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return fmt.Errorf("cannot create output directory: %w", err)
		}
		outPath := filepath.Join(outDir, fname)
		if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Sensor written to %s\n", outPath)
	} else {
		fmt.Print(content)
	}
	return nil
}
