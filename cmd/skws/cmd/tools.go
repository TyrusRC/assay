package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools/sqlmap"
)

// toolsCmd represents the tools command.
var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Manage security tools",
	Long:  `Manage and inspect security tools integrated with SKWS.`,
}

// toolsListCmd lists all available tools.
var toolsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available security tools",
	Long:  `List all security tools integrated with SKWS and their availability status.`,
	Run:   runToolsList,
}

// toolsCheckCmd checks tool availability.
var toolsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check tool health and availability",
	Long:  `Run health checks on all integrated security tools.`,
	Run:   runToolsCheck,
}

func init() {
	rootCmd.AddCommand(toolsCmd)
	toolsCmd.AddCommand(toolsListCmd)
	toolsCmd.AddCommand(toolsCheckCmd)
}

type toolInfo struct {
	name        string
	version     string
	available   bool
	description string
}

func getRegisteredTools() []toolInfo {
	tools := []toolInfo{}

	// SQLMap
	s := sqlmap.New()
	tools = append(tools, toolInfo{
		name:        s.Name(),
		version:     s.Version(),
		available:   s.IsAvailable(),
		description: "Automatic SQL injection detection and exploitation",
	})

	// TODO: Add more tools as implemented
	// - nuclei
	// - ffuf
	// - nikto

	return tools
}

func runToolsList(cmd *cobra.Command, args []string) {
	tools := getRegisteredTools()

	fmt.Println("Registered Security Tools:")
	fmt.Println("==========================")
	fmt.Println()

	for _, tool := range tools {
		status := "✗ Not Available"
		if tool.available {
			status = "✓ Available"
		}

		fmt.Printf("  %s\n", tool.name)
		fmt.Printf("    Status:  %s\n", status)
		if tool.version != "" {
			fmt.Printf("    Version: %s\n", tool.version)
		}
		fmt.Printf("    %s\n", tool.description)
		fmt.Println()
	}
}

func runToolsCheck(cmd *cobra.Command, args []string) {
	tools := getRegisteredTools()

	fmt.Println("Tool Health Check:")
	fmt.Println("==================")
	fmt.Println()

	allHealthy := true
	for _, tool := range tools {
		if tool.available {
			fmt.Printf("  ✓ %s (v%s) - OK\n", tool.name, tool.version)
		} else {
			fmt.Printf("  ✗ %s - Not found in PATH\n", tool.name)
			allHealthy = false
		}
	}

	fmt.Println()
	if allHealthy {
		fmt.Println("All tools are healthy and ready to use.")
	} else {
		fmt.Println("Some tools are not available. Install missing tools for full functionality.")
	}
}
