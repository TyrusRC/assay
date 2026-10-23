package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
	"github.com/spf13/cobra"
)

var fpCmd = &cobra.Command{
	Use:   "fp",
	Short: "Manage the false-positive feedback database",
	Long:  `Mark findings as false positives so future scans suppress them.`,
}

var fpMarkCmd = &cobra.Command{
	Use:   "mark <report.json> <finding-id> [reason]",
	Short: "Mark a finding as a false positive",
	Long: `Mark a finding from a scan report as a false positive.
The finding's dedup key is stored in the FP database so future scans
matching the same (type, url, parameter) tuple downgrade its confidence.`,
	Args: cobra.RangeArgs(2, 3),
	RunE: runFPMark,
}

var fpListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all marked false positives",
	RunE:  runFPList,
}

var fpDatabase string

func init() {
	rootCmd.AddCommand(fpCmd)
	fpCmd.AddCommand(fpMarkCmd)
	fpCmd.AddCommand(fpListCmd)

	fpCmd.PersistentFlags().StringVar(&fpDatabase, "database", ".assay-fp.json", "Path to the FP feedback database")
}

func runFPMark(_ *cobra.Command, args []string) error {
	reportPath := args[0]
	findingID := args[1]
	reason := ""
	if len(args) > 2 {
		reason = args[2]
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("cannot read report: %w", err)
	}

	var report struct {
		ScanResult struct {
			Findings []*core.Finding `json:"findings"`
		} `json:"scan_result"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("cannot parse report: %w", err)
	}

	var target *core.Finding
	for _, f := range report.ScanResult.Findings {
		if f.ID == findingID {
			target = f
			break
		}
	}
	if target == nil {
		return fmt.Errorf("finding %q not found in report", findingID)
	}

	db := scanner.LoadFPFeedback(fpDatabase)
	db.MarkFP(target, reason)
	if err := db.Save(); err != nil {
		return fmt.Errorf("cannot save FP database: %w", err)
	}

	fmt.Printf("Marked as FP: [%s] %s @ %s param=%s\n", target.Severity, target.Type, target.URL, target.Parameter)
	fmt.Printf("Database: %s (%d entries)\n", fpDatabase, db.Count())
	return nil
}

func runFPList(_ *cobra.Command, _ []string) error {
	db := scanner.LoadFPFeedback(fpDatabase)
	data, err := os.ReadFile(fpDatabase)
	if err != nil {
		fmt.Println("No FP database found.")
		return nil
	}

	var entries []struct {
		Key    string `json:"key"`
		Title  string `json:"title"`
		URL    string `json:"url"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	fmt.Printf("False Positive Database: %s (%d entries)\n\n", fpDatabase, db.Count())
	for i, e := range entries {
		fmt.Printf("  %d. %s\n", i+1, e.Title)
		fmt.Printf("     URL: %s\n", e.URL)
		if e.Reason != "" {
			fmt.Printf("     Reason: %s\n", e.Reason)
		}
		fmt.Println()
	}
	return nil
}
