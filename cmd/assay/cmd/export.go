package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/integrations"
)

// runExport files findings as issues in the configured trackers. Tokens are
// read from the environment only (never flags/argv). With --export-dry-run, or
// when no tracker is configured, it previews instead of sending. It is a no-op
// when no tracker flag is set.
func runExport(ctx context.Context, findings core.Findings) error {
	if githubRepo == "" && jiraURL == "" {
		return nil
	}

	minSev, err := core.ParseSeverity(exportMinSev)
	if err != nil {
		return fmt.Errorf("--export-min-severity: %w", err)
	}
	issues := integrations.BuildIssues(findings, minSev)
	if len(issues) == 0 {
		fmt.Fprintf(os.Stderr, "[*] No findings at or above %s to export\n", minSev)
		return nil
	}

	if exportDryRun {
		previewIssues(issues)
		return nil
	}

	for _, ex := range configuredExporters() {
		if verr := ex.Validate(); verr != nil {
			return verr
		}
		n, eerr := ex.Export(ctx, issues)
		if eerr != nil {
			return fmt.Errorf("%s export failed after %d issue(s): %w", ex.Name(), n, eerr)
		}
		fmt.Fprintf(os.Stderr, "[+] %s: created %d issue(s)\n", ex.Name(), n)
	}
	return nil
}

// issueExporter is the subset of an integrations exporter the CLI drives.
type issueExporter interface {
	Name() string
	Validate() error
	Export(ctx context.Context, issues []integrations.Issue) (int, error)
}

// configuredExporters builds an exporter per tracker flag, wiring credentials
// from the environment.
func configuredExporters() []issueExporter {
	var exporters []issueExporter
	if githubRepo != "" {
		exporters = append(exporters, &integrations.GitHubExporter{
			Repo:  githubRepo,
			Token: os.Getenv("GITHUB_TOKEN"),
		})
	}
	if jiraURL != "" {
		exporters = append(exporters, &integrations.JiraExporter{
			BaseURL: jiraURL,
			Project: jiraProject,
			Email:   os.Getenv("JIRA_EMAIL"),
			Token:   os.Getenv("JIRA_TOKEN"),
		})
	}
	return exporters
}

// previewIssues prints what would be filed without sending anything.
func previewIssues(issues []integrations.Issue) {
	fmt.Fprintf(os.Stderr, "[*] Dry run: %d issue(s) would be filed\n\n", len(issues))
	for _, iss := range issues {
		fmt.Printf("== %s ==\nlabels: %v\n\n%s\n\n", iss.Title, iss.Labels, iss.Body)
	}
}
