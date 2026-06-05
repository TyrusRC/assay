// Package integrations exports scan findings to external issue trackers
// (GitHub Issues, Jira). It converts findings into a tracker-neutral Issue and
// provides exporters that create them via each tracker's REST API. Exporters
// support a dry-run mode so users can preview exactly what would be filed
// before anything is sent.
package integrations

import (
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// Issue is a tracker-neutral representation of a finding to be filed.
type Issue struct {
	// Title is the issue summary.
	Title string
	// Body is the Markdown issue description.
	Body string
	// Labels are tracker labels to apply.
	Labels []string
	// Severity is the source finding's severity, for priority mapping.
	Severity core.Severity
}

// FindingToIssue renders a finding as a tracker-neutral Issue.
func FindingToIssue(f *core.Finding) Issue {
	label := f.Title
	if label == "" {
		label = f.Type
	}
	host := hostOf(f.URL)

	title := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), label)
	if host != "" {
		title += " @ " + host
	}

	return Issue{
		Title:    title,
		Body:     buildBody(f),
		Labels:   buildLabels(f),
		Severity: f.Severity,
	}
}

// BuildIssues converts findings at or above minSeverity into issues.
func BuildIssues(findings core.Findings, minSeverity core.Severity) []Issue {
	filtered := findings.FilterByMinSeverity(minSeverity)
	issues := make([]Issue, 0, len(filtered))
	for _, f := range filtered {
		issues = append(issues, FindingToIssue(f))
	}
	return issues
}

// buildBody assembles the Markdown issue description.
func buildBody(f *core.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Severity:** %s  \n", f.Severity)
	if f.Confidence != "" {
		fmt.Fprintf(&b, "**Confidence:** %s  \n", f.Confidence)
	}
	if f.URL != "" {
		fmt.Fprintf(&b, "**URL:** %s  \n", f.URL)
	}
	if f.Parameter != "" {
		fmt.Fprintf(&b, "**Parameter:** `%s`  \n", f.Parameter)
	}
	writeSection(&b, "Description", f.Description)
	writeCodeSection(&b, "Evidence", f.Evidence)
	writeSection(&b, "Remediation", f.Remediation)

	if mapping := classificationLine(f); mapping != "" {
		fmt.Fprintf(&b, "\n**Classification:** %s\n", mapping)
	}
	if len(f.References) > 0 {
		b.WriteString("\n**References:**\n")
		for _, r := range f.References {
			fmt.Fprintf(&b, "- %s\n", r)
		}
	}
	b.WriteString("\n_Filed by assay._")
	return b.String()
}

func writeSection(b *strings.Builder, heading, body string) {
	if strings.TrimSpace(body) == "" {
		return
	}
	fmt.Fprintf(b, "\n### %s\n\n%s\n", heading, body)
}

func writeCodeSection(b *strings.Builder, heading, body string) {
	if strings.TrimSpace(body) == "" {
		return
	}
	fmt.Fprintf(b, "\n### %s\n\n```\n%s\n```\n", heading, body)
}

// classificationLine joins CWE and OWASP tags into one line.
func classificationLine(f *core.Finding) string {
	parts := make([]string, 0, len(f.CWE)+len(f.Top10))
	parts = append(parts, f.CWE...)
	parts = append(parts, f.Top10...)
	return strings.Join(parts, ", ")
}

// buildLabels derives tracker labels from the finding.
func buildLabels(f *core.Finding) []string {
	labels := []string{"assay", "security"}
	if f.Severity != "" {
		labels = append(labels, "severity:"+string(f.Severity))
	}
	return labels
}

// hostOf returns the host portion of a URL, best-effort, without importing
// net/url for such a small need in the title.
func hostOf(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
