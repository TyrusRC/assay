package reporting

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// severityOrder is the canonical Critical-to-Info ordering used by the
// Markdown and HTML renderers.
var severityOrder = []core.Severity{
	core.SeverityCritical, core.SeverityHigh, core.SeverityMedium,
	core.SeverityLow, core.SeverityInfo,
}

// WriteMarkdown writes the report as a shareable Markdown document.
func (r *Report) WriteMarkdown(w io.Writer) error {
	res := r.ScanResult
	st := computeStats(res.Findings)

	fmt.Fprintf(w, "# assay Scan Report\n\n")
	fmt.Fprintf(w, "- **Generated:** %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "- **Duration:** %s\n", res.Duration.Round(time.Second))
	if len(res.Targets) > 0 {
		fmt.Fprintf(w, "- **Targets:** %s\n", strings.Join(res.Targets, ", "))
	}
	fmt.Fprintf(w, "\n## Summary\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n|---|---|\n")
	for _, sev := range severityOrder {
		fmt.Fprintf(w, "| %s | %d |\n", sev, st.BySeverity[sev])
	}
	fmt.Fprintf(w, "| **Total** | **%d** |\n", st.Total)

	for _, sev := range severityOrder {
		group := res.Findings.FilterBySeverity(sev)
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n## %s (%d)\n\n", sev, len(group))
		for _, f := range group {
			fmt.Fprintf(w, "### %s\n\n", f.Type)
			if f.CVSS > 0 {
				fmt.Fprintf(w, "- **CVSS:** %.1f", f.CVSS)
				if f.CVSSVector != "" {
					fmt.Fprintf(w, " (`%s`, default)", f.CVSSVector)
				}
				fmt.Fprintf(w, "\n")
			}
			fmt.Fprintf(w, "- **URL:** %s\n", f.URL)
			if f.Parameter != "" {
				fmt.Fprintf(w, "- **Parameter:** %s\n", f.Parameter)
			}
			if len(f.CWE) > 0 {
				fmt.Fprintf(w, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
			}
			if len(f.Top10) > 0 {
				fmt.Fprintf(w, "- **OWASP:** %s\n", strings.Join(f.Top10, ", "))
			}
			if f.Description != "" {
				fmt.Fprintf(w, "\n%s\n", f.Description)
			}
			if f.Evidence != "" {
				fmt.Fprintf(w, "\n```\n%s\n```\n", f.Evidence)
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "\n**Remediation:** %s\n", f.Remediation)
			}
		}
	}
	return nil
}
