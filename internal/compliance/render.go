package compliance

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/TyrusRC/assay/internal/core"
)

// WriteMarkdown renders the assessment as a control-by-control Markdown report.
func (a Assessment) WriteMarkdown(w io.Writer) error {
	fmt.Fprintf(w, "# Compliance Assessment — %s\n\n", a.Framework.Title())

	mapped := 0
	for _, r := range a.Requirements {
		mapped += len(r.Findings)
	}
	if mapped == 0 && len(a.Unmapped) == 0 {
		fmt.Fprintln(w, "No findings — no control gaps identified in this scan.")
		return nil
	}

	fmt.Fprintf(w, "Controls with findings: **%d** · Findings mapped: **%d** · Unmapped: **%d**\n\n",
		len(a.Requirements), mapped, len(a.Unmapped))

	for _, r := range a.Requirements {
		fmt.Fprintf(w, "## %s — %s\n\n", r.Control.ID, r.Control.Title)
		fmt.Fprintf(w, "%d finding(s):\n\n", len(r.Findings))
		for _, f := range r.Findings {
			fmt.Fprintf(w, "- **[%s]** %s — `%s`\n", f.Severity, findingLabel(f), f.URL)
		}
		fmt.Fprintln(w)
	}

	if len(a.Unmapped) > 0 {
		fmt.Fprintf(w, "## Unmapped findings (%d)\n\n", len(a.Unmapped))
		fmt.Fprintln(w, "These findings are not directly tied to a control in this framework but still warrant review:")
		fmt.Fprintln(w)
		for _, f := range a.Unmapped {
			fmt.Fprintf(w, "- **[%s]** %s — `%s`\n", f.Severity, findingLabel(f), f.URL)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// WriteJSON renders the assessment as indented JSON.
func (a Assessment) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(a)
}

// findingLabel returns the most descriptive available label for a finding.
func findingLabel(f *core.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return f.Type
}
