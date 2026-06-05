package reporting

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// gitlabReportVersion is the GitLab security report schema version assay emits.
const gitlabReportVersion = "15.0.4"

// gitlabTimeLayout is the timestamp format GitLab expects (no timezone).
const gitlabTimeLayout = "2006-01-02T15:04:05"

type gitlabReport struct {
	Version         string       `json:"version"`
	Scan            gitlabScan   `json:"scan"`
	Vulnerabilities []gitlabVuln `json:"vulnerabilities"`
}

type gitlabScan struct {
	Scanner   gitlabScanner `json:"scanner"`
	Type      string        `json:"type"`
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
	Status    string        `json:"status"`
}

type gitlabScanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type gitlabVuln struct {
	ID          string         `json:"id"`
	Category    string         `json:"category"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Severity    string         `json:"severity"`
	Identifiers []gitlabIdent  `json:"identifiers"`
	Location    gitlabLocation `json:"location"`
}

type gitlabIdent struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type gitlabLocation struct {
	Hostname string `json:"hostname,omitempty"`
	Path     string `json:"path,omitempty"`
	Param    string `json:"param,omitempty"`
}

// WriteGitLab writes the report in the GitLab DAST security-report schema,
// consumable by GitLab CI's vulnerability management / security dashboard.
func (r *Report) WriteGitLab(w io.Writer) error {
	end := r.GeneratedAt
	start := end.Add(-r.ScanResult.Duration)

	doc := gitlabReport{
		Version: gitlabReportVersion,
		Scan: gitlabScan{
			Scanner:   gitlabScanner{ID: toolName, Name: toolName, Version: reportVersion},
			Type:      "dast",
			StartTime: start.Format(gitlabTimeLayout),
			EndTime:   end.Format(gitlabTimeLayout),
			Status:    "success",
		},
		Vulnerabilities: make([]gitlabVuln, 0, len(r.ScanResult.Findings)),
	}
	for _, f := range r.ScanResult.Findings {
		doc.Vulnerabilities = append(doc.Vulnerabilities, newGitLabVuln(f))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func newGitLabVuln(f *core.Finding) gitlabVuln {
	hostname, path := splitURL(f.URL)
	return gitlabVuln{
		ID:          f.ID,
		Category:    "dast",
		Name:        f.Type,
		Description: f.Description,
		Severity:    gitlabSeverity(f.Severity),
		Identifiers: gitlabIdentifiers(f),
		Location:    gitlabLocation{Hostname: hostname, Path: path, Param: f.Parameter},
	}
}

// gitlabIdentifiers builds the identifier list; GitLab requires at least one,
// and treats the first as primary. A stable assay rule id leads, followed by
// any CWE identifiers.
func gitlabIdentifiers(f *core.Finding) []gitlabIdent {
	idents := []gitlabIdent{{Type: toolName, Name: f.Type, Value: ruleID(f.Type)}}
	for _, cwe := range f.CWE {
		num := strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")
		idents = append(idents, gitlabIdent{
			Type:  "cwe",
			Name:  cwe,
			Value: num,
			URL:   "https://cwe.mitre.org/data/definitions/" + num + ".html",
		})
	}
	return idents
}

// gitlabSeverity maps an assay severity to GitLab's capitalized scale.
func gitlabSeverity(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "Critical"
	case core.SeverityHigh:
		return "High"
	case core.SeverityMedium:
		return "Medium"
	case core.SeverityLow:
		return "Low"
	case core.SeverityInfo:
		return "Info"
	default:
		return "Unknown"
	}
}

// splitURL separates a URL into a scheme://host hostname and a path(+query),
// returning the raw URL as hostname when it cannot be parsed.
func splitURL(raw string) (hostname, path string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, ""
	}
	hostname = u.Scheme + "://" + u.Host
	path = u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return hostname, path
}
