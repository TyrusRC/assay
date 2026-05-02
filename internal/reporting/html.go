package reporting

import (
	"html/template"
	"io"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// htmlData holds template data for the HTML report.
type htmlData struct {
	Version     string
	GeneratedAt string
	Targets     []string
	Duration    string
	ToolsRun    int
	Total       int
	Critical    int
	High        int
	Medium      int
	Low         int
	Info        int
	Findings    []htmlFinding
	Errors      []string
}

// htmlFinding holds a single finding for the HTML template.
type htmlFinding struct {
	Index       int
	ID          string
	Type        string
	Severity    string
	BadgeClass  string
	URL         string
	Parameter   string
	Description string
	Evidence    string
	Tool        string
	WSTG        []string
	Top10       []string
	APITop10    []string
	CWE         []string
}

// severityBadgeClass returns the CSS class for a severity badge.
func severityBadgeClass(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "badge-critical"
	case core.SeverityHigh:
		return "badge-high"
	case core.SeverityMedium:
		return "badge-medium"
	case core.SeverityLow:
		return "badge-low"
	case core.SeverityInfo:
		return "badge-info"
	default:
		return "badge-info"
	}
}

// WriteHTML writes the report as a self-contained HTML file.
func (r *Report) WriteHTML(w io.Writer) error {
	data := htmlData{
		Version:     r.Version,
		GeneratedAt: r.GeneratedAt.Format(time.RFC3339),
		Targets:     r.ScanResult.Targets,
		Duration:    r.ScanResult.Duration.Round(time.Second).String(),
		ToolsRun:    r.ScanResult.ToolsRun,
		Total:       r.Summary.TotalFindings,
		Critical:    r.Summary.Critical,
		High:        r.Summary.High,
		Medium:      r.Summary.Medium,
		Low:         r.Summary.Low,
		Info:        r.Summary.Info,
		Errors:      r.ScanResult.Errors,
	}

	for i, f := range r.ScanResult.Findings {
		data.Findings = append(data.Findings, htmlFinding{
			Index:       i + 1,
			ID:          f.ID,
			Type:        f.Type,
			Severity:    string(f.Severity),
			BadgeClass:  severityBadgeClass(f.Severity),
			URL:         f.URL,
			Parameter:   f.Parameter,
			Description: f.Description,
			Evidence:    f.Evidence,
			Tool:        f.Tool,
			WSTG:        f.WSTG,
			Top10:       f.Top10,
			APITop10:    f.APITop10,
			CWE:         f.CWE,
		})
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	return tmpl.Execute(w, data)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SKWS Scan Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1a2e;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:20px}
h1{color:#e94560;margin-bottom:5px}
h2{color:#0f3460;background:#16213e;padding:12px 18px;border-left:4px solid #e94560;margin:30px 0 15px;border-radius:0 6px 6px 0;color:#e0e0e0}
.meta{color:#888;font-size:0.9em;margin-bottom:20px}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.summary-card{background:#16213e;border-radius:8px;padding:18px;text-align:center}
.summary-card .count{font-size:2em;font-weight:bold}
.summary-card .label{font-size:0.85em;color:#888;text-transform:uppercase}
.count-critical{color:#ff4757}
.count-high{color:#ff6b35}
.count-medium{color:#ffc048}
.count-low{color:#4da6ff}
.count-info{color:#888}
.count-total{color:#e94560}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:600;text-transform:uppercase;color:#fff}
.badge-critical{background:#ff4757}
.badge-high{background:#ff6b35}
.badge-medium{background:#ffc048;color:#1a1a2e}
.badge-low{background:#4da6ff}
.badge-info{background:#555}
.finding{background:#16213e;border-radius:8px;margin:12px 0;overflow:hidden}
.finding-header{padding:14px 18px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;user-select:none}
.finding-header:hover{background:#1a2744}
.finding-title{font-weight:600}
.finding-details{padding:0 18px 18px;display:none}
.finding-details.open{display:block}
.detail-row{margin:6px 0}
.detail-label{color:#888;font-size:0.85em;display:inline-block;min-width:110px}
.detail-value{color:#e0e0e0}
.tag{display:inline-block;background:#0f3460;padding:2px 8px;border-radius:4px;font-size:0.8em;margin:2px}
.evidence{background:#0d1b2a;padding:12px;border-radius:6px;font-family:monospace;font-size:0.85em;white-space:pre-wrap;word-break:break-all;margin-top:6px}
.errors{background:#2d1b1b;border:1px solid #ff4757;border-radius:8px;padding:14px;margin:20px 0}
.errors h3{color:#ff4757;margin-bottom:8px}
.chevron{transition:transform 0.2s;font-size:0.8em}
.chevron.open{transform:rotate(90deg)}
footer{text-align:center;color:#555;margin:40px 0 20px;font-size:0.85em}
</style>
</head>
<body>
<div class="container">
<h1>SKWS Scan Report</h1>
<div class="meta">
Version {{.Version}} | Generated {{.GeneratedAt}} | Duration {{.Duration}} | Tools Run: {{.ToolsRun}}
</div>

<h2>Targets</h2>
<ul>
{{range .Targets}}<li>{{.}}</li>{{end}}
</ul>

<h2>Summary</h2>
<div class="summary-grid">
<div class="summary-card"><div class="count count-total">{{.Total}}</div><div class="label">Total</div></div>
<div class="summary-card"><div class="count count-critical">{{.Critical}}</div><div class="label">Critical</div></div>
<div class="summary-card"><div class="count count-high">{{.High}}</div><div class="label">High</div></div>
<div class="summary-card"><div class="count count-medium">{{.Medium}}</div><div class="label">Medium</div></div>
<div class="summary-card"><div class="count count-low">{{.Low}}</div><div class="label">Low</div></div>
<div class="summary-card"><div class="count count-info">{{.Info}}</div><div class="label">Info</div></div>
</div>

<h2>Findings</h2>
{{if .Findings}}
{{range .Findings}}
<div class="finding">
<div class="finding-header" onclick="toggleDetails(this)">
<span class="finding-title">[{{.Index}}] {{.Type}} <span class="badge {{.BadgeClass}}">{{.Severity}}</span></span>
<span class="chevron">&#9654;</span>
</div>
<div class="finding-details">
<div class="detail-row"><span class="detail-label">ID:</span> <span class="detail-value">{{.ID}}</span></div>
<div class="detail-row"><span class="detail-label">URL:</span> <span class="detail-value">{{.URL}}</span></div>
{{if .Parameter}}<div class="detail-row"><span class="detail-label">Parameter:</span> <span class="detail-value">{{.Parameter}}</span></div>{{end}}
{{if .Description}}<div class="detail-row"><span class="detail-label">Description:</span> <span class="detail-value">{{.Description}}</span></div>{{end}}
{{if .Tool}}<div class="detail-row"><span class="detail-label">Tool:</span> <span class="detail-value">{{.Tool}}</span></div>{{end}}
{{if .WSTG}}<div class="detail-row"><span class="detail-label">WSTG:</span> {{range .WSTG}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
{{if .Top10}}<div class="detail-row"><span class="detail-label">OWASP Top 10:</span> {{range .Top10}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
{{if .APITop10}}<div class="detail-row"><span class="detail-label">API Top 10:</span> {{range .APITop10}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
{{if .CWE}}<div class="detail-row"><span class="detail-label">CWE:</span> {{range .CWE}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
{{if .Evidence}}<div class="detail-row"><span class="detail-label">Evidence:</span><div class="evidence">{{.Evidence}}</div></div>{{end}}
</div>
</div>
{{end}}
{{else}}
<p>No vulnerabilities found.</p>
{{end}}

{{if .Errors}}
<div class="errors">
<h3>Errors</h3>
<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>
</div>
{{end}}

</div>
<footer>Generated by SKWS - Swiss Knife for Web Security Scanner</footer>
<script>
function toggleDetails(header){
var details=header.nextElementSibling;
var chevron=header.querySelector('.chevron');
details.classList.toggle('open');
chevron.classList.toggle('open');
}
</script>
</body>
</html>`
