package reporting

import (
	"html/template"
	"io"
	"time"
	"unicode"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scoring"
)

type htmlFinding struct {
	Type          string
	Severity      string
	SeverityClass string
	CVSS          float64
	CVSSVector    string
	Confidence    string
	URL           string
	Parameter     string
	Description   string
	Evidence      string
	Request       string
	Response      string
	Remediation   string
	CWE           []string
	Top10         []string
	WSTG          []string
}

type htmlSeverityGroup struct {
	Severity string
	Class    string
	Count    int
	Findings []htmlFinding
}

type htmlSevCount struct {
	Severity string
	Class    string
	Count    int
	Pct      int
}

type htmlOWASP struct {
	Code  string
	Count int
}

type htmlData struct {
	Tool          string
	Version       string
	GeneratedAt   string
	Duration      string
	Targets       []string
	Technologies  []string
	ToolsRun      int
	ToolsSkipped  int
	Total         int
	HighestCVSS   float64
	HighestRating string
	BySeverity    []htmlSevCount
	OWASP         []htmlOWASP
	Groups        []htmlSeverityGroup
}

// capitalizeSeverity returns the severity label with the first letter
// upper-cased (e.g. "critical" → "Critical").
func capitalizeSeverity(s core.Severity) string {
	str := string(s)
	if str == "" {
		return str
	}
	runes := []rune(str)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

func severityClass(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "critical"
	case core.SeverityHigh:
		return "high"
	case core.SeverityMedium:
		return "medium"
	case core.SeverityLow:
		return "low"
	case core.SeverityInfo:
		return "info"
	default:
		return "info"
	}
}

// WriteHTML writes a rich, self-contained HTML report (inline CSS, no external
// assets).
func (r *Report) WriteHTML(w io.Writer) error {
	res := r.ScanResult
	st := computeStats(res.Findings)

	data := htmlData{
		Tool:          r.Tool,
		Version:       r.Version,
		GeneratedAt:   r.GeneratedAt.Format(time.RFC3339),
		Duration:      res.Duration.Round(time.Second).String(),
		Targets:       res.Targets,
		Technologies:  res.Technologies,
		ToolsRun:      res.ToolsRun,
		ToolsSkipped:  res.ToolsSkipped,
		Total:         st.Total,
		HighestCVSS:   st.HighestCVSS,
		HighestRating: scoring.Rating(st.HighestCVSS),
	}
	for _, sev := range severityOrder {
		count := st.BySeverity[sev]
		pct := 0
		if st.Total > 0 {
			pct = count * 100 / st.Total
		}
		data.BySeverity = append(data.BySeverity, htmlSevCount{
			Severity: capitalizeSeverity(sev), Class: severityClass(sev), Count: count, Pct: pct,
		})
		group := res.Findings.FilterBySeverity(sev)
		if len(group) == 0 {
			continue
		}
		hg := htmlSeverityGroup{Severity: capitalizeSeverity(sev), Class: severityClass(sev), Count: len(group)}
		for _, f := range group {
			hg.Findings = append(hg.Findings, htmlFinding{
				Type: f.Type, Severity: capitalizeSeverity(f.Severity), SeverityClass: severityClass(f.Severity),
				CVSS: f.CVSS, CVSSVector: f.CVSSVector, Confidence: string(f.Confidence),
				URL: f.URL, Parameter: f.Parameter, Description: f.Description,
				Evidence: f.Evidence, Request: f.Request, Response: f.Response,
				Remediation: f.Remediation, CWE: f.CWE, Top10: f.Top10, WSTG: f.WSTG,
			})
		}
		data.Groups = append(data.Groups, hg)
	}
	for code, n := range st.OWASPCoverage {
		data.OWASP = append(data.OWASP, htmlOWASP{Code: code, Count: n})
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
<meta charset="utf-8">
<title>{{.Tool}} scan report</title>
<style>
:root{--c-critical:#b00020;--c-high:#e65100;--c-medium:#f9a825;--c-low:#0277bd;--c-info:#607d8b}
body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;color:#1a1a1a;background:#f5f6f8}
header{background:#11243b;color:#fff;padding:24px 32px}
header h1{margin:0 0 4px;font-size:20px}
header .meta{font-size:13px;opacity:.85}
main{max-width:1000px;margin:0 auto;padding:24px 32px}
.dash{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{flex:1;min-width:120px;background:#fff;border-radius:8px;padding:12px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card .n{font-size:28px;font-weight:700}
.bar{height:10px;border-radius:5px;background:#e0e0e0;overflow:hidden;margin-top:8px;display:flex}
.seg{height:100%}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px;font-weight:600}
.critical{background:var(--c-critical)}.high{background:var(--c-high)}.medium{background:var(--c-medium)}.low{background:var(--c-low)}.info{background:var(--c-info)}
.finding{background:#fff;border-radius:8px;margin:12px 0;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.finding h3{margin:0 0 8px;font-size:16px}
.kv{font-size:13px;color:#333;margin:2px 0}
pre{background:#0f1115;color:#e6e6e6;padding:10px;border-radius:6px;overflow:auto;font-size:12px}
details{margin-top:8px}summary{cursor:pointer;font-size:13px;color:#11243b}
.owasp span{display:inline-block;background:#eef;border-radius:6px;padding:2px 8px;margin:2px;font-size:12px}
.tag{display:inline-block;background:#eee;border-radius:6px;padding:1px 6px;margin:1px;font-size:12px}
</style>
</head>
<body>
<header>
<h1>{{.Tool}} scan report</h1>
<div class="meta">Generated {{.GeneratedAt}} &middot; Duration {{.Duration}} &middot; {{.ToolsRun}} tools run, {{.ToolsSkipped}} skipped</div>
<div class="meta">Targets: {{range .Targets}}{{.}} {{end}}</div>
{{if .Technologies}}<div class="meta">Tech: {{range .Technologies}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
</header>
<main>
<div class="dash">
{{range .BySeverity}}<div class="card"><div class="n">{{.Count}}</div><span class="badge {{.Class}}">{{.Severity}}</span></div>{{end}}
<div class="card"><div class="n">{{.Total}}</div>Total</div>
{{if gt .HighestCVSS 0.0}}<div class="card"><div class="n">{{printf "%.1f" .HighestCVSS}}</div>Highest CVSS ({{.HighestRating}})</div>{{end}}
</div>
<div class="bar">
{{range .BySeverity}}{{if .Count}}<div class="seg {{.Class}}" style="width:{{.Pct}}%"></div>{{end}}{{end}}
</div>
{{if .OWASP}}<div class="owasp" style="margin-top:16px">OWASP coverage: {{range .OWASP}}<span>{{.Code}} ({{.Count}})</span>{{end}}</div>{{end}}

{{range .Groups}}
<h2><span class="badge {{.Class}}">{{.Severity}}</span> {{.Count}}</h2>
{{range .Findings}}
<div class="finding">
<h3>{{.Type}}</h3>
{{if gt .CVSS 0.0}}<div class="kv"><strong>CVSS:</strong> {{printf "%.1f" .CVSS}}{{if .CVSSVector}} <code>{{.CVSSVector}}</code> (default){{end}}</div>{{end}}
<div class="kv"><strong>URL:</strong> {{.URL}}</div>
{{if .Parameter}}<div class="kv"><strong>Parameter:</strong> {{.Parameter}}</div>{{end}}
{{if .Confidence}}<div class="kv"><strong>Confidence:</strong> {{.Confidence}}</div>{{end}}
{{if .CWE}}<div class="kv">{{range .CWE}}<span class="tag">{{.}}</span>{{end}}{{range .Top10}}<span class="tag">{{.}}</span>{{end}}{{range .WSTG}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
{{if .Description}}<div class="kv">{{.Description}}</div>{{end}}
{{if .Evidence}}<details><summary>Evidence</summary><pre>{{.Evidence}}</pre></details>{{end}}
{{if .Request}}<details><summary>Request</summary><pre>{{.Request}}</pre></details>{{end}}
{{if .Response}}<details><summary>Response</summary><pre>{{.Response}}</pre></details>{{end}}
{{if .Remediation}}<div class="kv"><strong>Remediation:</strong> {{.Remediation}}</div>{{end}}
</div>
{{end}}
{{end}}
{{if not .Groups}}<p>No vulnerabilities found.</p>{{end}}
</main>
</body>
</html>`
