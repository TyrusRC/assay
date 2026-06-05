package reporting

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// sarifSchema is the canonical SARIF 2.1.0 schema URL recognized by GitHub
// code scanning and other SARIF consumers.
const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// informationURI is the project home advertised in the SARIF tool driver.
const informationURI = "https://github.com/TyrusRC/assay"

// SARIF result levels (the only values GitHub code scanning recognizes).
const (
	sarifLevelError   = "error"
	sarifLevelWarning = "warning"
	sarifLevelNote    = "note"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifText struct {
	Text string `json:"text"`
}

// WriteSARIF writes the report as a SARIF 2.1.0 log suitable for GitHub code
// scanning and other SARIF consumers. Each distinct finding type becomes a
// rule; each finding becomes a result carrying its CVSS as security-severity.
func (r *Report) WriteSARIF(w io.Writer) error {
	findings := r.ScanResult.Findings

	ruleIndex := make(map[string]bool)
	rules := make([]sarifRule, 0)
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		id := ruleID(f.Type)
		if !ruleIndex[id] {
			ruleIndex[id] = true
			rules = append(rules, newSARIFRule(id, f))
		}
		results = append(results, newSARIFResult(id, f))
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				Version:        reportVersion,
				InformationURI: informationURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func newSARIFRule(id string, f *core.Finding) sarifRule {
	rule := sarifRule{
		ID:               id,
		Name:             f.Type,
		ShortDescription: sarifText{Text: f.Type},
	}
	if f.Description != "" {
		rule.FullDescription = &sarifText{Text: f.Description}
	}
	if len(f.References) > 0 {
		rule.HelpURI = f.References[0]
	}
	props := map[string]any{}
	if len(f.CWE) > 0 {
		props["cwe"] = f.CWE
	}
	if len(f.Top10) > 0 {
		props["owasp-top10"] = f.Top10
	}
	if len(props) > 0 {
		rule.Properties = props
	}
	return rule
}

func newSARIFResult(id string, f *core.Finding) sarifResult {
	msg := f.Type
	if f.Description != "" {
		msg = f.Description
	}
	props := map[string]any{
		"security-severity": strconv.FormatFloat(f.CVSS, 'f', 1, 64),
	}
	if f.Confidence != "" {
		props["confidence"] = string(f.Confidence)
	}
	return sarifResult{
		RuleID:  id,
		Level:   sarifLevel(f.Severity),
		Message: sarifText{Text: msg},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: f.URL},
			},
		}},
		Properties: props,
	}
}

// sarifLevel maps an assay severity onto a SARIF result level.
func sarifLevel(s core.Severity) string {
	switch s {
	case core.SeverityCritical, core.SeverityHigh:
		return sarifLevelError
	case core.SeverityMedium:
		return sarifLevelWarning
	case core.SeverityLow, core.SeverityInfo:
		return sarifLevelNote
	default:
		return sarifLevelNote
	}
}

// ruleID derives a stable, SARIF-safe rule identifier from a finding type,
// e.g. "SQL Injection" -> "sql-injection".
func ruleID(vulnType string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(vulnType) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen && b.Len() > 0 {
				b.WriteRune('-')
				prevHyphen = true
			}
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if out == "" {
		return "finding"
	}
	return out
}
