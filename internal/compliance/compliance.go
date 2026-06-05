// Package compliance maps scan findings to the controls of common regulatory
// and standards frameworks (PCI-DSS, HIPAA, ISO 27001). Mapping is driven by
// each finding's OWASP Top 10 (2025) category, which the scoring layer assigns
// to every finding, so the assessment stays consistent with the rest of the
// report. The result groups findings under the framework controls they bear on,
// giving auditors a control-by-control view of where the application falls
// short.
package compliance

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// Framework identifies a compliance standard.
type Framework string

const (
	// PCIDSS is the Payment Card Industry Data Security Standard (v4.0).
	PCIDSS Framework = "pci-dss"
	// HIPAA is the HIPAA Security Rule (45 CFR Part 164, Subpart C).
	HIPAA Framework = "hipaa"
	// ISO27001 is ISO/IEC 27001:2022 Annex A.
	ISO27001 Framework = "iso-27001"
)

// Control is a single framework control or requirement.
type Control struct {
	// ID is the control identifier (e.g. "PCI 6.2.4", "ISO A.8.28").
	ID string `json:"id"`
	// Title summarizes the control.
	Title string `json:"title"`
}

// Requirement pairs a control with the findings that bear on it.
type Requirement struct {
	Control  Control       `json:"control"`
	Findings core.Findings `json:"findings"`
}

// Assessment is the compliance view of a set of findings for one framework.
type Assessment struct {
	Framework    Framework     `json:"framework"`
	Requirements []Requirement `json:"requirements"`
	Unmapped     core.Findings `json:"unmapped,omitempty"`
}

var owaspRe = regexp.MustCompile(`(?i)\bA(\d{1,2})\b`)

// Frameworks returns the supported frameworks.
func Frameworks() []Framework {
	return []Framework{PCIDSS, HIPAA, ISO27001}
}

// ParseFramework resolves a user-supplied name to a Framework.
func ParseFramework(s string) (Framework, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pci", "pci-dss", "pcidss":
		return PCIDSS, nil
	case "hipaa":
		return HIPAA, nil
	case "iso", "iso-27001", "iso27001", "iso-27001:2022":
		return ISO27001, nil
	default:
		return "", fmt.Errorf("unknown compliance framework: %q (want pci-dss, hipaa, or iso-27001)", s)
	}
}

// Title returns a human-readable framework name.
func (f Framework) Title() string {
	switch f {
	case PCIDSS:
		return "PCI-DSS v4.0"
	case HIPAA:
		return "HIPAA Security Rule"
	case ISO27001:
		return "ISO/IEC 27001:2022"
	default:
		return string(f)
	}
}

// owaspCategory extracts a normalized OWASP category ("A01".."A10") from a
// Top 10 tag, or "" when none is present.
func owaspCategory(tag string) string {
	m := owaspRe.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	n := m[1]
	if len(n) == 1 {
		n = "0" + n
	}
	return "A" + n
}

// MapFinding returns the deduplicated framework controls a finding bears on.
func MapFinding(f *core.Finding, fw Framework) []Control {
	table := mappingFor(fw)
	seen := make(map[string]bool)
	var controls []Control
	for _, tag := range f.Top10 {
		cat := owaspCategory(tag)
		if cat == "" {
			continue
		}
		for _, c := range table[cat] {
			if seen[c.ID] {
				continue
			}
			seen[c.ID] = true
			controls = append(controls, c)
		}
	}
	return controls
}

// Assess groups findings under the controls they map to for a framework.
// Findings that map to no control are returned in Unmapped.
func Assess(findings core.Findings, fw Framework) Assessment {
	byControl := make(map[string]*Requirement)
	var order []string
	a := Assessment{Framework: fw}

	for _, f := range findings {
		controls := MapFinding(f, fw)
		if len(controls) == 0 {
			a.Unmapped = append(a.Unmapped, f)
			continue
		}
		for _, c := range controls {
			req, ok := byControl[c.ID]
			if !ok {
				req = &Requirement{Control: c}
				byControl[c.ID] = req
				order = append(order, c.ID)
			}
			req.Findings = append(req.Findings, f)
		}
	}

	a.Requirements = make([]Requirement, 0, len(order))
	for _, id := range order {
		a.Requirements = append(a.Requirements, *byControl[id])
	}
	return a
}
