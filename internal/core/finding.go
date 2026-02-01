package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Finding represents a discovered security vulnerability.
type Finding struct {
	// Identification
	ID   string `json:"id"`
	Tool string `json:"tool,omitempty"`

	// Classification
	Type       string     `json:"type"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`

	// Details
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter,omitempty"`

	// Evidence
	Evidence string `json:"evidence,omitempty"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`

	// OWASP Mapping
	WSTG     []string `json:"wstg,omitempty"`
	Top10    []string `json:"top10,omitempty"`
	APITop10 []string `json:"api_top10,omitempty"`
	CWE      []string `json:"cwe,omitempty"`
	CVSS     float64  `json:"cvss,omitempty"`

	// Remediation
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	// Status
	Verified  bool      `json:"verified,omitempty"`
	Timestamp time.Time `json:"timestamp"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewFinding creates a new Finding with the given type and severity.
func NewFinding(vulnType string, severity Severity) *Finding {
	return &Finding{
		ID:         uuid.New().String(),
		Type:       vulnType,
		Severity:   severity,
		Confidence: ConfidenceMedium,
		Timestamp:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}
}

// Validate checks if the finding has all required fields.
func (f *Finding) Validate() error {
	if f.ID == "" {
		return errors.New("finding ID is required")
	}
	if f.Type == "" {
		return errors.New("finding type is required")
	}
	if !f.Severity.IsValid() {
		return errors.New("invalid severity")
	}
	if f.Confidence != "" && !f.Confidence.IsValid() {
		return errors.New("invalid confidence")
	}
	if f.URL == "" {
		return errors.New("finding URL is required")
	}
	return nil
}

// DeduplicationKey returns a unique key for deduplication purposes.
func (f *Finding) DeduplicationKey() string {
	data := fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(f.Type), f.Type, len(f.URL), f.URL, len(f.Parameter), f.Parameter)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// WithOWASPMapping adds OWASP framework mappings to the finding.
func (f *Finding) WithOWASPMapping(wstg, top10, cwe []string) *Finding {
	f.WSTG = wstg
	f.Top10 = top10
	f.CWE = cwe
	return f
}

// SetEvidence sets the evidence details for the finding.
func (f *Finding) SetEvidence(evidence, request, response string) *Finding {
	f.Evidence = evidence
	f.Request = request
	f.Response = response
	return f
}

// Age returns the duration since the finding was discovered.
func (f *Finding) Age() time.Duration {
	return time.Since(f.Timestamp)
}

// Findings is a slice of Finding with helper methods.
type Findings []*Finding

// SortBySeverity sorts findings by severity (critical first).
func (f Findings) SortBySeverity() {
	sort.Slice(f, func(i, j int) bool {
		return f[i].Severity.Score() > f[j].Severity.Score()
	})
}

// Deduplicate removes duplicate findings based on deduplication key.
func (f Findings) Deduplicate() Findings {
	best := make(map[string]*Finding)
	order := make([]string, 0, len(f))

	for _, finding := range f {
		key := finding.DeduplicationKey()
		if existing, ok := best[key]; !ok {
			best[key] = finding
			order = append(order, key)
		} else if confidenceScore(finding.Confidence) > confidenceScore(existing.Confidence) {
			best[key] = finding
		}
	}

	result := make(Findings, 0, len(order))
	for _, key := range order {
		result = append(result, best[key])
	}
	return result
}

// confidenceScore returns a numeric score for confidence comparison.
func confidenceScore(c Confidence) int {
	switch c {
	case ConfidenceConfirmed:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// FilterBySeverity returns findings with the specified severity.
func (f Findings) FilterBySeverity(severity Severity) Findings {
	result := make(Findings, 0)
	for _, finding := range f {
		if finding.Severity == severity {
			result = append(result, finding)
		}
	}
	return result
}

// FilterByMinSeverity returns findings with severity >= minSeverity.
func (f Findings) FilterByMinSeverity(minSeverity Severity) Findings {
	minScore := minSeverity.Score()
	result := make(Findings, 0)
	for _, finding := range f {
		if finding.Severity.Score() >= minScore {
			result = append(result, finding)
		}
	}
	return result
}

// Count returns the total number of findings.
func (f Findings) Count() int {
	return len(f)
}

// CountBySeverity returns a map of severity to count.
func (f Findings) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, finding := range f {
		counts[finding.Severity]++
	}
	return counts
}
