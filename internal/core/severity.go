package core

import (
	"fmt"
	"strings"
)

// Severity represents the severity level of a vulnerability finding.
type Severity string

const (
	// SeverityCritical indicates a critical vulnerability that requires immediate attention.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high severity vulnerability.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium severity vulnerability.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low severity vulnerability.
	SeverityLow Severity = "low"
	// SeverityInfo indicates an informational finding.
	SeverityInfo Severity = "info"
)

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// IsValid returns true if the severity is a valid known value.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

// Score returns a numeric score for the severity (5=critical, 1=info, 0=invalid).
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ParseSeverity parses a string into a Severity value.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "info", "informational":
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity: %q", s)
	}
}

// Confidence represents the confidence level of a vulnerability finding.
type Confidence string

const (
	// ConfidenceConfirmed indicates the vulnerability has been confirmed/verified.
	ConfidenceConfirmed Confidence = "confirmed"
	// ConfidenceHigh indicates high confidence in the finding.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium indicates medium confidence in the finding.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow indicates low confidence in the finding.
	ConfidenceLow Confidence = "low"
)

// String returns the string representation of the confidence.
func (c Confidence) String() string {
	return string(c)
}

// IsValid returns true if the confidence is a valid known value.
func (c Confidence) IsValid() bool {
	switch c {
	case ConfidenceConfirmed, ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	default:
		return false
	}
}

// ParseConfidence parses a string into a Confidence value.
func ParseConfidence(s string) (Confidence, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "confirmed", "certain":
		return ConfidenceConfirmed, nil
	case "high":
		return ConfidenceHigh, nil
	case "medium":
		return ConfidenceMedium, nil
	case "low":
		return ConfidenceLow, nil
	default:
		return "", fmt.Errorf("invalid confidence: %q", s)
	}
}
