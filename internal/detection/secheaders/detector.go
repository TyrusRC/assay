// Package secheaders provides detection for HTTP security header misconfigurations.
package secheaders

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/secheaders"
)

// Detector performs HTTP security header misconfiguration detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Security Headers Detector.
func New(client *http.Client) *Detector {
	return &Detector{
		client: client,
	}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	Timeout             time.Duration
	CheckRequired       bool
	CheckOptional       bool
	CheckInfoDisclosure bool
	MinHSTSMaxAge       int // Minimum required HSTS max-age in seconds
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             10 * time.Second,
		CheckRequired:       true,
		CheckOptional:       true,
		CheckInfoDisclosure: true,
		MinHSTSMaxAge:       31536000, // 1 year
	}
}

// DetectionResult contains security header detection results.
type DetectionResult struct {
	Vulnerable            bool
	Findings              []*core.Finding
	MissingHeaders        []string
	InsecureHeaders       []string
	InfoDisclosureHeaders []string
	PresentHeaders        map[string]string
	Score                 int // Security score 0-100
}

// Detect checks for HTTP security header misconfigurations.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:              make([]*core.Finding, 0),
		MissingHeaders:        make([]string, 0),
		InsecureHeaders:       make([]string, 0),
		InfoDisclosureHeaders: make([]string, 0),
		PresentHeaders:        make(map[string]string),
	}

	// Check context before making request
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	// Make request to target
	resp, err := d.client.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("failed to fetch target: %w", err)
	}

	// Store present headers
	for name, value := range resp.Headers {
		result.PresentHeaders[name] = value
	}

	// Check required and optional security headers
	if opts.CheckRequired || opts.CheckOptional {
		d.checkSecurityHeaders(result, resp.Headers, opts)
	}

	// Check for information disclosure headers
	if opts.CheckInfoDisclosure {
		d.checkInfoDisclosure(result, resp.Headers, target)
	}

	// Calculate security score
	result.Score = d.calculateScore(result)

	// Mark as vulnerable if any findings exist
	result.Vulnerable = len(result.Findings) > 0

	return result, nil
}

// checkSecurityHeaders checks for missing or misconfigured security headers.
func (d *Detector) checkSecurityHeaders(result *DetectionResult, headers map[string]string, opts DetectOptions) {
	checks := secheaders.GetHeaderChecks()

	for _, check := range checks {
		// Skip optional headers if not requested
		if !check.Required && !opts.CheckOptional {
			continue
		}

		// Skip required headers if not requested
		if check.Required && !opts.CheckRequired {
			continue
		}

		value, found := d.getHeader(headers, check.Name)

		if !found {
			// Header is missing
			result.MissingHeaders = append(result.MissingHeaders, check.Name)
			finding := d.createMissingHeaderFinding(check)
			result.Findings = append(result.Findings, finding)
		} else {
			// Header is present - check for insecure values
			if d.hasInsecureValue(value, check, opts) {
				result.InsecureHeaders = append(result.InsecureHeaders, check.Name)
				finding := d.createInsecureHeaderFinding(check, value)
				result.Findings = append(result.Findings, finding)
			}
		}
	}
}

// checkInfoDisclosure checks for information disclosure headers.
func (d *Detector) checkInfoDisclosure(result *DetectionResult, headers map[string]string, target string) {
	insecureHeaders := secheaders.GetInsecureHeaders()

	for _, ih := range insecureHeaders {
		value, found := d.getHeader(headers, ih.Name)
		if found {
			result.InfoDisclosureHeaders = append(result.InfoDisclosureHeaders, ih.Name)
			finding := d.createInfoDisclosureFinding(ih, value, target)
			result.Findings = append(result.Findings, finding)
		}
	}
}

// getHeader gets a header value case-insensitively.
func (d *Detector) getHeader(headers map[string]string, name string) (string, bool) {
	// Try exact match first
	if value, ok := headers[name]; ok {
		return value, true
	}

	// Try case-insensitive match
	lowerName := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == lowerName {
			return v, true
		}
	}

	return "", false
}

// hasInsecureValue checks if a header value is insecure.
func (d *Detector) hasInsecureValue(value string, check secheaders.HeaderCheck, opts DetectOptions) bool {
	lowerValue := strings.ToLower(value)

	// Check for invalid values
	for _, invalid := range check.InvalidValues {
		if strings.Contains(lowerValue, strings.ToLower(invalid)) {
			return true
		}
	}

	// Special check for HSTS max-age
	if check.Name == "Strict-Transport-Security" && opts.MinHSTSMaxAge > 0 {
		maxAge := d.extractHSTSMaxAge(value)
		if maxAge < opts.MinHSTSMaxAge {
			return true
		}
	}

	// Check if value matches any valid values (if specified)
	if len(check.ValidValues) > 0 && check.Name == "X-Frame-Options" {
		isValid := false
		for _, valid := range check.ValidValues {
			if strings.EqualFold(value, valid) {
				isValid = true
				break
			}
		}
		if !isValid {
			return true
		}
	}

	return false
}

// hstsMaxAgeRe extracts the max-age value from HSTS headers.
var hstsMaxAgeRe = regexp.MustCompile(`max-age=(\d+)`)

// extractHSTSMaxAge extracts the max-age value from HSTS header.
func (d *Detector) extractHSTSMaxAge(value string) int {
	re := hstsMaxAgeRe
	matches := re.FindStringSubmatch(value)
	if len(matches) > 1 {
		if maxAge, err := strconv.Atoi(matches[1]); err == nil {
			return maxAge
		}
	}
	return 0
}

// createMissingHeaderFinding creates a finding for a missing security header.
func (d *Detector) createMissingHeaderFinding(check secheaders.HeaderCheck) *core.Finding {
	severity := d.mapSeverity(check.Severity)

	finding := core.NewFinding("Missing Security Header", severity)
	finding.Parameter = check.Name
	finding.Description = fmt.Sprintf("Security header '%s' is missing. %s", check.Name, check.Description)
	finding.Evidence = fmt.Sprintf("Header '%s' was not present in the response", check.Name)
	finding.Tool = "secheaders-detector"
	finding.Confidence = core.ConfidenceHigh
	finding.Remediation = check.Remediation
	finding.References = check.References

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-05"}, // Test HTTP Methods
		[]string{"A05:2021"},     // Security Misconfiguration
		check.CWE,
	)

	return finding
}

// createInsecureHeaderFinding creates a finding for an insecure security header.
func (d *Detector) createInsecureHeaderFinding(check secheaders.HeaderCheck, value string) *core.Finding {
	severity := d.mapSeverity(check.Severity)

	finding := core.NewFinding("Insecure Security Header", severity)
	finding.Parameter = check.Name
	finding.Description = fmt.Sprintf("Security header '%s' has an insecure configuration. %s", check.Name, check.Description)
	finding.Evidence = fmt.Sprintf("Header: %s: %s", check.Name, value)
	finding.Tool = "secheaders-detector"
	finding.Confidence = core.ConfidenceHigh
	finding.Remediation = check.Remediation
	finding.References = check.References

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-05"},
		[]string{"A05:2021"},
		check.CWE,
	)

	return finding
}

// createInfoDisclosureFinding creates a finding for information disclosure.
func (d *Detector) createInfoDisclosureFinding(ih secheaders.InsecureHeader, value, target string) *core.Finding {
	severity := d.mapSeverity(ih.Severity)

	finding := core.NewFinding("Information Disclosure Header", severity)
	finding.URL = target
	finding.Parameter = ih.Name
	finding.Description = fmt.Sprintf("Header '%s' reveals sensitive information. %s", ih.Name, ih.Description)
	finding.Evidence = fmt.Sprintf("Header: %s: %s", ih.Name, value)
	finding.Tool = "secheaders-detector"
	finding.Confidence = core.ConfidenceHigh
	finding.Remediation = ih.Remediation
	finding.References = ih.References

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INFO-02"}, // Fingerprint Web Server
		[]string{"A05:2021"},     // Security Misconfiguration
		ih.CWE,
	)

	return finding
}

// mapSeverity maps payload severity to core severity.
func (d *Detector) mapSeverity(s secheaders.Severity) core.Severity {
	switch s {
	case secheaders.SeverityHigh:
		return core.SeverityHigh
	case secheaders.SeverityMedium:
		return core.SeverityMedium
	case secheaders.SeverityLow:
		return core.SeverityLow
	case secheaders.SeverityInfo:
		return core.SeverityInfo
	default:
		return core.SeverityMedium
	}
}

// calculateScore calculates a security score based on header presence.
func (d *Detector) calculateScore(result *DetectionResult) int {
	checks := secheaders.GetHeaderChecks()

	totalRequired := 0
	presentRequired := 0
	totalOptional := 0
	presentOptional := 0

	for _, check := range checks {
		_, found := d.getHeader(result.PresentHeaders, check.Name)

		if check.Required {
			totalRequired++
			if found {
				presentRequired++
			}
		} else {
			totalOptional++
			if found {
				presentOptional++
			}
		}
	}

	// Calculate weighted score (required headers worth 70%, optional 30%)
	requiredScore := 0
	if totalRequired > 0 {
		requiredScore = (presentRequired * 70) / totalRequired
	}

	optionalScore := 0
	if totalOptional > 0 {
		optionalScore = (presentOptional * 30) / totalOptional
	}

	// Deduct points for insecure headers
	deduction := len(result.InsecureHeaders) * 10

	score := requiredScore + optionalScore - deduction
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
