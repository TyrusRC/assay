// Package exposure provides detection for sensitive file exposure vulnerabilities.
package exposure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/exposure"
)

// Detector performs sensitive file exposure detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Sensitive File Exposure Detector.
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
	MaxChecks     int
	Timeout       time.Duration
	Categories    []exposure.Category
	OnlyCritical  bool
	ContinueOnHit bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxChecks:     100,
		Timeout:       10 * time.Second,
		Categories:    nil, // All categories
		OnlyCritical:  false,
		ContinueOnHit: true,
	}
}

// DetectionResult contains exposure detection results.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	CheckedFiles  int
	ExposedFiles  []string
	CategoriesHit map[exposure.Category]int
}

// Detect checks for sensitive file exposure vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		ExposedFiles:  make([]string, 0),
		CategoriesHit: make(map[exposure.Category]int),
	}

	// Normalize target URL
	target = strings.TrimSuffix(target, "/")

	// Get payloads based on options
	payloads := d.getPayloads(opts)

	// Limit number of checks
	if opts.MaxChecks > 0 && len(payloads) > opts.MaxChecks {
		payloads = payloads[:opts.MaxChecks]
	}

	// Test each sensitive file path
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.CheckedFiles++

		// Build URL for the sensitive file
		fileURL := fmt.Sprintf("%s/%s", target, payload.Path)

		resp, err := d.client.Get(ctx, fileURL)
		if err != nil {
			continue
		}

		// Check if file is exposed and contains expected content
		if d.isValidExposure(resp) && d.matchesPatterns(resp.Body, payload.Patterns) {
			finding := d.createFinding(target, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.ExposedFiles = append(result.ExposedFiles, payload.Path)
			result.CategoriesHit[payload.Category]++

			// Stop if not continuing after hit
			if !opts.ContinueOnHit {
				return result, nil
			}
		}
	}

	return result, nil
}

// getPayloads returns payloads based on options.
func (d *Detector) getPayloads(opts DetectOptions) []exposure.Payload {
	// Start with all payloads
	allPayloads := exposure.GetPayloads()

	// Filter by categories if specified
	if len(opts.Categories) > 0 {
		categorySet := make(map[exposure.Category]bool)
		for _, cat := range opts.Categories {
			categorySet[cat] = true
		}

		var filtered []exposure.Payload
		for _, p := range allPayloads {
			if categorySet[p.Category] {
				filtered = append(filtered, p)
			}
		}
		allPayloads = filtered
	}

	// Filter by severity if only critical
	if opts.OnlyCritical {
		var critical []exposure.Payload
		for _, p := range allPayloads {
			if p.Severity == exposure.SeverityCritical {
				critical = append(critical, p)
			}
		}
		allPayloads = critical
	}

	return allPayloads
}

// isValidExposure checks if the response indicates a valid file exposure.
func (d *Detector) isValidExposure(resp *http.Response) bool {
	// Only consider 200 OK responses
	if resp.StatusCode != 200 {
		return false
	}

	// Empty response is not a valid exposure
	if resp.Body == "" {
		return false
	}

	// Check for common "not found" soft 404 patterns
	lowerBody := strings.ToLower(resp.Body)
	softNotFoundPatterns := []string{
		"not found",
		"page not found",
		"file not found",
		"404",
		"does not exist",
		"cannot be found",
		"was not found",
		"no such file",
	}

	for _, pattern := range softNotFoundPatterns {
		if strings.Contains(lowerBody, pattern) {
			return false
		}
	}

	return true
}

// matchesPatterns checks if the content contains expected patterns.
func (d *Detector) matchesPatterns(content string, patterns []string) bool {
	// No patterns means any content is valid
	if len(patterns) == 0 {
		return true
	}

	// Check if at least one pattern matches
	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

// createFinding creates a Finding from a detected exposure.
func (d *Detector) createFinding(target string, payload exposure.Payload, resp *http.Response) *core.Finding {
	severity := d.mapSeverity(payload.Severity)

	finding := core.NewFinding("Sensitive File Exposure", severity)
	finding.URL = fmt.Sprintf("%s/%s", target, payload.Path)
	finding.Description = fmt.Sprintf("Sensitive file '%s' is publicly accessible: %s",
		payload.Path, payload.Description)

	// Build evidence
	evidence := fmt.Sprintf("File: %s\nCategory: %s\nSeverity: %s\n",
		payload.Path, payload.Category, payload.Severity)

	// Add response snippet
	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	evidence += fmt.Sprintf("\nResponse snippet:\n%s", body)

	finding.Evidence = evidence
	finding.Tool = "exposure-detector"
	finding.Confidence = core.ConfidenceHigh

	// Set remediation based on category
	finding.Remediation = d.getRemediation(payload.Category)

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-04"},       // Testing for Backup and Unreferenced Files
		[]string{"A05:2025"},           // Security Misconfiguration
		[]string{"CWE-538", "CWE-200"}, // Insertion of Sensitive Info, Exposure of Sensitive Info
	)

	return finding
}

// mapSeverity maps payload severity to core severity.
func (d *Detector) mapSeverity(s exposure.Severity) core.Severity {
	switch s {
	case exposure.SeverityCritical:
		return core.SeverityCritical
	case exposure.SeverityHigh:
		return core.SeverityHigh
	case exposure.SeverityMedium:
		return core.SeverityMedium
	case exposure.SeverityLow:
		return core.SeverityLow
	default:
		return core.SeverityMedium
	}
}

// getRemediation returns remediation advice based on category.
func (d *Detector) getRemediation(category exposure.Category) string {
	remediations := map[exposure.Category]string{
		exposure.CategoryConfig: "Remove configuration files from web root or restrict access via web server configuration. " +
			"Store sensitive configuration outside the document root. Use environment variables for secrets.",
		exposure.CategoryVersionCtrl: "Add version control directories to .htaccess or web server configuration deny rules. " +
			"Use 'Deny from all' for .git, .svn, .hg directories. Consider using git-archive for deployments.",
		exposure.CategoryBackup: "Remove backup files from web-accessible directories. " +
			"Store backups in a secure, non-web-accessible location. Implement proper backup procedures.",
		exposure.CategoryDebug: "Remove debug and test files from production servers. " +
			"Disable debug endpoints in production. Use feature flags for debug functionality.",
		exposure.CategorySecret: "Never store private keys, credentials, or secrets in web-accessible directories. " +
			"Use secret management solutions (Vault, AWS Secrets Manager). Rotate exposed credentials immediately.",
		exposure.CategoryLog: "Configure log files to be written outside the web root. " +
			"Restrict access to log directories. Implement proper log rotation and archival.",
		exposure.CategoryIDE: "Remove IDE configuration files from deployments. " +
			"Add IDE directories to .gitignore and deployment exclusions.",
		exposure.CategoryDatabase: "Never store database files in web-accessible directories. " +
			"Use proper database servers instead of file-based databases in production.",
	}

	if remediation, ok := remediations[category]; ok {
		return remediation
	}

	return "Remove or restrict access to sensitive files. Review deployment procedures to prevent sensitive file exposure."
}
