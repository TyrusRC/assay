// Package cloud provides detection for cloud storage misconfiguration vulnerabilities.
package cloud

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/cloud"
)

// Detector performs cloud misconfiguration detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Cloud Misconfiguration Detector.
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

// DetectOptions configures cloud detection behavior.
type DetectOptions struct {
	MaxChecks     int
	Timeout       time.Duration
	Providers     []cloud.Provider
	CustomBuckets []string
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxChecks: 100,
		Timeout:   10 * time.Second,
	}
}

// DetectionResult contains cloud misconfiguration detection results.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	CheckedURLs   int
	OpenBuckets   []string
	OpenProviders map[cloud.Provider]int
}

// Detect checks for cloud storage misconfigurations for a domain.
func (d *Detector) Detect(ctx context.Context, domain string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		OpenBuckets:   make([]string, 0),
		OpenProviders: make(map[cloud.Provider]int),
	}

	// Generate bucket names
	bucketNames := d.generateBucketNames(domain)
	if len(opts.CustomBuckets) > 0 {
		bucketNames = append(bucketNames, opts.CustomBuckets...)
	}

	// Get checks
	checks := cloud.GetBucketChecks()
	if len(opts.Providers) > 0 {
		providerSet := make(map[cloud.Provider]bool)
		for _, p := range opts.Providers {
			providerSet[p] = true
		}
		var filtered []cloud.BucketCheck
		for _, c := range checks {
			if providerSet[c.Provider] {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}

	// Test each bucket name against each check
	for _, bucketName := range bucketNames {
		for _, check := range checks {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			if opts.MaxChecks > 0 && result.CheckedURLs >= opts.MaxChecks {
				return result, nil
			}

			result.CheckedURLs++

			// Build check URL
			checkURL := strings.ReplaceAll(check.URLTemplate, "{BUCKET}", bucketName)
			checkURL = strings.ReplaceAll(checkURL, "{ACCOUNT}", bucketName)
			checkURL = strings.ReplaceAll(checkURL, "{CONTAINER}", bucketName)

			resp, err := d.client.Get(ctx, checkURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && d.matchesPatterns(resp.Body, check.Patterns) {
				finding := d.createFinding(checkURL, bucketName, check, resp)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				result.OpenBuckets = append(result.OpenBuckets, bucketName)
				result.OpenProviders[check.Provider]++
			}
		}
	}

	return result, nil
}

// DetectBucket checks a specific URL for open bucket/blob.
func (d *Detector) DetectBucket(ctx context.Context, checkURL, bucketName string) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		OpenBuckets:   make([]string, 0),
		OpenProviders: make(map[cloud.Provider]int),
	}

	resp, err := d.client.Get(ctx, checkURL)
	if err != nil {
		return result, fmt.Errorf("failed to check bucket: %w", err)
	}

	result.CheckedURLs++

	// Check all known patterns
	checks := cloud.GetBucketChecks()
	for _, check := range checks {
		if resp.StatusCode == 200 && d.matchesPatterns(resp.Body, check.Patterns) {
			finding := d.createFinding(checkURL, bucketName, check, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.OpenBuckets = append(result.OpenBuckets, bucketName)
			result.OpenProviders[check.Provider]++
			return result, nil
		}
	}

	return result, nil
}

// generateBucketNames generates possible bucket names from a domain.
func (d *Detector) generateBucketNames(domain string) []string {
	// Clean domain
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")

	patterns := cloud.GetCommonBucketNames()

	var names []string
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		name := strings.ReplaceAll(pattern, "{DOMAIN}", domain)
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}

		// Also try with dots replaced by dashes
		dashDomain := strings.ReplaceAll(domain, ".", "-")
		dashName := strings.ReplaceAll(pattern, "{DOMAIN}", dashDomain)
		if !seen[dashName] {
			seen[dashName] = true
			names = append(names, dashName)
		}
	}

	return names
}

// matchesPatterns checks if the content contains expected patterns.
func (d *Detector) matchesPatterns(content string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

// createFinding creates a Finding from a detected cloud misconfiguration.
func (d *Detector) createFinding(checkURL, bucketName string, check cloud.BucketCheck, resp *http.Response) *core.Finding {
	finding := core.NewFinding("Cloud Storage Misconfiguration", core.SeverityHigh)
	finding.URL = checkURL
	finding.Description = fmt.Sprintf(
		"Open cloud storage detected: %s (provider: %s). "+
			"The storage bucket/container '%s' allows public access, "+
			"potentially exposing sensitive data.",
		check.Description, check.Provider, bucketName,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("Bucket: %s\nProvider: %s\nURL: %s\nResponse snippet: %s",
		bucketName, check.Provider, checkURL, body)
	finding.Tool = "cloud-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = d.getRemediation(check.Provider)

	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-11"},       // Test Cloud Storage
		[]string{"A05:2025"},           // Security Misconfiguration
		[]string{"CWE-284", "CWE-732"}, // Improper Access Control, Incorrect Permission Assignment
	)

	return finding
}

// getRemediation returns remediation advice based on cloud provider.
func (d *Detector) getRemediation(provider cloud.Provider) string {
	switch provider {
	case cloud.ProviderAWS:
		return "Disable public access using S3 Block Public Access settings. " +
			"Review and restrict bucket policies and ACLs. " +
			"Enable S3 server-side encryption. " +
			"Use AWS CloudTrail to monitor access."
	case cloud.ProviderGCP:
		return "Remove allUsers and allAuthenticatedUsers from bucket IAM policies. " +
			"Use uniform bucket-level access. " +
			"Enable Cloud Audit Logging. " +
			"Consider using VPC Service Controls."
	case cloud.ProviderAzure:
		return "Disable anonymous public read access on the container. " +
			"Use Azure RBAC for access control. " +
			"Enable Azure Storage Analytics logging. " +
			"Consider using Private Endpoints."
	default:
		return "Restrict public access to cloud storage resources. " +
			"Implement proper access controls and encryption. " +
			"Enable access logging and monitoring."
	}
}
