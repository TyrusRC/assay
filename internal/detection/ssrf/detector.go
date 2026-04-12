package ssrf

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/ssrf"
)

// Detector performs SSRF vulnerability detection.
type Detector struct {
	client           *http.Client
	verbose          bool
	responsePatterns map[ssrf.TargetType][]*regexp.Regexp
}

// New creates a new SSRF Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client: client,
	}
	d.initResponsePatterns()
	return d
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// initResponsePatterns initializes patterns that indicate successful SSRF.
func (d *Detector) initResponsePatterns() {
	d.responsePatterns = make(map[ssrf.TargetType][]*regexp.Regexp)

	// Cloud metadata patterns
	d.responsePatterns[ssrf.TargetCloud] = []*regexp.Regexp{
		// AWS
		regexp.MustCompile(`(?i)ami-[a-f0-9]+`),
		regexp.MustCompile(`(?i)instance-id.*i-[a-f0-9]+`),
		regexp.MustCompile(`(?i)iam.*security-credentials`),
		regexp.MustCompile(`(?i)"Code"\s*:\s*"Success"`),
		regexp.MustCompile(`(?i)AccessKeyId.*AKIA`),
		regexp.MustCompile(`(?i)ec2\.internal`),
		regexp.MustCompile(`(?i)meta-data`),

		// GCP
		regexp.MustCompile(`(?i)computeMetadata`),
		regexp.MustCompile(`(?i)project-id`),
		regexp.MustCompile(`(?i)service-accounts.*token`),

		// Azure
		regexp.MustCompile(`(?i)microsoft.*metadata`),
		regexp.MustCompile(`(?i)subscriptionId`),
		regexp.MustCompile(`(?i)resourceGroupName`),

		// Generic cloud
		regexp.MustCompile(`(?i)metadata.*instance`),
	}

	// Internal service patterns
	d.responsePatterns[ssrf.TargetInternal] = []*regexp.Regexp{
		// Redis
		regexp.MustCompile(`(?i)redis_version:`),
		regexp.MustCompile(`(?i)redis_git_sha1:`),
		regexp.MustCompile(`(?i)connected_clients:\d+`),

		// Memcached
		regexp.MustCompile(`(?i)STAT\s+pid\s+\d+`),
		regexp.MustCompile(`(?i)STAT\s+version`),

		// Elasticsearch
		regexp.MustCompile(`(?i)"cluster_name"\s*:`),
		regexp.MustCompile(`(?i)"tagline"\s*:\s*"You Know, for Search"`),

		// MongoDB
		regexp.MustCompile(`(?i)"ismaster"\s*:\s*(true|false)`),

		// MySQL
		regexp.MustCompile(`(?i)mysql_native_password`),

		// SSH
		regexp.MustCompile(`(?i)SSH-\d+\.\d+-OpenSSH`),

		// HTTP services
		regexp.MustCompile(`(?i)<title>.*admin.*</title>`),
		regexp.MustCompile(`(?i)phpinfo\(\)`),
		regexp.MustCompile(`(?i)Server:\s*(Apache|nginx|IIS)`),

		// Docker
		regexp.MustCompile(`(?i)"ContainerConfig"`),
		regexp.MustCompile(`(?i)docker.*version`),
	}

	// Local file patterns
	d.responsePatterns[ssrf.TargetLocalFile] = []*regexp.Regexp{
		regexp.MustCompile(`root:x:0:0:`),
		regexp.MustCompile(`(?i)\[fonts\]`),
		regexp.MustCompile(`(?i)\[extensions\]`),
		regexp.MustCompile(`localhost`),
		regexp.MustCompile(`127\.0\.0\.1`),
	}
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
	TargetTypes      []ssrf.TargetType
	TestCloudTypes   []string // aws, gcp, azure, etc.
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		TargetTypes:      []ssrf.TargetType{ssrf.TargetCloud, ssrf.TargetInternal},
		TestCloudTypes:   []string{"aws", "gcp", "azure"},
	}
}

// DetectionResult contains SSRF detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
	DetectedTarget ssrf.TargetType
	CloudProvider  string
}

// Detect tests a parameter for SSRF vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Collect payloads based on target types
	var payloads []ssrf.Payload
	for _, targetType := range opts.TargetTypes {
		payloads = append(payloads, ssrf.GetPayloads(targetType)...)
	}

	// Add WAF bypass payloads if requested
	if opts.IncludeWAFBypass {
		payloads = append(payloads, ssrf.GetWAFBypassPayloads()...)
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "https://example.com", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test each payload
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		resp, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
		if err != nil {
			continue
		}

		// Check if response indicates SSRF success
		if d.isSSRFSuccess(resp, baselineResp, payload) {
			finding := d.createFinding(target, param, payload, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.DetectedTarget = payload.Target
			result.CloudProvider = payload.CloudType

			// Continue testing to find all vulnerabilities
			// but limit to first few for efficiency
			if len(result.Findings) >= 3 {
				return result, nil
			}
		}
	}

	return result, nil
}

// isSSRFSuccess determines if the response indicates a successful SSRF attack.
func (d *Detector) isSSRFSuccess(resp, baseline *http.Response, payload ssrf.Payload) bool {
	if resp == nil {
		return false
	}

	// Check for patterns based on target type
	if patterns, ok := d.responsePatterns[payload.Target]; ok {
		for _, pattern := range patterns {
			if pattern.MatchString(resp.Body) {
				// Make sure it's not in baseline
				if baseline != nil && pattern.MatchString(baseline.Body) {
					continue
				}
				return true
			}
		}
	}

	// Cloud-specific checks
	if payload.Target == ssrf.TargetCloud {
		return d.hasCloudMetadataIndicators(resp.Body, payload.CloudType)
	}

	// Check for significant response differences
	if baseline != nil {
		// Response much larger than baseline might indicate data retrieval
		if len(resp.Body) > len(baseline.Body)*2 && len(resp.Body) > 500 {
			// Additional check: response should contain meaningful data
			if d.containsInternalData(resp.Body) {
				return true
			}
		}

		// Different status codes might indicate SSRF
		if resp.StatusCode != baseline.StatusCode && resp.StatusCode == 200 {
			if d.containsInternalData(resp.Body) {
				return true
			}
		}
	}

	// Check for error messages that indicate SSRF capability (only if not in baseline)
	if baseline != nil && d.hasSSRFErrorIndicators(resp.Body) && !d.hasSSRFErrorIndicators(baseline.Body) {
		return true
	}

	return false
}

// hasCloudMetadataIndicators checks for cloud-specific metadata patterns.
func (d *Detector) hasCloudMetadataIndicators(body, cloudType string) bool {
	cloudPatterns := map[string][]string{
		"aws": {
			"ami-id", "instance-id", "iam/security-credentials",
			"AccessKeyId", "SecretAccessKey", "ec2.internal",
		},
		"gcp": {
			"computeMetadata", "project-id", "service-accounts",
			"google.internal",
		},
		"azure": {
			"subscriptionId", "resourceGroupName", "vmId",
			"azure.com",
		},
	}

	patterns, ok := cloudPatterns[cloudType]
	if !ok {
		patterns = cloudPatterns["aws"] // Default to AWS patterns
	}

	matchCount := 0
	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			matchCount++
		}
	}

	// Require multiple matches to reduce false positives
	return matchCount >= 2
}

// containsInternalData checks if response contains data from internal sources.
func (d *Detector) containsInternalData(body string) bool {
	internalIndicators := []string{
		// File content
		"root:x:0:0:", "/bin/bash", "/home/",
		// Network info
		"127.0.0.1", "192.168.", "10.0.", "172.16.",
		// Service info
		"redis_version:", "mysql_native_password",
		// Cloud metadata
		"ami-id", "instance-id", "computeMetadata",
	}

	matchCount := 0
	for _, indicator := range internalIndicators {
		if strings.Contains(body, indicator) {
			matchCount++
		}
	}

	return matchCount >= 2
}

// hasSSRFErrorIndicators checks for error messages that indicate SSRF capability.
func (d *Detector) hasSSRFErrorIndicators(body string) bool {
	errorPatterns := []string{
		"Connection refused",
		"Connection timed out",
		"No route to host",
		"Name or service not known",
		"getaddrinfo failed",
		"couldn't connect to host",
		"Failed to connect",
		"Could not resolve host",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []ssrf.Payload) []ssrf.Payload {
	seen := make(map[string]bool)
	var unique []ssrf.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful SSRF test.
func (d *Detector) createFinding(target, param string, payload ssrf.Payload, resp *http.Response) *core.Finding {
	severity := core.SeverityHigh
	if payload.Target == ssrf.TargetCloud {
		severity = core.SeverityCritical
	}

	finding := core.NewFinding("Server-Side Request Forgery (SSRF)", severity)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("SSRF vulnerability in '%s' parameter (Target: %s, Protocol: %s)",
		param, payload.Target, payload.Protocol)

	if payload.CloudType != "" {
		finding.Description += fmt.Sprintf(" - Cloud: %s", payload.CloudType)
	}

	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "ssrf-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Validate and sanitize all user-supplied URLs. " +
		"Use allowlists for permitted domains and IP ranges. " +
		"Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). " +
		"Block requests to cloud metadata endpoints (169.254.169.254). " +
		"Use network-level controls to restrict outbound requests."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-19"}, // SSRF testing
		[]string{"A10:2025"},     // Server-Side Request Forgery
		[]string{"CWE-918"},      // SSRF
	)

	return finding
}
