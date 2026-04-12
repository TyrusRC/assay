// Package subtakeover provides detection for subdomain takeover vulnerabilities.
package subtakeover

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/subtakeover"
)

// SubdomainInfo contains information about a subdomain to check.
type SubdomainInfo struct {
	Subdomain string
	CNAME     string
	URL       string // Override URL for testing
}

// Detector performs subdomain takeover detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Subdomain Takeover Detector.
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

// DetectOptions configures subdomain takeover detection behavior.
type DetectOptions struct {
	Timeout time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout: 10 * time.Second,
	}
}

// DetectionResult contains subdomain takeover detection results.
type DetectionResult struct {
	Vulnerable         bool
	Findings           []*core.Finding
	CheckedSubdomains  int
	VulnerableServices map[string]int
}

// Detect checks a list of subdomains for takeover vulnerabilities.
func (d *Detector) Detect(ctx context.Context, subdomains []SubdomainInfo, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:           make([]*core.Finding, 0),
		VulnerableServices: make(map[string]int),
	}

	services := subtakeover.GetServices()

	for _, sub := range subdomains {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.CheckedSubdomains++

		// Match CNAME to known vulnerable service
		matchedService := d.findMatchingService(sub.CNAME, services)
		if matchedService == nil {
			continue
		}

		// Check HTTP fingerprint if the service requires it
		if matchedService.HTTPCheck {
			targetURL := sub.URL
			if targetURL == "" {
				targetURL = fmt.Sprintf("https://%s", sub.Subdomain)
			}

			finding := d.checkHTTPFingerprint(ctx, targetURL, sub.CNAME, *matchedService)
			if finding != nil {
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				result.VulnerableServices[matchedService.Name]++
			}
		}
	}

	return result, nil
}

// findMatchingService finds a service matching the CNAME.
func (d *Detector) findMatchingService(cname string, services []subtakeover.Service) *subtakeover.Service {
	lowerCNAME := strings.ToLower(cname)
	for i, svc := range services {
		for _, pattern := range svc.CNames {
			if strings.HasSuffix(lowerCNAME, strings.ToLower(pattern)) {
				return &services[i]
			}
		}
	}
	return nil
}

// checkHTTPFingerprint checks if an HTTP response matches a takeover fingerprint.
func (d *Detector) checkHTTPFingerprint(ctx context.Context, targetURL, cname string, service subtakeover.Service) *core.Finding {
	resp, err := d.client.Get(ctx, targetURL)
	if err != nil {
		return nil
	}

	if d.matchesFingerprint(resp.Body, service.Fingerprint) {
		return d.createFinding(targetURL, cname, service, resp)
	}

	return nil
}

// matchesFingerprint checks if the response body matches any fingerprint.
func (d *Detector) matchesFingerprint(body string, fingerprints []string) bool {
	if len(fingerprints) == 0 {
		return false
	}

	for _, fp := range fingerprints {
		if strings.Contains(body, fp) {
			return true
		}
	}
	return false
}

// createFinding creates a Finding from a detected subdomain takeover.
func (d *Detector) createFinding(targetURL, cname string, service subtakeover.Service, resp *http.Response) *core.Finding {
	severity := d.mapSeverity(service.Severity)

	finding := core.NewFinding("Subdomain Takeover", severity)
	finding.URL = targetURL
	finding.Description = fmt.Sprintf(
		"Subdomain takeover vulnerability detected. CNAME '%s' points to %s, "+
			"but the resource is not claimed. An attacker could register this resource "+
			"and serve malicious content on the subdomain.",
		cname, service.Name,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf("CNAME: %s\nService: %s\nResponse snippet: %s",
		cname, service.Name, body)
	finding.Tool = "subtakeover-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = fmt.Sprintf(
		"Remove the DNS CNAME record pointing to %s if no longer needed. "+
			"If the service is still needed, reclaim the resource on %s. "+
			"Implement DNS monitoring to detect dangling CNAME records.",
		service.Name, service.Name,
	)

	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-10"}, // Test for Subdomain Takeover
		[]string{"A05:2025"},     // Security Misconfiguration
		[]string{"CWE-284"},      // Improper Access Control
	)

	return finding
}

// mapSeverity maps string severity to core severity.
func (d *Detector) mapSeverity(s string) core.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return core.SeverityCritical
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	default:
		return core.SeverityMedium
	}
}
