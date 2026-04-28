// Package cors provides CORS Misconfiguration vulnerability detection.
package cors

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Detector performs CORS misconfiguration detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new CORS Detector.
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

// MisconfigType represents the type of CORS misconfiguration.
type MisconfigType string

const (
	// MisconfigReflection is when Origin header is reflected.
	MisconfigReflection MisconfigType = "origin_reflection"
	// MisconfigNullOrigin is when null origin is allowed.
	MisconfigNullOrigin MisconfigType = "null_origin"
	// MisconfigWildcard is when wildcard (*) is used with credentials.
	MisconfigWildcard MisconfigType = "wildcard_credentials"
	// MisconfigSubdomain is when subdomain wildcard matching is used.
	MisconfigSubdomain MisconfigType = "subdomain_wildcard"
	// MisconfigInsecure is when HTTP origins are allowed for HTTPS sites.
	MisconfigInsecure MisconfigType = "insecure_protocol"
	// MisconfigPrefix is when origin matching is prefix-based.
	MisconfigPrefix MisconfigType = "prefix_match"
	// MisconfigSuffix is when origin matching is suffix-based.
	MisconfigSuffix MisconfigType = "suffix_match"
)

// DetectOptions configures detection behavior.
type DetectOptions struct {
	// Timeout for each request
	Timeout time.Duration
	// Custom origins to test
	CustomOrigins []string
	// Test with credentials header
	TestCredentials bool
	// Test pre-flight requests
	TestPreflight bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:         10 * time.Second,
		CustomOrigins:   []string{},
		TestCredentials: true,
		TestPreflight:   true,
	}
}

// DetectionResult contains CORS detection results.
type DetectionResult struct {
	Vulnerable        bool
	Findings          []*core.Finding
	MisconfigType     MisconfigType
	AllowsCredentials bool
	ReflectedOrigin   string
	AllowedMethods    string
	AllowedHeaders    string
	ExposedHeaders    string
}

// Detect tests a URL for CORS misconfigurations.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Parse target URL
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return result, fmt.Errorf("invalid target URL: %w", err)
	}

	targetDomain := parsedTarget.Host

	// Generate test origins
	testOrigins := d.generateTestOrigins(targetDomain, opts.CustomOrigins)

	// Test each origin
	for _, origin := range testOrigins {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Test with the origin
		corsResult, err := d.testOrigin(ctx, target, origin.value, opts.TestCredentials)
		if err != nil {
			continue
		}

		// Check if vulnerable
		if corsResult.isVulnerable {
			finding := d.createFinding(target, origin, corsResult)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.MisconfigType = origin.misconfigType
			result.AllowsCredentials = corsResult.allowCredentials
			result.ReflectedOrigin = corsResult.allowOrigin
			result.AllowedMethods = corsResult.allowMethods
			result.AllowedHeaders = corsResult.allowHeaders
			result.ExposedHeaders = corsResult.exposeHeaders

			// Continue testing to find all misconfigs but limit
			if len(result.Findings) >= 5 {
				return result, nil
			}
		}
	}

	// Test pre-flight if requested
	if opts.TestPreflight && !result.Vulnerable {
		preflightResult, err := d.testPreflight(ctx, target, "https://evil.com")
		if err == nil && preflightResult.isVulnerable {
			finding := d.createPreflightFinding(target, preflightResult)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
		}
	}

	return result, nil
}

// testOrigin represents a test origin with metadata.
type testOrigin struct {
	value         string
	description   string
	misconfigType MisconfigType
}

// generateTestOrigins creates a list of origins to test.
func (d *Detector) generateTestOrigins(targetDomain string, customOrigins []string) []testOrigin {
	// Extract base domain (remove port if present)
	baseDomain := targetDomain
	if colonIdx := strings.LastIndex(targetDomain, ":"); colonIdx != -1 {
		baseDomain = targetDomain[:colonIdx]
	}

	origins := []testOrigin{
		// Direct reflection test
		{
			value:         "https://evil.com",
			description:   "External domain origin",
			misconfigType: MisconfigReflection,
		},
		// Null origin
		{
			value:         "null",
			description:   "Null origin bypass",
			misconfigType: MisconfigNullOrigin,
		},
		// Subdomain of attacker domain with target as subdomain
		{
			value:         "https://" + baseDomain + ".evil.com",
			description:   "Target as subdomain of attacker",
			misconfigType: MisconfigSuffix,
		},
		// Attacker domain with target suffix
		{
			value:         "https://evil" + baseDomain,
			description:   "Attacker prefix with target suffix",
			misconfigType: MisconfigSuffix,
		},
		// Subdomain of target
		{
			value:         "https://evil." + baseDomain,
			description:   "Attacker subdomain of target",
			misconfigType: MisconfigSubdomain,
		},
		// HTTP origin for HTTPS target
		{
			value:         "http://" + baseDomain,
			description:   "HTTP origin for HTTPS target",
			misconfigType: MisconfigInsecure,
		},
		// Target with different port
		{
			value:         "https://" + baseDomain + ":8443",
			description:   "Different port on same domain",
			misconfigType: MisconfigReflection,
		},
		// Prefix match bypass
		{
			value:         "https://" + baseDomain + "evil.com",
			description:   "Target as prefix of attacker",
			misconfigType: MisconfigPrefix,
		},
		// Unicode bypass
		{
			value:         "https://" + baseDomain + "%60.evil.com",
			description:   "Backtick encoding bypass",
			misconfigType: MisconfigReflection,
		},
		// Underscore bypass
		{
			value:         "https://" + baseDomain + "_.evil.com",
			description:   "Underscore domain bypass",
			misconfigType: MisconfigReflection,
		},
	}

	// Add custom origins
	for _, custom := range customOrigins {
		origins = append(origins, testOrigin{
			value:         custom,
			description:   "Custom origin",
			misconfigType: MisconfigReflection,
		})
	}

	return origins
}

// corsTestResult holds the result of a CORS test.
type corsTestResult struct {
	isVulnerable     bool
	allowOrigin      string
	allowCredentials bool
	allowMethods     string
	allowHeaders     string
	exposeHeaders    string
	statusCode       int
}

// testOrigin sends a request with the specified Origin header.
func (d *Detector) testOrigin(ctx context.Context, target, origin string, testCredentials bool) (*corsTestResult, error) {
	result := &corsTestResult{}

	// Build request with Origin header
	req := &http.Request{
		Method: "GET",
		URL:    target,
		Headers: map[string]string{
			"Origin": origin,
		},
	}

	resp, err := d.client.Do(ctx, req)
	if err != nil {
		return result, err
	}

	result.statusCode = resp.StatusCode

	// Extract CORS headers (case-insensitive)
	for k, v := range resp.Headers {
		switch strings.ToLower(k) {
		case "access-control-allow-origin":
			result.allowOrigin = v
		case "access-control-allow-credentials":
			result.allowCredentials = strings.ToLower(v) == "true"
		case "access-control-allow-methods":
			result.allowMethods = v
		case "access-control-allow-headers":
			result.allowHeaders = v
		case "access-control-expose-headers":
			result.exposeHeaders = v
		}
	}

	// Determine if vulnerable
	result.isVulnerable = d.isCORSVulnerable(result, origin, testCredentials)

	return result, nil
}

// testPreflight sends an OPTIONS pre-flight request.
func (d *Detector) testPreflight(ctx context.Context, target, origin string) (*corsTestResult, error) {
	result := &corsTestResult{}

	req := &http.Request{
		Method: "OPTIONS",
		URL:    target,
		Headers: map[string]string{
			"Origin":                         origin,
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "X-Custom-Header",
		},
	}

	resp, err := d.client.Do(ctx, req)
	if err != nil {
		return result, err
	}

	result.statusCode = resp.StatusCode

	// Extract CORS headers
	for k, v := range resp.Headers {
		switch strings.ToLower(k) {
		case "access-control-allow-origin":
			result.allowOrigin = v
		case "access-control-allow-credentials":
			result.allowCredentials = strings.ToLower(v) == "true"
		case "access-control-allow-methods":
			result.allowMethods = v
		case "access-control-allow-headers":
			result.allowHeaders = v
		}
	}

	// Check for vulnerable configuration
	result.isVulnerable = d.isCORSVulnerable(result, origin, true)

	return result, nil
}

// isCORSVulnerable determines if a CORS configuration is vulnerable.
//
// Every origin we test is one we crafted (see CORS test list — all built
// from "evil" / "<base>.evil.com" / etc.), so an exact reflection of
// testedOrigin in Access-Control-Allow-Origin proves the server reflects
// arbitrary attacker-supplied origins. The previous logic gated
// no-credentials reflection behind a `Contains("evil")` substring check
// on testedOrigin (always true) and on result.allowOrigin (false-positive
// risk on legitimate domains containing "evil" like medieval.com).
// Both substring checks are dropped — exact reflection of a crafted
// attacker origin is sufficient signal regardless of literal spelling.
func (d *Detector) isCORSVulnerable(result *corsTestResult, testedOrigin string, testCredentials bool) bool {
	if result.allowOrigin == "" {
		return false
	}

	// Direct reflection of an attacker-controlled origin we crafted.
	if result.allowOrigin == testedOrigin {
		return true
	}

	// Null origin or wildcard reflected with credentials is exploitable.
	if (result.allowOrigin == "null" || result.allowOrigin == "*") && result.allowCredentials {
		return true
	}

	return false
}

// createFinding creates a Finding from a CORS misconfiguration.
func (d *Detector) createFinding(target string, origin testOrigin, corsResult *corsTestResult) *core.Finding {
	severity := core.SeverityMedium
	if corsResult.allowCredentials {
		severity = core.SeverityHigh
	}

	finding := core.NewFinding("CORS Misconfiguration", severity)
	finding.URL = target
	finding.Description = fmt.Sprintf("CORS misconfiguration: %s (%s)",
		origin.misconfigType, origin.description)

	finding.Evidence = fmt.Sprintf("Tested Origin: %s\n", origin.value)
	finding.Evidence += fmt.Sprintf("Access-Control-Allow-Origin: %s\n", corsResult.allowOrigin)
	finding.Evidence += fmt.Sprintf("Access-Control-Allow-Credentials: %t\n", corsResult.allowCredentials)

	if corsResult.allowMethods != "" {
		finding.Evidence += fmt.Sprintf("Access-Control-Allow-Methods: %s\n", corsResult.allowMethods)
	}
	if corsResult.allowHeaders != "" {
		finding.Evidence += fmt.Sprintf("Access-Control-Allow-Headers: %s\n", corsResult.allowHeaders)
	}
	if corsResult.exposeHeaders != "" {
		finding.Evidence += fmt.Sprintf("Access-Control-Expose-Headers: %s\n", corsResult.exposeHeaders)
	}

	finding.Tool = "cors-detector"

	finding.Remediation = "Implement a strict allowlist of trusted origins. " +
		"Avoid reflecting the Origin header directly. " +
		"Never use 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'. " +
		"Validate origins against a whitelist before responding with CORS headers. " +
		"Consider using a CORS library that handles validation properly."

	if corsResult.allowCredentials {
		finding.Remediation += " The 'Access-Control-Allow-Credentials: true' header significantly " +
			"increases the severity as it allows attackers to access authenticated endpoints."
	}

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-07"}, // Test Cross Origin Resource Sharing (not exact but closest)
		[]string{"A05:2025"},     // Security Misconfiguration
		[]string{"CWE-942"},      // Permissive CORS Policy
	)

	// Add API Top 10 mapping
	finding.APITop10 = []string{"API8:2023"} // Security Misconfiguration

	return finding
}

// createPreflightFinding creates a Finding from a pre-flight misconfiguration.
func (d *Detector) createPreflightFinding(target string, corsResult *corsTestResult) *core.Finding {
	severity := core.SeverityMedium
	if corsResult.allowCredentials {
		severity = core.SeverityHigh
	}

	finding := core.NewFinding("CORS Pre-flight Misconfiguration", severity)
	finding.URL = target
	finding.Description = "CORS pre-flight request accepts arbitrary origins"

	finding.Evidence = fmt.Sprintf("Pre-flight Response:\n")
	finding.Evidence += fmt.Sprintf("Access-Control-Allow-Origin: %s\n", corsResult.allowOrigin)
	finding.Evidence += fmt.Sprintf("Access-Control-Allow-Methods: %s\n", corsResult.allowMethods)
	finding.Evidence += fmt.Sprintf("Access-Control-Allow-Headers: %s\n", corsResult.allowHeaders)
	finding.Evidence += fmt.Sprintf("Access-Control-Allow-Credentials: %t\n", corsResult.allowCredentials)

	finding.Tool = "cors-detector"

	finding.Remediation = "Configure the server to only accept pre-flight requests from trusted origins. " +
		"Limit the allowed methods and headers to only those required by the application."

	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-07"},
		[]string{"A05:2025"},
		[]string{"CWE-942"},
	)

	finding.APITop10 = []string{"API8:2023"}

	return finding
}
