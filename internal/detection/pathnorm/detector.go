package pathnorm

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// bypassPayload represents a path normalization bypass technique.
type bypassPayload struct {
	// Template is a format string where %s is replaced with the path segment.
	Template    string
	Description string
}

// payloads is the curated list of path-normalization bypass templates. The
// full list lives in payloads.go (defaultPayloads); this var is kept as a
// thin alias so existing tests and downstream callers that referenced it
// directly continue to work.
var payloads = defaultPayloads()

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

		// If the original was 401/403 and the bypass returns 200, the
		// status-code transition alone is suggestive but NOT sufficient.
		// Many SPAs and reverse proxies return the same forbidden body
		// at status 200 (an "internal redirect to login" pattern); without
		// a body-shape check, every such app trips on every payload.
		//
		// We require BOTH: status 200 AND the response body must have
		// diverged from the canonical 401/403 body. The createFinding
		// path then grades severity by whether admin markers are present.
		if resp.StatusCode != 200 {
			continue
		}
		if !bodyShapeDiverged(originalResp.Body, resp.Body) {
			continue
		}
		finding := d.createFinding(target, bypassURL, payload, originalResp, resp)
		result.Findings = append(result.Findings, finding)
		result.Vulnerable = true
	}

	return result, nil
}

// createFinding renders a Finding from a successful path-normalization
// bypass. Severity is graded by content:
//   - Critical when the bypass body contains ≥ 2 admin/dashboard markers
//     (almost certainly a real auth-bypass-of-protected-resource).
//   - High otherwise (status 200 + diverged body — strongly suggestive but
//     could conceivably be a soft 404 that happens to differ from the 401
//     page). The body-shape FP guard already filtered out the obvious FP.
func (d *Detector) createFinding(originalURL, bypassURL string, payload bypassPayload, originalResp, bypassResp *http.Response) *core.Finding {
	severity := core.SeverityHigh
	title := "Path Normalization Bypass"
	if hasAdminMarkers(bypassResp.Body) {
		severity = core.SeverityCritical
		title = "Path Normalization Bypass (Authenticated Content Reached)"
	}

	finding := core.NewFinding(title, severity)
	finding.URL = originalURL
	finding.Description = fmt.Sprintf("Path normalization bypass detected: %s (original: %d, bypass: %d)",
		payload.Description, originalResp.StatusCode, bypassResp.StatusCode)
	finding.Evidence = fmt.Sprintf("Original URL: %s (Status: %d, body=%d bytes)\nBypass URL: %s (Status: %d, body=%d bytes)\nTechnique: %s\nAdmin markers present: %t",
		originalURL, originalResp.StatusCode, len(originalResp.Body),
		bypassURL, bypassResp.StatusCode, len(bypassResp.Body),
		payload.Description, hasAdminMarkers(bypassResp.Body))
	finding.Tool = "pathnorm-detector"
	finding.Remediation = "Normalize paths (resolve dot-segments, decode percent-encoding, strip path parameters) before the access-control check runs. Run the same normalizer on every layer that makes routing or auth decisions — the typical bug is one layer (the auth filter) seeing the raw URL while another (the controller dispatcher) sees the normalized one. As defense in depth, configure the reverse proxy to reject URLs containing semicolons, double slashes, or encoded slashes."

	finding.WithOWASPMapping(
		[]string{"WSTG-ATHZ-02", "WSTG-ATHZ-03"},
		[]string{"A01:2025"},
		[]string{"CWE-22", "CWE-285"},
	)

	return finding
}
