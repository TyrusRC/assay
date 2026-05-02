package lfi

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/lfi"
)

// Detector performs LFI/Path Traversal vulnerability detection.
type Detector struct {
	client       *http.Client
	verbose      bool
	filePatterns map[string][]*regexp.Regexp
}

// New creates a new LFI Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client: client,
	}
	d.initFilePatterns()
	return d
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// initFilePatterns initializes patterns for detecting file content.
func (d *Detector) initFilePatterns() {
	d.filePatterns = make(map[string][]*regexp.Regexp)

	// /etc/passwd patterns
	d.filePatterns["/etc/passwd"] = []*regexp.Regexp{
		regexp.MustCompile(`root:x:0:0:`),
		regexp.MustCompile(`root:[^:]*:0:0:`),
		regexp.MustCompile(`daemon:x:\d+:\d+:`),
		regexp.MustCompile(`nobody:x:\d+:\d+:`),
		regexp.MustCompile(`www-data:x:\d+:\d+:`),
		regexp.MustCompile(`(?m)^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:[^:]*:[^:]*:[^:]*$`),
	}

	// /etc/shadow patterns
	d.filePatterns["/etc/shadow"] = []*regexp.Regexp{
		regexp.MustCompile(`root:\$[0-9a-z]+\$`),
		regexp.MustCompile(`root:[\*!]:`),
		regexp.MustCompile(`(?m)^[a-z_][a-z0-9_-]*:[\$\*!][^:]*:\d+:\d*:\d*:`),
	}

	// /etc/hosts patterns
	d.filePatterns["/etc/hosts"] = []*regexp.Regexp{
		regexp.MustCompile(`127\.0\.0\.1\s+localhost`),
		regexp.MustCompile(`::1\s+localhost`),
		regexp.MustCompile(`(?m)^\d+\.\d+\.\d+\.\d+\s+\S+`),
	}

	// Windows win.ini patterns
	d.filePatterns["C:\\Windows\\win.ini"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\[fonts\]`),
		regexp.MustCompile(`(?i)\[extensions\]`),
		regexp.MustCompile(`(?i)\[mci extensions\]`),
		regexp.MustCompile(`(?i)\[files\]`),
	}

	// Windows hosts patterns
	d.filePatterns["C:\\Windows\\System32\\drivers\\etc\\hosts"] = []*regexp.Regexp{
		regexp.MustCompile(`127\.0\.0\.1\s+localhost`),
		regexp.MustCompile(`(?i)#.*Copyright`),
	}

	// PHP source code patterns (for wrapper payloads)
	d.filePatterns["php_source"] = []*regexp.Regexp{
		regexp.MustCompile(`<\?php`),
		regexp.MustCompile(`<\?=`),
		regexp.MustCompile(`\$_(?:GET|POST|REQUEST|SERVER|SESSION|COOKIE)\[`),
		regexp.MustCompile(`(?i)include\s*\(`),
		regexp.MustCompile(`(?i)require\s*\(`),
	}

	// /proc/ patterns
	d.filePatterns["/proc/self/environ"] = []*regexp.Regexp{
		regexp.MustCompile(`PATH=`),
		regexp.MustCompile(`HOME=`),
		regexp.MustCompile(`USER=`),
		regexp.MustCompile(`PWD=`),
		regexp.MustCompile(`SHELL=`),
	}

	// SSH key patterns
	d.filePatterns["ssh_key"] = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
		regexp.MustCompile(`ssh-rsa AAAA`),
	}

	// Log file patterns
	d.filePatterns["log_file"] = []*regexp.Regexp{
		regexp.MustCompile(`\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}`), // Apache log format
		regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`), // Nginx log format
		regexp.MustCompile(`(?i)GET|POST|PUT|DELETE.*HTTP/`),
	}
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
	Platform         lfi.Platform
	TestWrappers     bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		Platform:         lfi.PlatformBoth,
		TestWrappers:     true,
	}
}

// DetectionResult contains LFI detection results.
type DetectionResult struct {
	Vulnerable       bool
	Findings         []*core.Finding
	TestedPayloads   int
	DetectedFile     string
	DetectedPlatform lfi.Platform
	Technique        lfi.Technique
}

// Detect tests a parameter for LFI/Path Traversal vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads based on platform
	payloads := lfi.GetPayloads(opts.Platform)

	// Add wrapper payloads if testing PHP
	if opts.TestWrappers {
		payloads = append(payloads, lfi.GetByTechnique(lfi.TechWrapper)...)
	}

	// Add WAF bypass payloads if requested
	if opts.IncludeWAFBypass {
		payloads = append(payloads, lfi.GetWAFBypassPayloads()...)
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "nonexistent_file_baseline_test", method)
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

		// Check if response contains file content
		detectedFile := d.detectFileContent(resp.Body, payload, baselineResp)
		if detectedFile != "" {
			finding := d.createFinding(target, param, payload, resp, detectedFile)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.DetectedFile = detectedFile
			result.DetectedPlatform = payload.Platform
			result.Technique = payload.Technique

			// Stop after first finding for efficiency
			return result, nil
		}
	}

	return result, nil
}

// detectFileContent checks if the response contains expected file content.
func (d *Detector) detectFileContent(body string, payload lfi.Payload, baseline *http.Response) string {
	// Skip if response is same as baseline
	if baseline != nil && body == baseline.Body {
		return ""
	}

	// Handle base64-encoded responses from PHP filter
	if strings.Contains(payload.Value, "convert.base64-encode") {
		// Try to find and decode base64 content
		decoded := d.tryDecodeBase64(body)
		if decoded != "" {
			body = decoded
		}
	}

	// Check for specific file patterns based on payload target. Same
	// baseline guard as the generic-pattern branch below — without it,
	// a page that legitimately mentions /etc/passwd in docs or error
	// messages would FP on every probe.
	if payload.TargetFile != "" {
		patterns := d.getFilePatterns(payload.TargetFile)
		for _, pattern := range patterns {
			if pattern.MatchString(body) {
				if baseline == nil || !pattern.MatchString(baseline.Body) {
					return payload.TargetFile
				}
			}
		}
	}

	// Check for generic file content patterns
	for filePath, patterns := range d.filePatterns {
		for _, pattern := range patterns {
			if pattern.MatchString(body) {
				if baseline == nil || !pattern.MatchString(baseline.Body) {
					return filePath
				}
			}
		}
	}

	return ""
}

// getFilePatterns returns patterns for a specific file path.
func (d *Detector) getFilePatterns(targetFile string) []*regexp.Regexp {
	// Normalize path
	normalized := targetFile
	if strings.HasPrefix(normalized, "/") {
		normalized = targetFile
	}

	// Try exact match
	if patterns, ok := d.filePatterns[normalized]; ok {
		return patterns
	}

	// Try matching by file name
	for key, patterns := range d.filePatterns {
		if strings.HasSuffix(targetFile, key) || strings.HasSuffix(key, targetFile) {
			return patterns
		}
	}

	// Return generic patterns for unknown files
	return []*regexp.Regexp{
		regexp.MustCompile(`root:x:0:0:`),             // passwd
		regexp.MustCompile(`(?i)\[fonts\]`),           // win.ini
		regexp.MustCompile(`<\?php`),                  // PHP files
		regexp.MustCompile(`127\.0\.0\.1.*localhost`), // hosts
	}
}

// base64ContentRe matches base64-like strings for decoding attempts.
var base64ContentRe = regexp.MustCompile(`[A-Za-z0-9+/=]{50,}`)

// tryDecodeBase64 attempts to find and decode base64 content in the response.
func (d *Detector) tryDecodeBase64(body string) string {
	// Look for base64-like strings (long alphanumeric strings)
	base64Pattern := base64ContentRe
	matches := base64Pattern.FindAllString(body, -1)

	for _, match := range matches {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err == nil && len(decoded) > 0 {
			// Check if decoded content looks like valid file content
			decodedStr := string(decoded)
			if d.looksLikeFileContent(decodedStr) {
				return decodedStr
			}
		}
	}

	return ""
}

// looksLikeFileContent checks if content appears to be valid file content.
func (d *Detector) looksLikeFileContent(content string) bool {
	// Check for common file content patterns
	fileIndicators := []string{
		"root:", "<?php", "[fonts]", "127.0.0.1",
		"PATH=", "HOME=", "-----BEGIN", "#!/",
	}

	for _, indicator := range fileIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []lfi.Payload) []lfi.Payload {
	seen := make(map[string]bool)
	var unique []lfi.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful LFI test.
func (d *Detector) createFinding(target, param string, payload lfi.Payload, resp *http.Response, detectedFile string) *core.Finding {
	finding := core.NewFinding("Local File Inclusion / Path Traversal", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("LFI/Path Traversal vulnerability in '%s' parameter (Technique: %s, Platform: %s)",
		param, payload.Technique, payload.Platform)

	if detectedFile != "" {
		finding.Description += fmt.Sprintf(" - File accessed: %s", detectedFile)
	}

	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s\nTarget File: %s",
		payload.Value, payload.Description, payload.TargetFile)
	finding.Tool = "lfi-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Never use user input directly in file paths. " +
		"Use allowlists for permitted files. " +
		"Validate and sanitize all file path inputs. " +
		"Use chroot jails or containerization. " +
		"Disable PHP wrappers if not needed (allow_url_include=Off)."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},     // LFI testing
		[]string{"A01:2025"},         // Broken Access Control
		[]string{"CWE-22", "CWE-98"}, // Path Traversal, LFI
	)

	return finding
}
