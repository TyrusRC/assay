package cmdi

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/cmdi"
)

// Detector performs Command Injection vulnerability detection.
type Detector struct {
	client         *http.Client
	verbose        bool
	outputPatterns []*regexp.Regexp
}

// New creates a new Command Injection Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client: client,
	}
	d.initOutputPatterns()
	return d
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// initOutputPatterns initializes patterns that indicate successful command execution.
func (d *Detector) initOutputPatterns() {
	d.outputPatterns = []*regexp.Regexp{
		// Linux patterns
		regexp.MustCompile(`uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)`),              // id command output
		regexp.MustCompile(`root:x:0:0:`),                                      // /etc/passwd content
		regexp.MustCompile(`Linux\s+\S+\s+\d+\.\d+`),                           // uname -a output
		regexp.MustCompile(`(?i)(total\s+\d+|drwx|lrwx|-rw-)`),                 // ls -la output
		regexp.MustCompile(`(?i)^(root|www-data|apache|nginx|nobody|daemon)$`), // whoami output
		regexp.MustCompile(`PRETTY_NAME=|DISTRIB_ID=|ID=`),                     // /etc/os-release content
		regexp.MustCompile(`(?m)^(PATH|HOME|USER|SHELL|PWD|LANG)=`),            // env output
		regexp.MustCompile(`(?i)inet\s+\d+\.\d+\.\d+\.\d+`),                    // ifconfig output
		regexp.MustCompile(`/bin/(ba)?sh`),                                     // shell path in output
		regexp.MustCompile(`(?i)listening\s+on.*:\d+`),                         // netstat output

		// Windows patterns
		regexp.MustCompile(`(?i)[A-Z]:\\(Windows|Users|Program Files)`), // Windows paths
		regexp.MustCompile(`(?i)COMPUTERNAME=|USERNAME=|USERDOMAIN=`),   // Windows env vars
		regexp.MustCompile(`(?i)Microsoft\s+Windows\s+\[Version`),       // Windows version
		regexp.MustCompile(`(?i)Volume\s+in\s+drive\s+[A-Z]`),           // dir output
		regexp.MustCompile(`(?i)(BUILTIN\\|NT AUTHORITY\\)`),            // Windows SIDs
		regexp.MustCompile(`(?i)\[fonts\]|\[extensions\]`),              // win.ini content
		regexp.MustCompile(`(?i)Windows IP Configuration`),              // ipconfig output
	}
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
	Platform         cmdi.Platform
	EnableTimeBased  bool
	TimeBasedDelay   time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		Platform:         cmdi.PlatformBoth,
		EnableTimeBased:  true,
		TimeBasedDelay:   5 * time.Second,
	}
}

// DetectionResult contains CMDI detection results.
type DetectionResult struct {
	Vulnerable       bool
	Findings         []*core.Finding
	TestedPayloads   int
	DetectedPlatform cmdi.Platform
}

// Detect tests a parameter for Command Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads based on platform
	payloads := cmdi.GetPayloads(opts.Platform)

	// Add WAF bypass payloads if requested
	if opts.IncludeWAFBypass {
		payloads = append(payloads, cmdi.GetWAFBypassPayloads()...)
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// First, get baseline response
	baselineResp, err := d.client.SendPayload(ctx, target, param, "baseline_test_value", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}
	baselineTime := baselineResp.Duration

	// Test output-based payloads first (faster)
	for _, payload := range payloads {
		if payload.Type == cmdi.TypeTimeBased {
			continue // Skip time-based for now
		}

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

		// Check for command output in response (compare against baseline)
		if d.hasCommandOutput(resp.Body, baselineResp.Body, payload) {
			finding := d.createFinding(target, param, payload, resp, "output-based")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.DetectedPlatform = payload.Platform

			// Stop after first finding
			return result, nil
		}
	}

	// Test time-based payloads if enabled
	if opts.EnableTimeBased {
		timePayloads := cmdi.GetByType(opts.Platform, cmdi.TypeTimeBased)
		for _, payload := range timePayloads {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			result.TestedPayloads++

			start := time.Now()
			_, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
			elapsed := time.Since(start)

			if err != nil {
				continue
			}

			// Check if response was significantly delayed
			expectedDelay := opts.TimeBasedDelay
			tolerance := time.Second * 2

			if elapsed > baselineTime+expectedDelay-tolerance && elapsed < baselineTime+expectedDelay+tolerance*2 {
				finding := d.createFinding(target, param, payload, nil, "time-based")
				finding.Evidence = fmt.Sprintf("Response delayed by %v (baseline: %v, expected delay: %v)",
					elapsed, baselineTime, expectedDelay)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				result.DetectedPlatform = payload.Platform
				return result, nil
			}
		}
	}

	return result, nil
}

// hasCommandOutput checks if the response contains command execution output
// that was not present in the baseline response.
func (d *Detector) hasCommandOutput(body, baseline string, payload cmdi.Payload) bool {
	// Check against known output patterns, ensuring they are NOT in the baseline
	for _, pattern := range d.outputPatterns {
		if pattern.MatchString(body) && !pattern.MatchString(baseline) {
			return true
		}
	}

	// Platform-specific additional checks (also compare against baseline)
	switch payload.Platform {
	case cmdi.PlatformLinux:
		if strings.Contains(body, "uid=") && strings.Contains(body, "gid=") &&
			!(strings.Contains(baseline, "uid=") && strings.Contains(baseline, "gid=")) {
			return true
		}
		if strings.Contains(body, "root:") && strings.Contains(body, ":/bin/") &&
			!(strings.Contains(baseline, "root:") && strings.Contains(baseline, ":/bin/")) {
			return true
		}
	case cmdi.PlatformWindows:
		if (strings.Contains(body, "Volume in drive") && !strings.Contains(baseline, "Volume in drive")) ||
			(strings.Contains(body, "Directory of") && !strings.Contains(baseline, "Directory of")) {
			return true
		}
		if strings.Contains(body, "Windows IP Configuration") && !strings.Contains(baseline, "Windows IP Configuration") {
			return true
		}
	}

	return false
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []cmdi.Payload) []cmdi.Payload {
	seen := make(map[string]bool)
	var unique []cmdi.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful CMDI test.
func (d *Detector) createFinding(target, param string, payload cmdi.Payload, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("Command Injection", core.SeverityCritical)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("%s Command Injection vulnerability in '%s' parameter (Platform: %s, Type: %s)",
		detectionType, param, payload.Platform, payload.Type)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "cmdi-detector"

	if resp != nil && len(resp.Body) > 0 {
		// Truncate evidence if too long
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Never pass user input directly to system commands. " +
		"Use allowlists for valid inputs. " +
		"Escape or sanitize all user input. " +
		"Use language-specific APIs instead of shell commands."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-12"}, // OS Command Injection
		[]string{"A03:2025"},     // Injection
		[]string{"CWE-78"},       // OS Command Injection
	)

	return finding
}
