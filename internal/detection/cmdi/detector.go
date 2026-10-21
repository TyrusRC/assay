package cmdi

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/dedup"
	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/payloads/cmdi"
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

// DetectParam tests a parameter for Command Injection vulnerabilities using
// location-aware payload dispatch. Use this over Detect when the parameter's
// location (path, header, JSON body, etc.) matters.
func (d *Detector) DetectParam(ctx context.Context, target string, param core.Parameter, method string, opts DetectOptions) (*DetectionResult, error) {
	return d.detectImpl(ctx, target, param.Name, method, opts, func(ctx context.Context, payload string) (*http.Response, error) {
		return d.client.SendPayloadAt(ctx, target, param, payload, method)
	})
}

// Detect tests a parameter for Command Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	return d.detectImpl(ctx, target, param, method, opts, func(ctx context.Context, payload string) (*http.Response, error) {
		return d.client.SendPayload(ctx, target, param, payload, method)
	})
}

func (d *Detector) detectImpl(ctx context.Context, target, param, method string, opts DetectOptions, send func(context.Context, string) (*http.Response, error)) (*DetectionResult, error) {
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
	baselineResp, err := send(ctx, "baseline_test_value")
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

		resp, err := send(ctx, payload.Value)
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

	// Status-code differential: a command separator (;) that crashes the
	// shell or causes an unhandled error produces a 500 while clean input
	// returns 200. This catches blind CMDI where output is suppressed.
	if baselineResp.StatusCode >= 200 && baselineResp.StatusCode < 400 {
		for _, sep := range []string{";", "|", "`"} {
			probe := "baseline_test_value" + sep
			resp, err := send(ctx, probe)
			if err != nil || resp == nil {
				continue
			}
			result.TestedPayloads++
			if resp.StatusCode >= 500 {
				finding := d.createFinding(target, param, cmdi.Payload{
					Value:       probe,
					Description: fmt.Sprintf("Command separator %q caused server error (status %d vs baseline %d)", sep, resp.StatusCode, baselineResp.StatusCode),
					Platform:    cmdi.PlatformLinux,
					Type:        cmdi.TypeDirect,
				}, resp, "error-differential")
				finding.Confidence = core.ConfidenceMedium
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return result, nil
			}
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
			_, err := send(ctx, payload.Value)
			elapsed := time.Since(start)

			if err != nil {
				continue
			}

			// Check if response was significantly delayed
			expectedDelay := opts.TimeBasedDelay
			tolerance := time.Second * 2

			if elapsed > baselineTime+expectedDelay-tolerance && elapsed < baselineTime+expectedDelay+tolerance*2 {
				// Confirmation round: send the same probe again to
				// rule out transient network/server slowness.
				start2 := time.Now()
				_, err2 := send(ctx, payload.Value)
				elapsed2 := time.Since(start2)
				if err2 != nil {
					continue
				}
				if elapsed2 < baselineTime+expectedDelay-tolerance || elapsed2 > baselineTime+expectedDelay+tolerance*2 {
					continue
				}

				finding := d.createFinding(target, param, payload, nil, "time-based")
				finding.Evidence = fmt.Sprintf("Response delayed by %v and %v on confirmation (baseline: %v, expected delay: %v)",
					elapsed, elapsed2, baselineTime, expectedDelay)
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
	return dedup.ByKey(payloads, func(p cmdi.Payload) string { return p.Value })
}

// createFinding creates a Finding from a successful CMDI test.
func (d *Detector) createFinding(target, param string, payload cmdi.Payload, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("Command Injection", core.SeverityCritical).At(target, param)
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
		[]string{"A05:2025"},     // Injection
		[]string{"CWE-78"},       // OS Command Injection
	)

	return finding
}
