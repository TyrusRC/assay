package secondorder

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Detector performs second-order injection testing.
type Detector struct {
	client     *http.Client
	verbose    bool
	strategies []Strategy
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "secondorder"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Second-order injection detector using inject-then-verify strategies for blind XSS, stored SQLi, log injection, and JNDI attacks"
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	Strategies     []string      // strategy names to run, empty = all
	MaxPayloads    int           // max payloads per strategy
	Timeout        time.Duration // per-request timeout
	CallbackDomain string        // for OOB verification
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads: 50,
		Timeout:     10 * time.Second,
	}
}

// DetectionResult holds the results of second-order detection.
type DetectionResult struct {
	Vulnerable       bool
	Findings         []*core.Finding
	TestedStrategies int
}

// New creates a new second-order detector with default strategies.
func New(client *http.Client) *Detector {
	return &Detector{
		client:     client,
		strategies: DefaultStrategies(),
	}
}

// Detect runs second-order injection tests against the target URL.
func (d *Detector) Detect(ctx context.Context, targetURL string, opts DetectOptions) (*DetectionResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	strategies := d.filterStrategies(opts.Strategies)
	for _, strategy := range strategies {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedStrategies++
		findings, err := d.executeStrategy(ctx, targetURL, strategy, opts)
		if err != nil {
			return result, fmt.Errorf("strategy %s failed: %w", strategy.Name, err)
		}
		result.Findings = append(result.Findings, findings...)
		if len(findings) > 0 {
			result.Vulnerable = true
		}
	}

	return result, nil
}

// filterStrategies returns strategies matching the requested names.
// An empty or nil names slice returns all strategies.
func (d *Detector) filterStrategies(names []string) []Strategy {
	if len(names) == 0 {
		return d.strategies
	}

	allowed := make(map[string]bool, len(names))
	for _, n := range names {
		allowed[n] = true
	}

	filtered := make([]Strategy, 0, len(names))
	for _, s := range d.strategies {
		if allowed[s.Name] {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// executeStrategy runs a single strategy against the target.
func (d *Detector) executeStrategy(ctx context.Context, targetURL string, strategy Strategy, opts DetectOptions) ([]*core.Finding, error) {
	payloads := GetPayloads(strategy, opts.CallbackDomain)
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Establish baseline response for comparison.
	baseline, err := d.client.Get(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	findings := make([]*core.Finding, 0)
	for _, payload := range payloads {
		for _, point := range strategy.InjectPoints {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			resp, err := d.sendInjection(ctx, targetURL, point, payload)
			if err != nil {
				continue
			}

			if finding := d.analyzeResponse(targetURL, strategy, point, payload, resp, baseline); finding != nil {
				findings = append(findings, finding)
				return findings, nil
			}
		}
	}

	return findings, nil
}

// sendInjection sends a request with the payload at the specified inject point.
func (d *Detector) sendInjection(ctx context.Context, targetURL string, point InjectPoint, payload string) (*http.Response, error) {
	switch point.Location {
	case "header":
		return d.client.SendPayloadInHeader(ctx, targetURL, point.Field, payload, "GET")
	case "body":
		return d.client.SendPayload(ctx, targetURL, point.Field, payload, "POST")
	case "query":
		return d.client.SendPayload(ctx, targetURL, point.Field, payload, "GET")
	case "cookie":
		return d.client.SendPayloadInCookie(ctx, targetURL, point.Field, payload, "GET")
	default:
		return nil, fmt.Errorf("unsupported inject location: %s", point.Location)
	}
}

// analyzeResponse checks whether the response indicates vulnerability.
func (d *Detector) analyzeResponse(
	targetURL string,
	strategy Strategy,
	point InjectPoint,
	payload string,
	resp, baseline *http.Response,
) *core.Finding {
	for _, vp := range strategy.VerifyPoints {
		if vp.Location == "callback" {
			continue // OOB callbacks require external infrastructure.
		}
		if matched := d.matchVerifyPoint(vp, resp, baseline); matched {
			return d.createFinding(targetURL, strategy, point, payload, resp)
		}
	}
	return nil
}

// matchVerifyPoint checks if a verify point pattern matches the response.
func (d *Detector) matchVerifyPoint(vp VerifyPoint, resp, baseline *http.Response) bool {
	switch vp.Location {
	case "response_body":
		return d.matchInBody(vp.Pattern, resp.Body, baseline.Body)
	case "response_header":
		return d.matchInHeaders(vp.Pattern, resp.Headers, baseline.Headers)
	default:
		return false
	}
}

// matchInBody checks if a regex pattern matches in the response body but not the baseline.
func (d *Detector) matchInBody(pattern, body, baselineBody string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(body) && !re.MatchString(baselineBody)
}

// matchInHeaders checks if a pattern matches in response headers but not baseline headers.
func (d *Detector) matchInHeaders(pattern string, headers, baselineHeaders map[string]string) bool {
	for name := range headers {
		if strings.Contains(name, pattern) {
			// Only flag if the header was not present in the baseline.
			if _, exists := baselineHeaders[name]; !exists {
				return true
			}
		}
	}
	return false
}

// createFinding creates a core.Finding for a detected second-order vulnerability.
func (d *Detector) createFinding(
	targetURL string,
	strategy Strategy,
	point InjectPoint,
	payload string,
	resp *http.Response,
) *core.Finding {
	vulnType, severity := findingTypeAndSeverity(strategy.Name)
	finding := core.NewFinding(vulnType, severity)
	finding.URL = targetURL
	finding.Parameter = point.Field
	finding.Tool = "secondorder-detector"
	finding.Confidence = core.ConfidenceMedium

	finding.Description = fmt.Sprintf(
		"%s detected via %s injection point '%s'. %s",
		vulnType, point.Location, point.Field, strategy.Description,
	)

	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	finding.Evidence = fmt.Sprintf(
		"Strategy: %s\nInjection: %s (%s)\nPayload: %s\nResponse snippet: %s",
		strategy.Name, point.Field, point.Location, payload, body,
	)

	finding.Remediation = remediationForStrategy(strategy.Name)
	applyOWASPMapping(finding, strategy.Name)

	return finding
}

// findingTypeAndSeverity returns the finding type and severity for a strategy.
func findingTypeAndSeverity(strategyName string) (string, core.Severity) {
	switch strategyName {
	case StrategyBlindXSS:
		return "Second-Order XSS", core.SeverityHigh
	case StrategySecondOrderSQLi:
		return "Second-Order SQL Injection", core.SeverityCritical
	case StrategyLogInjection:
		return "Log Injection", core.SeverityMedium
	case StrategyJNDIHeaders:
		return "JNDI Injection", core.SeverityCritical
	default:
		return "Second-Order Injection", core.SeverityMedium
	}
}

// remediationForStrategy returns remediation advice for a given strategy.
func remediationForStrategy(strategyName string) string {
	switch strategyName {
	case StrategyBlindXSS:
		return "Sanitize all stored user input before rendering. " +
			"Apply context-aware output encoding. " +
			"Implement Content-Security-Policy headers."
	case StrategySecondOrderSQLi:
		return "Use parameterized queries for all database operations. " +
			"Treat all stored data as untrusted when building queries. " +
			"Apply the principle of least privilege to database accounts."
	case StrategyLogInjection:
		return "Sanitize user input before writing to logs. " +
			"Strip or encode CRLF characters. " +
			"Use structured logging formats (JSON)."
	case StrategyJNDIHeaders:
		return "Upgrade Log4j2 to version 2.17.0 or later. " +
			"Set log4j2.formatMsgNoLookups=true. " +
			"Restrict outbound network access from servers."
	default:
		return "Validate and sanitize all user input. " +
			"Apply context-aware encoding on output."
	}
}

// applyOWASPMapping adds OWASP framework mappings to a finding.
func applyOWASPMapping(finding *core.Finding, strategyName string) {
	switch strategyName {
	case StrategyBlindXSS:
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-02"},
			[]string{"A03:2025"},
			[]string{"CWE-79"},
		)
	case StrategySecondOrderSQLi:
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-05"},
			[]string{"A03:2025"},
			[]string{"CWE-89"},
		)
	case StrategyLogInjection:
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-07"},
			[]string{"A03:2025"},
			[]string{"CWE-117"},
		)
	case StrategyJNDIHeaders:
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-11"},
			[]string{"A06:2025"},
			[]string{"CWE-917"},
		)
	}
}
