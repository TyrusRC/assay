// Package behavior provides behavior-based vulnerability detection.
// It analyzes application responses to detect anomalies that indicate vulnerabilities
// without relying on specific payload signatures.
package behavior

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Detector performs behavior-based vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new behavior Detector.
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

// BehaviorType represents the type of behavioral anomaly.
type BehaviorType string

const (
	BehaviorTimingAnomaly   BehaviorType = "timing_anomaly"
	BehaviorContentAnomaly  BehaviorType = "content_anomaly"
	BehaviorStatusAnomaly   BehaviorType = "status_anomaly"
	BehaviorErrorDisclosure BehaviorType = "error_disclosure"
	BehaviorReflection      BehaviorType = "reflection"
	BehaviorRedirectAnomaly BehaviorType = "redirect_anomaly"
	BehaviorHeaderAnomaly   BehaviorType = "header_anomaly"
)

// Baseline represents a baseline response for comparison.
type Baseline struct {
	StatusCode    int
	ContentLength int
	ContentHash   string
	ResponseTime  time.Duration
	Headers       map[string]string
	ErrorPatterns []string
}

// Anomaly represents a detected behavioral anomaly.
type Anomaly struct {
	Type        BehaviorType
	Description string
	Confidence  core.Confidence
	Evidence    string
	Parameter   string
	Payload     string
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	Timeout              time.Duration
	TimingThreshold      time.Duration // Threshold for timing anomalies
	ContentDiffThreshold float64       // Threshold for content difference (0-1)
	CheckErrorMessages   bool
	CheckReflection      bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:              10 * time.Second,
		TimingThreshold:      3 * time.Second,
		ContentDiffThreshold: 0.3,
		CheckErrorMessages:   true,
		CheckReflection:      true,
	}
}

// DetectionResult contains behavior detection results.
type DetectionResult struct {
	Anomalies      []*Anomaly
	Baseline       *Baseline
	TestedPayloads int
}

// EstablishBaseline creates a baseline response for comparison.
func (d *Detector) EstablishBaseline(ctx context.Context, target, param, method string) (*Baseline, error) {
	// Send multiple requests to establish a stable baseline
	var responses []*http.Response
	var totalTime time.Duration

	for i := 0; i < 3; i++ {
		resp, err := d.client.SendPayload(ctx, target, param, "baseline_test_value", method)
		if err != nil {
			continue
		}
		responses = append(responses, resp)
		totalTime += resp.Duration
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("failed to establish baseline")
	}

	// Use the most common response as baseline
	baseline := &Baseline{
		StatusCode:    responses[0].StatusCode,
		ContentLength: len(responses[0].Body),
		ContentHash:   d.hashContent(responses[0].Body),
		ResponseTime:  totalTime / time.Duration(len(responses)),
		Headers:       responses[0].Headers,
		ErrorPatterns: d.extractErrorPatterns(responses[0].Body),
	}

	return baseline, nil
}

// AnalyzeResponse compares a response against the baseline for anomalies.
func (d *Detector) AnalyzeResponse(resp *http.Response, baseline *Baseline, payload string, opts DetectOptions) []*Anomaly {
	var anomalies []*Anomaly

	if resp == nil || baseline == nil {
		return anomalies
	}

	// Check timing anomaly
	if timing := d.checkTimingAnomaly(resp, baseline, opts); timing != nil {
		timing.Payload = payload
		anomalies = append(anomalies, timing)
	}

	// Check status code anomaly
	if status := d.checkStatusAnomaly(resp, baseline); status != nil {
		status.Payload = payload
		anomalies = append(anomalies, status)
	}

	// Check content anomaly
	if content := d.checkContentAnomaly(resp, baseline, opts); content != nil {
		content.Payload = payload
		anomalies = append(anomalies, content)
	}

	// Check for error disclosure
	if opts.CheckErrorMessages {
		if errors := d.checkErrorDisclosure(resp, baseline); errors != nil {
			errors.Payload = payload
			anomalies = append(anomalies, errors)
		}
	}

	// Check for reflection
	if opts.CheckReflection {
		if reflection := d.checkReflection(resp, payload); reflection != nil {
			anomalies = append(anomalies, reflection)
		}
	}

	// Check header anomalies
	if header := d.checkHeaderAnomaly(resp, baseline); header != nil {
		header.Payload = payload
		anomalies = append(anomalies, header)
	}

	return anomalies
}

// checkTimingAnomaly detects timing-based anomalies.
func (d *Detector) checkTimingAnomaly(resp *http.Response, baseline *Baseline, opts DetectOptions) *Anomaly {
	diff := resp.Duration - baseline.ResponseTime

	if diff > opts.TimingThreshold {
		return &Anomaly{
			Type:        BehaviorTimingAnomaly,
			Description: fmt.Sprintf("Response time significantly longer than baseline (diff: %v)", diff),
			Confidence:  d.calculateTimingConfidence(diff, opts.TimingThreshold),
			Evidence:    fmt.Sprintf("Baseline: %v, Current: %v", baseline.ResponseTime, resp.Duration),
		}
	}

	return nil
}

// checkStatusAnomaly detects status code anomalies.
func (d *Detector) checkStatusAnomaly(resp *http.Response, baseline *Baseline) *Anomaly {
	if resp.StatusCode != baseline.StatusCode {
		confidence := core.ConfidenceMedium
		description := fmt.Sprintf("Status code changed from %d to %d", baseline.StatusCode, resp.StatusCode)

		// Higher confidence for certain status codes
		if resp.StatusCode == 500 || resp.StatusCode == 503 {
			confidence = core.ConfidenceHigh
			description += " (server error)"
		} else if resp.StatusCode == 403 || resp.StatusCode == 401 {
			confidence = core.ConfidenceMedium
			description += " (access control)"
		}

		return &Anomaly{
			Type:        BehaviorStatusAnomaly,
			Description: description,
			Confidence:  confidence,
			Evidence:    fmt.Sprintf("Expected: %d, Got: %d", baseline.StatusCode, resp.StatusCode),
		}
	}

	return nil
}

// checkContentAnomaly detects content-based anomalies.
func (d *Detector) checkContentAnomaly(resp *http.Response, baseline *Baseline, opts DetectOptions) *Anomaly {
	currentHash := d.hashContent(resp.Body)

	if currentHash != baseline.ContentHash {
		lengthDiff := float64(len(resp.Body)-baseline.ContentLength) / float64(baseline.ContentLength+1)

		// Significant content change
		if lengthDiff > opts.ContentDiffThreshold || lengthDiff < -opts.ContentDiffThreshold {
			return &Anomaly{
				Type:        BehaviorContentAnomaly,
				Description: fmt.Sprintf("Significant content change (%.1f%% difference)", lengthDiff*100),
				Confidence:  core.ConfidenceMedium,
				Evidence:    fmt.Sprintf("Baseline length: %d, Current length: %d", baseline.ContentLength, len(resp.Body)),
			}
		}
	}

	return nil
}

// checkErrorDisclosure detects error message disclosure.
func (d *Detector) checkErrorDisclosure(resp *http.Response, baseline *Baseline) *Anomaly {
	errorPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		severity    core.Confidence
	}{
		{regexp.MustCompile(`(?i)stack\s*trace`), "Stack trace disclosed", core.ConfidenceHigh},
		{regexp.MustCompile(`(?i)exception\s+in`), "Exception details disclosed", core.ConfidenceHigh},
		{regexp.MustCompile(`(?i)fatal\s+error`), "Fatal error disclosed", core.ConfidenceHigh},
		{regexp.MustCompile(`(?i)debug\s+mode`), "Debug mode enabled", core.ConfidenceMedium},
		{regexp.MustCompile(`(?i)warning:\s+\w+\(\)`), "PHP warning disclosed", core.ConfidenceHigh},
		{regexp.MustCompile(`(?i)notice:\s+undefined`), "PHP notice disclosed", core.ConfidenceMedium},
		{regexp.MustCompile(`(?i)at\s+[\w\.]+\([\w\.]+:\d+\)`), "Java stack trace", core.ConfidenceHigh},
		{regexp.MustCompile(`(?i)traceback\s+\(most recent`), "Python traceback", core.ConfidenceHigh},
		{regexp.MustCompile(`(?i)error\s+on\s+line\s+\d+`), "Line number disclosed", core.ConfidenceMedium},
		{regexp.MustCompile(`(?i)/var/www/|/home/\w+/|C:\\inetpub\\`), "File path disclosed", core.ConfidenceHigh},
	}

	for _, ep := range errorPatterns {
		if ep.pattern.MatchString(resp.Body) {
			// Check if this error was already in baseline
			inBaseline := false
			for _, bp := range baseline.ErrorPatterns {
				if strings.Contains(bp, ep.description) {
					inBaseline = true
					break
				}
			}

			if !inBaseline {
				matches := ep.pattern.FindStringSubmatch(resp.Body)
				evidence := ""
				if len(matches) > 0 {
					evidence = matches[0]
					if len(evidence) > 200 {
						evidence = evidence[:200] + "..."
					}
				}

				return &Anomaly{
					Type:        BehaviorErrorDisclosure,
					Description: ep.description,
					Confidence:  ep.severity,
					Evidence:    evidence,
				}
			}
		}
	}

	return nil
}

// checkReflection detects payload reflection in response.
func (d *Detector) checkReflection(resp *http.Response, payload string) *Anomaly {
	if payload == "" || len(payload) < 3 {
		return nil
	}

	// Check for exact reflection
	if strings.Contains(resp.Body, payload) {
		return &Anomaly{
			Type:        BehaviorReflection,
			Description: "Payload reflected in response without encoding",
			Confidence:  core.ConfidenceHigh,
			Payload:     payload,
			Evidence:    fmt.Sprintf("Payload '%s' found in response body", payload),
		}
	}

	// Check for partial reflection (for XSS detection)
	dangerousChars := []string{"<", ">", "\"", "'", "&"}
	for _, char := range dangerousChars {
		if strings.Contains(payload, char) && strings.Contains(resp.Body, char) {
			// Further analysis needed
			return &Anomaly{
				Type:        BehaviorReflection,
				Description: "Dangerous characters reflected in response",
				Confidence:  core.ConfidenceMedium,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Character '%s' from payload found in response", char),
			}
		}
	}

	return nil
}

// checkHeaderAnomaly detects anomalies in response headers.
func (d *Detector) checkHeaderAnomaly(resp *http.Response, baseline *Baseline) *Anomaly {
	// Check for new security-relevant headers
	sensitiveHeaders := []string{
		"X-Debug-Token",
		"X-Debug-Token-Link",
		"X-Powered-By",
		"Server",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
	}

	for _, header := range sensitiveHeaders {
		currentVal := resp.Headers[header]
		baselineVal := baseline.Headers[header]

		if currentVal != "" && currentVal != baselineVal {
			return &Anomaly{
				Type:        BehaviorHeaderAnomaly,
				Description: fmt.Sprintf("Header '%s' changed or appeared", header),
				Confidence:  core.ConfidenceMedium,
				Evidence:    fmt.Sprintf("Baseline: '%s', Current: '%s'", baselineVal, currentVal),
			}
		}
	}

	return nil
}

// hashContent creates a hash of response content using SHA256 for consistency.
func (d *Detector) hashContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// extractErrorPatterns extracts error patterns from response for baseline.
func (d *Detector) extractErrorPatterns(body string) []string {
	var patterns []string
	errorIndicators := []string{
		"error", "exception", "warning", "notice",
		"stack trace", "debug", "fatal",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyLower, indicator) {
			patterns = append(patterns, indicator)
		}
	}

	return patterns
}

// calculateTimingConfidence calculates confidence based on timing difference.
func (d *Detector) calculateTimingConfidence(diff, threshold time.Duration) core.Confidence {
	// Guard against division by zero
	if threshold <= 0 {
		return core.ConfidenceLow
	}

	ratio := float64(diff) / float64(threshold)

	if ratio > 3 {
		return core.ConfidenceConfirmed
	} else if ratio > 2 {
		return core.ConfidenceHigh
	} else if ratio > 1.5 {
		return core.ConfidenceMedium
	}
	return core.ConfidenceLow
}

// CreateFinding creates a Finding from an anomaly.
func (d *Detector) CreateFinding(target, param string, anomaly *Anomaly) *core.Finding {
	severity := core.SeverityMedium
	switch anomaly.Type {
	case BehaviorErrorDisclosure:
		severity = core.SeverityMedium
	case BehaviorTimingAnomaly:
		severity = core.SeverityHigh
	case BehaviorReflection:
		severity = core.SeverityMedium
	}

	finding := core.NewFinding(fmt.Sprintf("Behavioral Anomaly: %s", anomaly.Type), severity)
	finding.URL = target
	finding.Parameter = param
	finding.Description = anomaly.Description
	finding.Evidence = fmt.Sprintf("Payload: %s\n%s", anomaly.Payload, anomaly.Evidence)
	finding.Confidence = anomaly.Confidence
	finding.Tool = "behavior-detector"

	finding.Remediation = "Review application behavior for the identified anomaly. " +
		"Behavioral anomalies may indicate underlying vulnerabilities that require further investigation."

	return finding
}
