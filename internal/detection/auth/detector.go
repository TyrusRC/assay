// Package auth provides detection for authentication security vulnerabilities.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/auth"
)

// Detector performs authentication security detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Authentication Security Detector.
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

// DetectOptions configures authentication detection behavior.
type DetectOptions struct {
	MaxAttempts       int
	Timeout           time.Duration
	RateLimitAttempts int
	Service           string
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxAttempts:       50,
		Timeout:           10 * time.Second,
		RateLimitAttempts: 10,
	}
}

// DetectionResult contains authentication detection results.
type DetectionResult struct {
	Vulnerable       bool
	Findings         []*core.Finding
	TestedAttempts   int
	DetectionType    string
	ValidCredentials []string
}

// DetectDefaultCredentials checks for default/common credentials.
func (d *Detector) DetectDefaultCredentials(ctx context.Context, loginURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:         make([]*core.Finding, 0),
		ValidCredentials: make([]string, 0),
	}

	// Get credentials to test
	creds := auth.GetDefaultCredentials()
	if opts.Service != "" {
		creds = auth.GetByService(opts.Service)
	}

	// Limit attempts
	if opts.MaxAttempts > 0 && len(creds) > opts.MaxAttempts {
		creds = creds[:opts.MaxAttempts]
	}

	for _, cred := range creds {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedAttempts++

		// Send login request
		bodyBytes, _ := json.Marshal(map[string]string{"username": cred.Username, "password": cred.Password})
		body := string(bodyBytes)
		resp, err := d.client.PostJSON(ctx, loginURL, body)
		if err != nil {
			continue
		}

		if d.isLoginSuccess(resp) {
			credStr := fmt.Sprintf("%s:%s", cred.Username, cred.Password)
			result.ValidCredentials = append(result.ValidCredentials, credStr)
			result.DetectionType = "default-credentials"

			finding := d.createDefaultCredFinding(loginURL, cred, resp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// DetectUserEnumeration checks for username enumeration vulnerability.
func (d *Detector) DetectUserEnumeration(ctx context.Context, loginURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	enumPayloads := auth.GetEnumerationPayloads()

	for _, payload := range enumPayloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedAttempts += 2

		// Test with valid username
		validBytes, _ := json.Marshal(map[string]string{"username": payload.ValidUser, "password": "wrong_password_xyz"})
		validBody := string(validBytes)
		validResp, err := d.client.PostJSON(ctx, loginURL, validBody)
		if err != nil {
			continue
		}

		// Test with invalid username
		invalidBytes, _ := json.Marshal(map[string]string{"username": payload.InvalidUser, "password": "wrong_password_xyz"})
		invalidBody := string(invalidBytes)
		invalidResp, err := d.client.PostJSON(ctx, loginURL, invalidBody)
		if err != nil {
			continue
		}

		// Compare responses for enumeration
		if d.hasEnumerationDifference(validResp, invalidResp) {
			result.DetectionType = "user-enumeration"

			finding := d.createEnumerationFinding(loginURL, payload, validResp, invalidResp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	return result, nil
}

// DetectMissingRateLimit checks for missing rate limiting on login.
func (d *Detector) DetectMissingRateLimit(ctx context.Context, loginURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	attempts := opts.RateLimitAttempts
	if attempts <= 0 {
		attempts = 10
	}

	rateLimited := false
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedAttempts++

		bodyBytes, _ := json.Marshal(map[string]string{"username": "admin", "password": fmt.Sprintf("wrong_password_%d", i)})
		body := string(bodyBytes)
		resp, err := d.client.PostJSON(ctx, loginURL, body)
		if err != nil {
			continue
		}

		// Check for rate limiting indicators
		if resp.StatusCode == 429 ||
			strings.Contains(strings.ToLower(resp.Body), "too many") ||
			strings.Contains(strings.ToLower(resp.Body), "rate limit") ||
			strings.Contains(strings.ToLower(resp.Body), "locked") {
			rateLimited = true
			break
		}
	}

	if !rateLimited {
		result.DetectionType = "missing-rate-limit"
		finding := d.createRateLimitFinding(loginURL, attempts)
		result.Findings = append(result.Findings, finding)
		result.Vulnerable = true
	}

	return result, nil
}

// isLoginSuccess determines if a login attempt was successful.
func (d *Detector) isLoginSuccess(resp *http.Response) bool {
	// Redirect (302/303) often indicates successful login
	if resp.StatusCode == 302 || resp.StatusCode == 303 {
		return true
	}

	// 401/403 always indicate failure
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}

	// 200 with error indicators means failure
	if resp.StatusCode == 200 {
		lowerBody := strings.ToLower(resp.Body)

		// Check for error indicators
		errorIndicators := []string{
			"invalid credentials",
			"invalid username",
			"invalid password",
			"login failed",
			"authentication failed",
			"incorrect password",
			"wrong password",
			"access denied",
			`"error"`,
		}
		for _, indicator := range errorIndicators {
			if strings.Contains(lowerBody, indicator) {
				return false
			}
		}

		// Check for success indicators
		successIndicators := []string{
			"token",
			"session",
			"success",
			"welcome",
			"dashboard",
			"logged in",
		}
		for _, indicator := range successIndicators {
			if strings.Contains(lowerBody, indicator) {
				return true
			}
		}
	}

	return false
}

// hasEnumerationDifference checks if responses differ between valid/invalid users.
func (d *Detector) hasEnumerationDifference(validResp, invalidResp *http.Response) bool {
	// Different status codes indicate enumeration
	if validResp.StatusCode != invalidResp.StatusCode {
		return true
	}

	// Different response bodies indicate enumeration
	if validResp.Body != invalidResp.Body {
		// Check for meaningful difference (not just timestamp/token)
		validLen := len(validResp.Body)
		invalidLen := len(invalidResp.Body)
		if validLen != invalidLen {
			return true
		}
	}

	// Different response times could indicate enumeration (timing attack)
	if validResp.Duration > 0 && invalidResp.Duration > 0 {
		diff := validResp.Duration - invalidResp.Duration
		if diff < 0 {
			diff = -diff
		}
		// More than 500ms difference suggests timing-based enumeration
		if diff > 500*time.Millisecond {
			return true
		}
	}

	return false
}

// createDefaultCredFinding creates a finding for default credentials.
func (d *Detector) createDefaultCredFinding(loginURL string, cred auth.DefaultCredential, resp *http.Response) *core.Finding {
	finding := core.NewFinding("Default Credentials", core.SeverityCritical)
	finding.URL = loginURL
	finding.Description = fmt.Sprintf(
		"Default credentials (%s) are accepted by the application. "+
			"An attacker can gain unauthorized access using well-known default credentials.",
		cred.Description,
	)
	finding.Evidence = fmt.Sprintf("Username: %s\nPassword: %s\nService: %s\nHTTP Status: %d",
		cred.Username, "***", cred.Service, resp.StatusCode)
	finding.Tool = "auth-detector"
	finding.Confidence = core.ConfidenceConfirmed

	finding.Remediation = "Change all default credentials immediately. " +
		"Implement mandatory password change on first login. " +
		"Enforce strong password policies. " +
		"Remove or disable default accounts."

	finding.WithOWASPMapping(
		[]string{"WSTG-ATHN-02"}, // Testing for Default Credentials
		[]string{"A07:2025"},     // Identification and Authentication Failures
		[]string{"CWE-798"},      // Use of Hard-coded Credentials
	)

	return finding
}

// createEnumerationFinding creates a finding for username enumeration.
func (d *Detector) createEnumerationFinding(loginURL string, payload auth.EnumerationPayload, validResp, invalidResp *http.Response) *core.Finding {
	finding := core.NewFinding("Username Enumeration", core.SeverityMedium)
	finding.URL = loginURL
	finding.Description = "The application reveals whether a username exists through " +
		"different error messages, response codes, or response times. " +
		"An attacker can enumerate valid usernames for targeted attacks."

	finding.Evidence = fmt.Sprintf(
		"Valid user (%s) response: status=%d, length=%d\n"+
			"Invalid user (%s) response: status=%d, length=%d",
		payload.ValidUser, validResp.StatusCode, len(validResp.Body),
		payload.InvalidUser, invalidResp.StatusCode, len(invalidResp.Body),
	)
	finding.Tool = "auth-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Return identical error messages for both valid and invalid usernames. " +
		"Use generic messages like 'Invalid credentials' regardless of which field is wrong. " +
		"Normalize response times to prevent timing-based enumeration."

	finding.WithOWASPMapping(
		[]string{"WSTG-IDNT-04"}, // Testing for Account Enumeration
		[]string{"A07:2025"},     // Identification and Authentication Failures
		[]string{"CWE-204"},      // Observable Response Discrepancy
	)

	return finding
}

// createRateLimitFinding creates a finding for missing rate limiting.
func (d *Detector) createRateLimitFinding(loginURL string, attempts int) *core.Finding {
	finding := core.NewFinding("Missing Login Rate Limiting", core.SeverityHigh)
	finding.URL = loginURL
	finding.Description = fmt.Sprintf(
		"The login endpoint does not implement rate limiting. "+
			"%d consecutive failed login attempts were allowed without any blocking or throttling.",
		attempts,
	)
	finding.Evidence = fmt.Sprintf("Attempted %d consecutive login requests without rate limiting", attempts)
	finding.Tool = "auth-detector"
	finding.Confidence = core.ConfidenceHigh

	finding.Remediation = "Implement rate limiting on login endpoints. " +
		"Use progressive delays or account lockout after failed attempts. " +
		"Consider CAPTCHA after multiple failures. " +
		"Implement IP-based and account-based rate limiting."

	finding.WithOWASPMapping(
		[]string{"WSTG-ATHN-03"}, // Testing for Weak Lock Out Mechanism
		[]string{"A07:2025"},     // Identification and Authentication Failures
		[]string{"CWE-307"},      // Improper Restriction of Excessive Authentication Attempts
	)

	return finding
}
