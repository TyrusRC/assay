package mfabypass

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectMFABruteForce logs in, then submits bruteForceAttempts wrong OTPs
// in rapid succession. If the server NEVER emits a rate-limit signal
// (429) or a lockout indicator, the endpoint is missing brute-force
// protection (CWE-307).
func (d *Detector) DetectMFABruteForce(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionBruteForce,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	lr, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}
	probe := d.withCookies(lr.SetCookie)

	var (
		rateLimited bool
		lockedOut   bool
		lastStatus  int
		lastBody    string
	)

	for i := 0; i < bruteForceAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		// Use deterministic-but-wrong OTP values.
		body := fmt.Sprintf(`{"otp":"00000%d"}`, i+1)
		resp, err := probe.PostJSON(ctx, opts.MFASubmitURL, body)
		if err != nil {
			return result, fmt.Errorf("mfa brute attempt %d: %w", i+1, err)
		}
		lastStatus = resp.StatusCode
		lastBody = resp.Body

		if resp.StatusCode == 429 {
			rateLimited = true
			break
		}
		if isLockoutResponse(resp.Body) {
			lockedOut = true
			break
		}
	}

	if !rateLimited && !lockedOut {
		f := d.findingBruteForce(opts, bruteForceAttempts, lastStatus, lastBody)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}
	return result, nil
}

// isLockoutResponse returns true if the response body contains language
// commonly associated with account lockout or rate limiting.
func isLockoutResponse(body string) bool {
	lower := strings.ToLower(body)
	indicators := []string{
		"locked", "lockout", "too many", "rate limit", "rate-limit",
		"try again later", "temporarily disabled", "account disabled",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func (d *Detector) findingBruteForce(opts DetectOptions, attempts, lastStatus int, lastBody string) *core.Finding {
	f := core.NewFinding(typeBruteForce, core.SeverityHigh)
	f.URL = opts.MFASubmitURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = fmt.Sprintf(
		"%d consecutive wrong OTP submissions did not trigger any rate-limit "+
			"(HTTP 429) or account-lockout response. A 6-digit OTP only has "+
			"1,000,000 possible values; without rate limiting an attacker can "+
			"enumerate the entire keyspace in minutes.", attempts,
	)
	// Truncate the response body for evidence so we don't leak a huge blob.
	snippet := lastBody
	if len(snippet) > 256 {
		snippet = snippet[:256] + "...(truncated)"
	}
	f.Evidence = fmt.Sprintf(
		"MFA URL: %s\nAttempts: %d\nLast response status=%d\nLast response body: %s",
		opts.MFASubmitURL, attempts, lastStatus, snippet,
	)
	f.Remediation = "Implement strict rate limiting on the MFA endpoint: lock the " +
		"user account after N failures within a sliding window, and respond " +
		"with HTTP 429 once the threshold is exceeded. Reset the counter " +
		"only after a successful first-factor re-authentication."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-11"},
		[]string{"A07:2025"},
		[]string{"CWE-307"},
	)
	return f
}
