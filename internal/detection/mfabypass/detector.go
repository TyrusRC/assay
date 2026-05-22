// Package mfabypass detects MFA bypass weaknesses (WSTG-ATHN-11).
package mfabypass

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// toolName identifies findings emitted by this detector.
const toolName = "mfabypass-detector"

// Detection-result type tags surfaced via DetectionResult.DetectionType.
const (
	detectionStepSkip       = "mfa-step-skip"
	detectionNullValue      = "mfa-null-value"
	detectionBruteForce     = "mfa-brute-force"
	detectionRespManipulate = "mfa-response-manipulation"
	detectionAll            = "mfa-bypass-all"
)

// Finding type names.
const (
	typeStepSkip       = "MFA Step Skip Allowed"
	typeNullValue      = "MFA Weak OTP Validation"
	typeBruteForce     = "MFA No Brute Force Protection"
	typeRespManipulate = "MFA Verification Status Tampering"
)

// bruteForceAttempts is the number of bogus OTPs we submit when probing
// for rate-limit / lockout protection.
const bruteForceAttempts = 20

// Detector performs MFA bypass detection (WSTG-ATHN-11).
type Detector struct {
	client *http.Client
}

// New creates a new MFA bypass detector. The supplied client provides the
// HTTP plumbing (timeouts, proxy, TLS settings). Per-request headers and
// cookies are applied via Cloned clients on a call-by-call basis.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// DetectOptions configures MFA bypass detection.
type DetectOptions struct {
	// LoginURL is the JSON endpoint that accepts username/password and
	// returns a partial (pre-MFA) session cookie or token.
	LoginURL string
	// MFASubmitURL is the JSON endpoint that completes the MFA challenge
	// by accepting an OTP value.
	MFASubmitURL string
	// ProtectedURL is a protected JSON resource that should ONLY be
	// reachable after MFA completion.
	ProtectedURL string

	// Username / Password are the test credentials used at LoginURL.
	Username string
	Password string

	// ResponseFlipPattern identifies the cookie/header name whose value
	// must be flipped from "false" to "true" for DetectMFAResponseManipulation.
	// When empty, that check is skipped.
	ResponseFlipPattern string

	// Timeout is reserved for future per-request override; the underlying
	// client already enforces its own timeout.
	Timeout time.Duration
}

// DetectionResult bundles the outcome of one detection.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// loginResponse captures both the JSON body and the response headers
// (so callers can read Set-Cookie or custom MFA-state headers).
type loginResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
	SetCookie  string
}

// login posts username/password to LoginURL and returns the raw response
// plumbing. Unlike a full session login, the server is expected to issue
// a *partial* session (pre-MFA).
func (d *Detector) login(ctx context.Context, opts DetectOptions) (*loginResponse, error) {
	payload, err := json.Marshal(map[string]string{
		"username": opts.Username,
		"password": opts.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal login: %w", err)
	}
	resp, err := d.client.PostJSON(ctx, opts.LoginURL, string(payload))
	if err != nil {
		return nil, fmt.Errorf("login request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("login failed: status=%d", resp.StatusCode)
	}
	return &loginResponse{
		StatusCode: resp.StatusCode,
		Body:       resp.Body,
		Headers:    resp.Headers,
		SetCookie:  resp.Headers["Set-Cookie"],
	}, nil
}

// withCookies clones the underlying client and attaches the given Cookie
// header for subsequent requests. The cookie value should already be in
// the canonical "name=value" form (or comma-separated for multiple).
func (d *Detector) withCookies(cookieHeader string) *http.Client {
	// Convert a Set-Cookie header into a Cookie request header by
	// stripping attributes (anything after the first ';').
	parts := strings.Split(cookieHeader, ",")
	pairs := make([]string, 0, len(parts))
	for _, p := range parts {
		nameVal := strings.SplitN(strings.TrimSpace(p), ";", 2)[0]
		if nameVal != "" {
			pairs = append(pairs, nameVal)
		}
	}
	return d.client.Clone().WithCookies(strings.Join(pairs, "; "))
}
