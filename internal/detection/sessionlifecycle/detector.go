// Package sessionlifecycle provides detection for session lifecycle policy
// weaknesses (token refresh rotation, post-logout invalidation, and concurrent
// session policy).
package sessionlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// toolName identifies findings emitted by this detector.
const toolName = "sessionlifecycle-detector"

// Detection-result type tags surfaced via DetectionResult.DetectionType.
const (
	detectionRefreshRotation  = "refresh-token-rotation"
	detectionLogoutStaleToken = "logout-stale-token"
	detectionConcurrentSess   = "concurrent-sessions"
)

// Detector performs session lifecycle policy detection.
type Detector struct {
	client *http.Client
}

// New creates a new session-lifecycle detector. The supplied client provides
// the HTTP plumbing (timeouts, proxy, TLS settings); per-request headers like
// Authorization are applied via Cloned clients on a call-by-call basis.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// DetectOptions configures session-lifecycle detection. All URL fields refer
// to JSON endpoints. Username/Password are used against LoginURL.
type DetectOptions struct {
	LoginURL     string
	RefreshURL   string
	LogoutURL    string
	ProtectedURL string

	Username string
	Password string

	// SingleSessionRequired causes DetectConcurrentSessions to emit a Low
	// severity finding when both tokens issued for the same user remain
	// valid. When false, the multi-session behaviour is not a finding.
	SingleSessionRequired bool

	Timeout time.Duration
}

// DetectionResult bundles the outcome of one detection.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// tokenPair holds the access/refresh tokens parsed from a JSON response.
type tokenPair struct {
	Access  string
	Refresh string
}

// login posts username/password to LoginURL and returns the parsed token pair.
// It returns an error if the login does not return a usable access token.
func (d *Detector) login(ctx context.Context, opts DetectOptions) (*tokenPair, *http.Response, error) {
	payload, err := json.Marshal(map[string]string{
		"username": opts.Username,
		"password": opts.Password,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal login: %w", err)
	}

	resp, err := d.client.PostJSON(ctx, opts.LoginURL, string(payload))
	if err != nil {
		return nil, nil, fmt.Errorf("login request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp, fmt.Errorf("login failed: status=%d", resp.StatusCode)
	}

	tp, err := parseTokens(resp.Body)
	if err != nil {
		return nil, resp, fmt.Errorf("parse login tokens: %w", err)
	}
	if tp.Access == "" {
		return nil, resp, errors.New("login returned no access_token")
	}
	return tp, resp, nil
}

// parseTokens extracts access_token and refresh_token from a JSON body.
// Missing fields are returned as empty strings (not an error).
func parseTokens(body string) (*tokenPair, error) {
	var raw map[string]interface{}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode token json: %w", err)
	}
	tp := &tokenPair{}
	if v, ok := raw["access_token"].(string); ok {
		tp.Access = v
	}
	if v, ok := raw["refresh_token"].(string); ok {
		tp.Refresh = v
	}
	return tp, nil
}

// withBearer clones the underlying client and sets a Bearer Authorization
// header for use against protected endpoints. Cloning avoids mutating the
// shared client (which other goroutines may use).
func (d *Detector) withBearer(token string) *http.Client {
	return d.client.Clone().WithHeaders(map[string]string{
		"Authorization": "Bearer " + token,
	})
}

// DetectRefreshRotation logs in, then exchanges the refresh token and checks
// whether the issued tokens actually rotate.
//
//   - Both access and refresh unchanged: High severity (no rotation at all).
//   - Refresh token reused (access rotated, refresh did not): Medium severity.
//   - Both rotated: no finding.
func (d *Detector) DetectRefreshRotation(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionRefreshRotation,
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	initial, _, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}
	if initial.Refresh == "" {
		// Nothing to test against; treat as a no-op success.
		return result, nil
	}

	payload, err := json.Marshal(map[string]string{"refresh_token": initial.Refresh})
	if err != nil {
		return result, fmt.Errorf("marshal refresh: %w", err)
	}
	resp, err := d.client.PostJSON(ctx, opts.RefreshURL, string(payload))
	if err != nil {
		return result, fmt.Errorf("refresh request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Refresh endpoint rejected the token: nothing to flag here.
		return result, nil
	}
	rotated, err := parseTokens(resp.Body)
	if err != nil {
		return result, err
	}

	sameAccess := rotated.Access != "" && rotated.Access == initial.Access
	sameRefresh := rotated.Refresh != "" && rotated.Refresh == initial.Refresh

	switch {
	case sameAccess && sameRefresh:
		f := d.findingNoRotation(opts.RefreshURL, initial, rotated, core.SeverityHigh,
			"Both the access token and the refresh token were returned unchanged "+
				"after exchanging the refresh token. The server does not rotate session "+
				"credentials, so a captured refresh token can be replayed indefinitely.")
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	case sameRefresh:
		f := d.findingNoRotation(opts.RefreshURL, initial, rotated, core.SeverityMedium,
			"The refresh token was reused after a refresh exchange (only the access "+
				"token rotated). Refresh tokens must be rotated on every use so that a "+
				"leaked token cannot be replayed.")
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}

	return result, nil
}

// DetectStaleTokenAfterLogout logs in, calls logout, then tries the protected
// resource with the original token. If the protected resource still responds
// 2xx, the token was not invalidated server-side.
func (d *Detector) DetectStaleTokenAfterLogout(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionLogoutStaleToken,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	tp, _, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}

	bearer := d.withBearer(tp.Access)

	// Call logout with the bearer token attached.
	logoutResp, err := bearer.PostJSON(ctx, opts.LogoutURL, "{}")
	if err != nil {
		return result, fmt.Errorf("logout request: %w", err)
	}
	_ = logoutResp // status not strictly required; we judge by what /me returns next.

	// Re-use the old token against the protected resource.
	protectedResp, err := bearer.Get(ctx, opts.ProtectedURL)
	if err != nil {
		return result, fmt.Errorf("protected request: %w", err)
	}

	if protectedResp.StatusCode >= 200 && protectedResp.StatusCode < 300 {
		f := d.findingStaleToken(opts, tp, protectedResp)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}

	return result, nil
}

// DetectConcurrentSessions logs in twice as the same user and tests whether
// the first token continues to work. When SingleSessionRequired is true and
// both tokens remain valid, a Low severity finding is emitted.
func (d *Detector) DetectConcurrentSessions(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionConcurrentSess,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	first, _, err := d.login(ctx, opts)
	if err != nil {
		return result, fmt.Errorf("first login: %w", err)
	}
	second, _, err := d.login(ctx, opts)
	if err != nil {
		return result, fmt.Errorf("second login: %w", err)
	}

	// Test the FIRST token after the SECOND login completed.
	firstResp, err := d.withBearer(first.Access).Get(ctx, opts.ProtectedURL)
	if err != nil {
		return result, fmt.Errorf("probe first token: %w", err)
	}
	secondResp, err := d.withBearer(second.Access).Get(ctx, opts.ProtectedURL)
	if err != nil {
		return result, fmt.Errorf("probe second token: %w", err)
	}

	firstValid := firstResp.StatusCode >= 200 && firstResp.StatusCode < 300
	secondValid := secondResp.StatusCode >= 200 && secondResp.StatusCode < 300

	if firstValid && secondValid && opts.SingleSessionRequired {
		f := d.findingConcurrent(opts, first, second, firstResp, secondResp)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}
	return result, nil
}

// DetectAll runs the three lifecycle checks in sequence and aggregates the
// results. Errors from individual checks are returned alongside whatever
// partial findings were gathered.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	aggregate := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "session-lifecycle-all",
	}
	var firstErr error
	add := func(res *DetectionResult, err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if res != nil {
			aggregate.Findings = append(aggregate.Findings, res.Findings...)
			if res.Vulnerable {
				aggregate.Vulnerable = true
			}
		}
	}

	if opts.RefreshURL != "" {
		r, err := d.DetectRefreshRotation(ctx, opts)
		add(r, err)
	}
	if opts.LogoutURL != "" && opts.ProtectedURL != "" {
		r, err := d.DetectStaleTokenAfterLogout(ctx, opts)
		add(r, err)
	}
	if opts.ProtectedURL != "" {
		r, err := d.DetectConcurrentSessions(ctx, opts)
		add(r, err)
	}
	return aggregate, firstErr
}

// ---------- finding constructors ----------

// findingNoRotation creates a Refresh Token Not Rotated finding at the
// requested severity. Same constructor is reused for the High (no rotation
// at all) and Medium (refresh-only reuse) variants.
func (d *Detector) findingNoRotation(refreshURL string, before, after *tokenPair, sev core.Severity, description string) *core.Finding {
	f := core.NewFinding("Refresh Token Not Rotated", sev)
	f.URL = refreshURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = description
	f.Evidence = fmt.Sprintf(
		"Initial access_token=%s\nInitial refresh_token=%s\nAfter-refresh access_token=%s\nAfter-refresh refresh_token=%s",
		redact(before.Access), redact(before.Refresh),
		redact(after.Access), redact(after.Refresh),
	)
	f.Remediation = "Issue a new refresh token on every refresh exchange and " +
		"immediately invalidate the previous one (refresh-token rotation). " +
		"Tie refresh tokens to a single use; if the same token is presented twice, " +
		"revoke the whole session family."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-01"},
		[]string{"A07:2025"},
		[]string{"CWE-613"},
	)
	return f
}

// findingStaleToken creates a finding for tokens that remain valid after
// logout (Session Not Invalidated After Logout, High severity).
func (d *Detector) findingStaleToken(opts DetectOptions, tp *tokenPair, protectedResp *http.Response) *core.Finding {
	f := core.NewFinding("Session Not Invalidated After Logout", core.SeverityHigh)
	f.URL = opts.ProtectedURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "After calling the logout endpoint, the original access token still " +
		"granted access to a protected resource. Logout must revoke server-side state " +
		"(token blocklist, session record, refresh-token family) so that a stolen token " +
		"cannot be reused after the user signs out."
	f.Evidence = fmt.Sprintf(
		"Login URL: %s\nLogout URL: %s\nProtected URL: %s\nAccess token: %s\n"+
			"Protected response after logout: status=%d, length=%d",
		opts.LoginURL, opts.LogoutURL, opts.ProtectedURL,
		redact(tp.Access), protectedResp.StatusCode, len(protectedResp.Body),
	)
	f.Remediation = "Invalidate the session record on logout. For JWTs, push the jti " +
		"to a server-side blocklist until its exp; for opaque tokens, delete the " +
		"session row. Also revoke any associated refresh tokens."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-06"},
		[]string{"A07:2025"},
		[]string{"CWE-613"},
	)
	return f
}

// findingConcurrent creates a Low severity finding for concurrent sessions
// when single-session is required by policy.
func (d *Detector) findingConcurrent(opts DetectOptions, first, second *tokenPair, firstResp, secondResp *http.Response) *core.Finding {
	f := core.NewFinding("Concurrent Sessions Permitted", core.SeverityLow)
	f.URL = opts.ProtectedURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "Two simultaneous sessions for the same user remained valid at the " +
		"same time. Configuration specifies single-session enforcement, so the older " +
		"session should have been invalidated when the user re-authenticated."
	f.Evidence = fmt.Sprintf(
		"User: %s\nFirst token: %s (status=%d)\nSecond token: %s (status=%d)",
		opts.Username,
		redact(first.Access), firstResp.StatusCode,
		redact(second.Access), secondResp.StatusCode,
	)
	f.Remediation = "If single-session is required by policy, invalidate the prior " +
		"session whenever a user logs in again. Alternatively, expose a 'sign out " +
		"other sessions' control and bind sessions to device/IP fingerprints."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-01"},
		[]string{"A07:2025"},
		[]string{"CWE-613"},
	)
	return f
}

// redact returns a short, non-secret-leaking representation of a token for
// inclusion in findings. The full token never appears in evidence.
func redact(tok string) string {
	if tok == "" {
		return "<empty>"
	}
	if len(tok) <= 8 {
		return "***"
	}
	return tok[:4] + "..." + tok[len(tok)-2:]
}
