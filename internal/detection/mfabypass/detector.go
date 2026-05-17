// Package mfabypass detects MFA bypass weaknesses (WSTG-ATHN-11).
package mfabypass

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
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

// DetectMFAStepSkip logs in (acquiring a partial pre-MFA session cookie)
// and then attempts to fetch ProtectedURL WITHOUT completing the MFA step.
// A 2xx response means MFA can be bypassed by skipping the OTP exchange.
func (d *Detector) DetectMFAStepSkip(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionStepSkip,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	lr, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}

	probe := d.withCookies(lr.SetCookie)
	resp, err := probe.Get(ctx, opts.ProtectedURL)
	if err != nil {
		return result, fmt.Errorf("protected probe: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		f := d.findingStepSkip(opts, lr, resp)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}
	return result, nil
}

// DetectMFANullValue logs in, then submits MFA OTPs that should be
// rejected by any sane validator (empty string, "0", literal null).
// Any acceptance (2xx) indicates broken validation.
func (d *Detector) DetectMFANullValue(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionNullValue,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	lr, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}

	probe := d.withCookies(lr.SetCookie)

	// Each payload exercises a different "empty-ish" value. The JSON
	// `null` payload requires a separate raw body so the OTP is decoded
	// as nil instead of the literal string "null".
	type attempt struct {
		label string
		body  string
	}
	attempts := []attempt{
		{label: "empty-string", body: `{"otp":""}`},
		{label: "zero-string", body: `{"otp":"0"}`},
		{label: "json-null", body: `{"otp":null}`},
	}

	for _, a := range attempts {
		resp, err := probe.PostJSON(ctx, opts.MFASubmitURL, a.body)
		if err != nil {
			return result, fmt.Errorf("mfa submit (%s): %w", a.label, err)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			f := d.findingNullValue(opts, a.label, a.body, resp)
			result.Findings = append(result.Findings, f)
			result.Vulnerable = true
			// Reporting the first weakness is enough; the rest are duplicates.
			return result, nil
		}
	}
	return result, nil
}

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

// DetectMFAResponseManipulation submits the MFA challenge, then re-sends
// the request with the verification cookie/header flipped from false to
// true. If the server accepts the manipulated value, the verification
// state is client-controlled (CWE-287).
//
// Requires opts.ResponseFlipPattern (the cookie name to flip). When the
// pattern is empty, the check is a no-op.
func (d *Detector) DetectMFAResponseManipulation(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionRespManipulate,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if opts.ResponseFlipPattern == "" {
		return result, nil
	}

	lr, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}
	probe := d.withCookies(lr.SetCookie)

	// First submission with an obviously wrong OTP — we don't care
	// about success; we only need the server to set its verification
	// cookie/header to a false-ish value we can flip.
	first, err := probe.PostJSON(ctx, opts.MFASubmitURL, `{"otp":"000000"}`)
	if err != nil {
		return result, fmt.Errorf("mfa submit #1: %w", err)
	}

	flipped, ok := flipVerifiedCookie(first.Headers["Set-Cookie"], opts.ResponseFlipPattern)
	if !ok {
		// Server didn't emit a verification cookie we could flip.
		return result, nil
	}

	// Replay with the flipped cookie attached.
	tampered := d.client.Clone().WithCookies(flipped)
	resp, err := tampered.Get(ctx, opts.ProtectedURL)
	if err != nil {
		return result, fmt.Errorf("tampered probe: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		f := d.findingRespManipulation(opts, flipped, resp)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}
	return result, nil
}

// DetectAll runs the four MFA-bypass checks in sequence and aggregates
// the results. Errors from individual checks are returned alongside any
// partial findings already gathered.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	aggregate := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionAll,
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

	if opts.LoginURL != "" && opts.ProtectedURL != "" {
		r, err := d.DetectMFAStepSkip(ctx, opts)
		add(r, err)
	}
	if opts.LoginURL != "" && opts.MFASubmitURL != "" {
		r, err := d.DetectMFANullValue(ctx, opts)
		add(r, err)
	}
	if opts.LoginURL != "" && opts.MFASubmitURL != "" {
		r, err := d.DetectMFABruteForce(ctx, opts)
		add(r, err)
	}
	if opts.LoginURL != "" && opts.MFASubmitURL != "" && opts.ProtectedURL != "" && opts.ResponseFlipPattern != "" {
		r, err := d.DetectMFAResponseManipulation(ctx, opts)
		add(r, err)
	}
	return aggregate, firstErr
}

// ---------- helpers ----------

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

// flipVerifiedCookie searches a Set-Cookie header for a cookie whose name
// matches pattern (case-insensitive) and whose value is "false" / "0".
// If found, it returns a Cookie request-header string with that value
// rewritten to "true" / "1" and ok=true.
func flipVerifiedCookie(setCookie, pattern string) (string, bool) {
	if setCookie == "" {
		return "", false
	}
	// Set-Cookie headers may carry multiple cookies separated by commas
	// (per the Client's header-flattening in internal/http). Each entry
	// has the form "name=value; attr=...; attr=...".
	entries := strings.Split(setCookie, ",")
	out := make([]string, 0, len(entries))
	flipped := false
	patternLower := strings.ToLower(pattern)
	for _, e := range entries {
		nameVal := strings.SplitN(strings.TrimSpace(e), ";", 2)[0]
		kv := strings.SplitN(nameVal, "=", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if strings.EqualFold(name, patternLower) || strings.Contains(strings.ToLower(name), patternLower) {
			switch strings.ToLower(val) {
			case "false":
				val = "true"
				flipped = true
			case "0":
				val = "1"
				flipped = true
			}
		}
		out = append(out, name+"="+val)
	}
	if !flipped {
		return "", false
	}
	return strings.Join(out, "; "), true
}

// ---------- finding constructors ----------

func (d *Detector) findingStepSkip(opts DetectOptions, lr *loginResponse, resp *http.Response) *core.Finding {
	f := core.NewFinding(typeStepSkip, core.SeverityCritical)
	f.URL = opts.ProtectedURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "After logging in with username/password the partial pre-MFA " +
		"session cookie granted access to a protected resource without ever " +
		"completing the MFA step. The server is treating the pre-MFA session as " +
		"a fully-authenticated one, allowing an attacker who has only the " +
		"first-factor credential to bypass the second factor entirely."
	f.Evidence = fmt.Sprintf(
		"Login URL: %s\nProtected URL: %s\nLogin status=%d, Set-Cookie=%s\n"+
			"Protected (no MFA) status=%d, length=%d",
		opts.LoginURL, opts.ProtectedURL, lr.StatusCode, lr.SetCookie,
		resp.StatusCode, len(resp.Body),
	)
	f.Remediation = "Issue a strictly pre-MFA token whose only allowed action is " +
		"completing the MFA challenge. Reject this token at every other " +
		"endpoint. Only after MFA verification should the server upgrade the " +
		"session to a fully-authenticated one."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-11"},
		[]string{"A07:2025"},
		[]string{"CWE-287"},
	)
	return f
}

func (d *Detector) findingNullValue(opts DetectOptions, label, body string, resp *http.Response) *core.Finding {
	f := core.NewFinding(typeNullValue, core.SeverityHigh)
	f.URL = opts.MFASubmitURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "The MFA endpoint accepted an OTP value that should never be " +
		"valid (empty / zero / null). Weak validation that treats missing or " +
		"falsy OTP values as a match allows trivial bypass of the second factor."
	f.Evidence = fmt.Sprintf(
		"MFA URL: %s\nAttempt: %s\nRequest body: %s\nResponse status=%d, length=%d",
		opts.MFASubmitURL, label, body, resp.StatusCode, len(resp.Body),
	)
	f.Remediation = "Reject empty, null, and zero-string OTP values before the " +
		"comparison happens. Use constant-time string comparison on the " +
		"server-side TOTP/HOTP value and require a fixed-length numeric input."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-11"},
		[]string{"A07:2025"},
		[]string{"CWE-287"},
	)
	return f
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

func (d *Detector) findingRespManipulation(opts DetectOptions, flippedCookie string, resp *http.Response) *core.Finding {
	f := core.NewFinding(typeRespManipulate, core.SeverityCritical)
	f.URL = opts.ProtectedURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "The server's MFA verification state is carried in a " +
		"client-controllable cookie/header. Flipping the value (e.g. " +
		"mfa_verified=false to mfa_verified=true) was accepted by a " +
		"protected endpoint, meaning MFA verification can be forged " +
		"client-side without ever solving the challenge."
	f.Evidence = fmt.Sprintf(
		"Protected URL: %s\nFlip pattern: %s\nFlipped Cookie header: %s\n"+
			"Tampered response status=%d, length=%d",
		opts.ProtectedURL, opts.ResponseFlipPattern, flippedCookie,
		resp.StatusCode, len(resp.Body),
	)
	f.Remediation = "Never derive MFA verification state from a client-side cookie " +
		"value. Track verification status server-side (signed/encrypted " +
		"session record or short-lived signed token) and refuse to honor any " +
		"client-supplied 'verified' flag."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-11"},
		[]string{"A07:2025"},
		[]string{"CWE-287"},
	)
	return f
}
