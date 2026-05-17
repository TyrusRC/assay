// Multi-step CSRF state-binding probes.
//
// These three detectors live next to the cross-origin probe in detector.go
// but exercise a different threat model: properly-bound vs improperly-bound
// CSRF tokens across (a) wizard steps, (b) replay windows, (c) sessions.
// They never mutate target state irreversibly — each probe is one Issue
// followed by one Submit, and the verdict is purely on the submit response.
package csrf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// MultiStepOptions configures the three multi-step CSRF probes.
//
// Fields are opt-in per probe:
//   - DetectStateReuseAcrossSteps uses Step1URL + Step2URL (+ optional Step3URL).
//   - DetectTokenIssuedNRequestsPrior uses Step1URL + ActionURL + UnrelatedURLs.
//   - DetectCrossSessionTokenAcceptance uses Step1URL + ActionURL.
//
// Timeout caps each probe's wall clock. Zero means "use a sane default".
type MultiStepOptions struct {
	Step1URL      string
	Step2URL      string
	Step3URL      string
	ActionURL     string
	UnrelatedURLs []string
	Timeout       time.Duration
}

const (
	// multiStepTool is the tool name stamped onto every multi-step finding.
	multiStepTool = "csrf-multistep-detector"
	// defaultMultiStepTimeout caps a probe when the caller passes zero.
	defaultMultiStepTimeout = 30 * time.Second
	// maxUnrelatedRequests caps the replay-window probe at the canonical
	// "way more than any reasonable rotation window" depth.
	maxUnrelatedRequests = 50
)

// tokenRegexes scrape a CSRF token out of HTML / form responses. We try
// multiple shapes so the probe works against typical frameworks (Rails
// meta-tags, Django form hidden inputs, etc.).
var tokenRegexes = []*regexp.Regexp{
	// <meta name="csrf-token" content="...">
	regexp.MustCompile(`(?i)<meta[^>]+name=["']csrf[-_]?token["'][^>]+content=["']([^"']+)["']`),
	// <input ... name="..csrf.." value="...">
	regexp.MustCompile(`(?i)<input[^>]+name=["'][^"']*csrf[^"']*["'][^>]+value=["']([^"']+)["']`),
	// <input ... value="..." name="..csrf..">
	regexp.MustCompile(`(?i)<input[^>]+value=["']([^"']+)["'][^>]+name=["'][^"']*csrf[^"']*["']`),
}

// jsonTokenKeys lists the JSON keys we treat as the CSRF token field when
// the issue endpoint returns JSON. First match wins.
var jsonTokenKeys = []string{
	"csrf_token", "csrfToken", "csrf", "_csrf",
	"xsrf_token", "xsrfToken", "token", "authenticity_token",
}

// DetectStateReuseAcrossSteps probes a multi-step ("wizard") flow for
// missing token rotation between steps.
//
// Algorithm:
//  1. GET Step1URL to obtain a token T.
//  2. POST T to Step2URL.
//  3. POST T to Step3URL (only if Step3URL is set).
//
// When a later step returns 2xx while reusing the original step-1 token,
// the server is failing to rotate per step and a Medium finding is emitted.
// A safe server either re-issues a fresh token at each step (rotation) or
// rejects the original (4xx).
func (d *Detector) DetectStateReuseAcrossSteps(ctx context.Context, opts MultiStepOptions) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	if opts.Step1URL == "" || opts.Step2URL == "" {
		return res, nil
	}

	ctx, cancel := withMultiStepTimeout(ctx, opts.Timeout)
	defer cancel()

	token, err := issueToken(ctx, d.client, opts.Step1URL)
	if err != nil || token == "" {
		return res, nil
	}

	step2OK, err := submitToken(ctx, d.client, opts.Step2URL, token)
	if err != nil {
		return res, nil
	}
	hasStep3 := opts.Step3URL != ""
	step3OK := false
	if hasStep3 {
		step3OK, err = submitToken(ctx, d.client, opts.Step3URL, token)
		if err != nil {
			return res, nil
		}
	}

	// Flag only when EVERY later step accepted the original token. Servers
	// that allow single-use of T at step2 (consume + rotate to T') and
	// then reject T at step3 are rotating correctly — that path lands on
	// step2OK=true && step3OK=false and must NOT emit a finding.
	flagged := step2OK && (!hasStep3 || step3OK)
	if !flagged {
		return res, nil
	}

	accepted := []string{opts.Step2URL}
	if hasStep3 {
		accepted = append(accepted, opts.Step3URL)
	}

	finding := core.NewFinding("CSRF Token Reused Across Wizard Steps", core.SeverityMedium)
	finding.URL = opts.Step1URL
	finding.Tool = multiStepTool
	finding.Confidence = core.ConfidenceHigh
	finding.Description = "The wizard issued a CSRF token at step 1 and accepted the SAME token at one or more later steps. Without per-step token rotation, an attacker only has to compromise a single token to drive the entire flow to completion."
	finding.Evidence = fmt.Sprintf(
		"Step1 (issue): %s\nReused token accepted at: %s\nToken (truncated): %s",
		opts.Step1URL, strings.Join(accepted, ", "), truncateToken(token),
	)
	finding.Remediation = "Rotate the CSRF token between every wizard step. Treat each transition as a fresh issuance and invalidate prior tokens server-side."
	finding.WithOWASPMapping(
		[]string{"WSTG-SESS-05"},
		[]string{"A01:2025"},
		[]string{"CWE-352"},
	)
	res.Findings = append(res.Findings, finding)
	return res, nil
}

// DetectTokenIssuedNRequestsPrior probes whether a CSRF token has any
// replay-window limit.
//
// Algorithm:
//  1. GET Step1URL → token T.
//  2. Issue up to maxUnrelatedRequests GETs against UnrelatedURLs. A
//     well-behaved server may rotate the token on these unrelated hits.
//  3. POST T to ActionURL. If the original token is still accepted after
//     many unrelated requests, the token has no replay window — Medium.
//
// Safe servers either rotate the token (issue a fresh one tied to a new
// nonce) or attach a short TTL and reject stale tokens.
func (d *Detector) DetectTokenIssuedNRequestsPrior(ctx context.Context, opts MultiStepOptions) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	if opts.Step1URL == "" || opts.ActionURL == "" {
		return res, nil
	}

	ctx, cancel := withMultiStepTimeout(ctx, opts.Timeout)
	defer cancel()

	token, err := issueToken(ctx, d.client, opts.Step1URL)
	if err != nil || token == "" {
		return res, nil
	}

	count := len(opts.UnrelatedURLs)
	if count > maxUnrelatedRequests {
		count = maxUnrelatedRequests
	}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return res, nil
		}
		_, _ = d.client.Get(ctx, opts.UnrelatedURLs[i])
	}

	ok, err := submitToken(ctx, d.client, opts.ActionURL, token)
	if err != nil || !ok {
		return res, nil
	}

	finding := core.NewFinding("CSRF Token Has No Replay Window Limit", core.SeverityMedium)
	finding.URL = opts.ActionURL
	finding.Tool = multiStepTool
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"A CSRF token issued at %s was accepted at %s after %d intervening unrelated requests. The token has no replay window or rotation policy — once exfiltrated it remains valid indefinitely.",
		opts.Step1URL, opts.ActionURL, count,
	)
	finding.Evidence = fmt.Sprintf(
		"Issue URL: %s\nAction URL: %s\nUnrelated requests in between: %d\nToken (truncated): %s",
		opts.Step1URL, opts.ActionURL, count, truncateToken(token),
	)
	finding.Remediation = "Bind every CSRF token to a short TTL and rotate it after each successful use. Reject tokens whose age exceeds the session's expected interaction cadence."
	finding.WithOWASPMapping(
		[]string{"WSTG-SESS-05"},
		[]string{"A01:2025"},
		[]string{"CWE-352"},
	)
	res.Findings = append(res.Findings, finding)
	return res, nil
}

// DetectCrossSessionTokenAcceptance probes whether a CSRF token is bound to
// the session that issued it.
//
// Algorithm:
//  1. Session A (fresh clone) GETs Step1URL → token T_A + cookie C_A.
//  2. Session B (different fresh clone) GETs Step1URL too to obtain its
//     own cookie C_B, then POSTs T_A to ActionURL under C_B.
//
// A vulnerable server accepts T_A under session B's cookies — the token is
// not bound to a session. Severity is Critical: token reuse across users
// is the single most damaging CSRF failure mode.
func (d *Detector) DetectCrossSessionTokenAcceptance(ctx context.Context, opts MultiStepOptions) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	if opts.Step1URL == "" || opts.ActionURL == "" {
		return res, nil
	}

	ctx, cancel := withMultiStepTimeout(ctx, opts.Timeout)
	defer cancel()

	// Session A: capture token + Set-Cookie from /login.
	sessionA := d.client.Clone()
	respA, err := sessionA.Get(ctx, opts.Step1URL)
	if err != nil || respA == nil {
		return res, nil
	}
	token := parseTokenFromResponse(respA.Body)
	if token == "" {
		return res, nil
	}

	// Session B: a fresh client that hits /login itself to establish a
	// DIFFERENT session cookie, then submits T_A.
	sessionB := d.client.Clone()
	respB, err := sessionB.Get(ctx, opts.Step1URL)
	if err != nil || respB == nil {
		return res, nil
	}
	if cookieB := extractSessionCookie(respB.Headers); cookieB != "" {
		sessionB = sessionB.WithCookies(cookieB)
	}

	// Cross-session submit: T_A under session B's cookie jar.
	ok, err := submitToken(ctx, sessionB, opts.ActionURL, token)
	if err != nil || !ok {
		return res, nil
	}

	finding := core.NewFinding("CSRF Token Not Bound to Session", core.SeverityCritical)
	finding.URL = opts.ActionURL
	finding.Tool = multiStepTool
	finding.Confidence = core.ConfidenceHigh
	finding.Description = "A CSRF token issued to session A was accepted when submitted under session B's cookies. The token is fungible across sessions, which defeats the per-user binding that CSRF tokens are supposed to provide. Any leaked or guessed token can be replayed by any other user."
	finding.Evidence = fmt.Sprintf(
		"Issue URL (session A): %s\nAction URL (submitted under session B): %s\nToken (truncated): %s",
		opts.Step1URL, opts.ActionURL, truncateToken(token),
	)
	finding.Remediation = "Bind every CSRF token to the issuing session (signed against the session id, or stored in the server-side session). Reject tokens whose binding does not match the incoming session cookie."
	finding.WithOWASPMapping(
		[]string{"WSTG-SESS-05"},
		[]string{"A01:2025"},
		[]string{"CWE-352", "CWE-613"},
	)
	res.Findings = append(res.Findings, finding)
	return res, nil
}

// --- helpers --------------------------------------------------------------

// withMultiStepTimeout derives a context with the supplied timeout, falling
// back to defaultMultiStepTimeout when the caller passes zero.
func withMultiStepTimeout(ctx context.Context, t time.Duration) (context.Context, context.CancelFunc) {
	if t <= 0 {
		t = defaultMultiStepTimeout
	}
	return context.WithTimeout(ctx, t)
}

// issueToken fetches issueURL with the given client and parses out a CSRF
// token from the response (HTML or JSON). Returns "" when nothing matches.
func issueToken(ctx context.Context, c *skwshttp.Client, issueURL string) (string, error) {
	resp, err := c.Get(ctx, issueURL)
	if err != nil || resp == nil {
		return "", err
	}
	return parseTokenFromResponse(resp.Body), nil
}

// submitToken POSTs `csrf_token=<token>` to actionURL and reports whether
// the server responded 2xx. Form-encoded to match the way most real
// frameworks accept CSRF tokens; servers that read JSON for the same field
// will still see the form body and respond consistently.
func submitToken(ctx context.Context, c *skwshttp.Client, actionURL, token string) (bool, error) {
	body := "csrf_token=" + token
	resp, err := c.SendRawBody(ctx, actionURL, http.MethodPost, body, "application/x-www-form-urlencoded")
	if err != nil || resp == nil {
		return false, err
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// parseTokenFromResponse tries JSON keys first, then HTML regexes. Returns
// empty string when nothing recognisable is found.
func parseTokenFromResponse(body string) string {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if tok := parseTokenFromJSON(trimmed); tok != "" {
			return tok
		}
	}
	for _, re := range tokenRegexes {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// parseTokenFromJSON does a single json.Unmarshal into a generic map and
// walks the well-known token field names. Nested objects are NOT searched —
// the goal is a cheap, predictable parse, not a JSONPath engine.
func parseTokenFromJSON(body string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return ""
	}
	for _, k := range jsonTokenKeys {
		if v, ok := obj[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// extractSessionCookie returns the canonical "name=value" pair for the
// first Set-Cookie header (or empty when none). Attribute params (Path,
// HttpOnly, etc.) are stripped — the cookie jar only needs the pair.
func extractSessionCookie(headers map[string]string) string {
	if headers == nil {
		return ""
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Set-Cookie") {
			if i := strings.Index(v, ";"); i >= 0 {
				return strings.TrimSpace(v[:i])
			}
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// truncateToken redacts most of a token before stamping it into the
// evidence string. We only want to demonstrate identity, not leak the
// secret into the report.
func truncateToken(token string) string {
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + "…" + token[len(token)-4:]
}
