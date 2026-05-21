package passwordreset

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// attackerHost is the canary host injected into the Host /
// X-Forwarded-Host headers. It uses a reserved label (.example) so it
// cannot accidentally collide with a real production host.
const attackerHost = "assay-passwordreset-poison.example"

// toolName is the value emitted in Finding.Tool for all findings in
// this package.
const toolName = "passwordreset-detector"

// requestPathHints / confirmPathHints are the substrings we add to the
// reset base URL when probing for the two-step (request, confirm) flow.
// Most apps expose the flow under /password/forgot or /password/reset
// and /password/confirm; we accept the base URL as-is and try both
// "request" and "confirm" suffixes alongside it.
var (
	requestPathHints = []string{"", "/request", "/forgot"}
	confirmPathHints = []string{"/confirm", "/reset", ""}
)

// Detector probes a password-reset endpoint for the three classic
// account-takeover flaws (host-header poison, cross-user replay, single-use
// bypass).
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a Detector wired to the shared HTTP client.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose enables verbose output for the detector.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the password-reset audit. UserA is always
// required; UserB is required only for the cross-user check.
type DetectOptions struct {
	UserA   string
	UserB   string
	Timeout time.Duration
}

// DetectionResult bundles findings from a single sub-check.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// DetectAll runs every sub-check and returns one DetectionResult per
// check in stable order (host-header, cross-user, replay). Errors from
// individual checks are surfaced via the returned error only when they
// prevent the check from running at all — per-request failures are
// silently skipped, matching the rest of the detector package.
func (d *Detector) DetectAll(ctx context.Context, resetURL string, opts DetectOptions) ([]*DetectionResult, error) {
	results := make([]*DetectionResult, 0, 3)

	host, err := d.DetectHostHeaderPoisoning(ctx, resetURL, opts)
	if err != nil {
		return results, fmt.Errorf("host-header check failed: %w", err)
	}
	results = append(results, host)

	cross, err := d.DetectCrossUserToken(ctx, resetURL, opts)
	if err != nil {
		return results, fmt.Errorf("cross-user check failed: %w", err)
	}
	results = append(results, cross)

	replay, err := d.DetectTokenReplay(ctx, resetURL, opts)
	if err != nil {
		return results, fmt.Errorf("replay check failed: %w", err)
	}
	results = append(results, replay)

	return results, nil
}

// DetectHostHeaderPoisoning posts a reset request with a hostile Host /
// X-Forwarded-Host header and checks whether the returned reset URL (or
// any other absolute URL in the body / Location header) carries the
// attacker host.
func (d *Detector) DetectHostHeaderPoisoning(ctx context.Context, resetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "host-header-poisoning",
	}

	// We inject through X-Forwarded-Host because the underlying
	// http.Client overwrites the Host header from the URL — proxies and
	// reverse-proxies are the realistic vector anyway.
	body := buildRequestBody(opts.UserA)

	probes := []struct{ header string }{
		{"X-Forwarded-Host"},
		{"X-Host"},
		{"X-Forwarded-Server"},
	}

	for _, hint := range requestPathHints {
		requestURL := joinPath(resetURL, hint)
		for _, p := range probes {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			client := d.client.Clone().WithHeaders(map[string]string{p.header: attackerHost})
			resp, err := client.SendRawBody(ctx, requestURL, "POST", body, "application/json")
			if err != nil || resp == nil {
				continue
			}
			if !containsAttacker(resp, attackerHost) {
				continue
			}

			result.Vulnerable = true
			result.Findings = append(result.Findings, buildHostHeaderFinding(resetURL, p.header, attackerHost, resp))
			return result, nil
		}
	}

	return result, nil
}

// DetectCrossUserToken requests a reset for UserA, extracts the issued
// token, and submits the token to confirm a password change for UserB.
// If the confirmation succeeds, the token is not scoped to the issuing
// user — a critical IDOR-style flaw.
func (d *Detector) DetectCrossUserToken(ctx context.Context, resetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "cross-user-token",
	}

	if opts.UserB == "" {
		return result, nil // cannot meaningfully test without a second user
	}

	token, requestURL, err := d.requestToken(ctx, resetURL, opts.UserA)
	if err != nil || token == "" {
		return result, nil
	}

	confirmURL := chooseConfirmURL(resetURL, requestURL)
	body := buildConfirmBody(opts.UserB, token, "Sk1ppy!NewPass#2026")

	resp, err := d.client.SendRawBody(ctx, confirmURL, "POST", body, "application/json")
	if err != nil || resp == nil {
		return result, nil
	}

	if !looksLikeConfirmSuccess(resp) {
		return result, nil
	}

	result.Vulnerable = true
	result.Findings = append(result.Findings, buildCrossUserFinding(resetURL, opts.UserA, opts.UserB, token, resp))
	return result, nil
}

// DetectTokenReplay requests a reset, submits the token successfully,
// then submits the same token again. If the second submission also
// succeeds, the token is not invalidated after first use.
func (d *Detector) DetectTokenReplay(ctx context.Context, resetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "token-replay",
	}

	token, requestURL, err := d.requestToken(ctx, resetURL, opts.UserA)
	if err != nil || token == "" {
		return result, nil
	}

	confirmURL := chooseConfirmURL(resetURL, requestURL)

	body1 := buildConfirmBody(opts.UserA, token, "Sk1ppy!NewPass#A")
	first, err := d.client.SendRawBody(ctx, confirmURL, "POST", body1, "application/json")
	if err != nil || first == nil || !looksLikeConfirmSuccess(first) {
		// If the first submission already failed, replay isn't meaningful.
		return result, nil
	}

	body2 := buildConfirmBody(opts.UserA, token, "Sk1ppy!NewPass#B")
	second, err := d.client.SendRawBody(ctx, confirmURL, "POST", body2, "application/json")
	if err != nil || second == nil {
		return result, nil
	}
	if !looksLikeConfirmSuccess(second) {
		return result, nil
	}

	result.Vulnerable = true
	result.Findings = append(result.Findings, buildReplayFinding(resetURL, token, first, second))
	return result, nil
}

// ---------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------

// requestToken issues a reset request for the given user and returns
// the issued token if one can be extracted from the response body. The
// returned URL is the request endpoint actually used, so the confirm
// step can derive a sibling URL if hints were applied.
func (d *Detector) requestToken(ctx context.Context, resetURL, user string) (string, string, error) {
	body := buildRequestBody(user)

	for _, hint := range requestPathHints {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		default:
		}

		u := joinPath(resetURL, hint)
		resp, err := d.client.SendRawBody(ctx, u, "POST", body, "application/json")
		if err != nil || resp == nil {
			continue
		}
		token := extractToken(resp.Body)
		if token != "" {
			return token, u, nil
		}
	}
	return "", resetURL, nil
}

// tokenRegex captures the most common JSON shapes used to return a
// reset token. We avoid HTML scraping — JSON is by far the dominant
// reset-API shape and HTML inspection is a separate problem.
var tokenRegex = regexp.MustCompile(`"(?:token|reset_token|resetToken|code)"\s*:\s*"([^"]+)"`)

func extractToken(body string) string {
	if m := tokenRegex.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// Fallback: try a tolerant JSON unmarshal — handles cases where the
	// token is in a nested "data" envelope.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err == nil {
		if v, ok := parsed["token"].(string); ok && v != "" {
			return v
		}
		if v, ok := parsed["reset_token"].(string); ok && v != "" {
			return v
		}
		if data, ok := parsed["data"].(map[string]any); ok {
			if v, ok := data["token"].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// buildRequestBody / buildConfirmBody build JSON payloads small enough
// to flex multiple shapes — the regex / matcher on the server side
// usually finds the field it cares about.
func buildRequestBody(user string) string {
	if user == "" {
		user = "anonymous@example.com"
	}
	out, _ := json.Marshal(map[string]string{
		"email":    user,
		"username": user,
	})
	return string(out)
}

func buildConfirmBody(user, token, newPassword string) string {
	if user == "" {
		user = "anonymous@example.com"
	}
	out, _ := json.Marshal(map[string]string{
		"email":        user,
		"username":     user,
		"token":        token,
		"reset_token":  token,
		"new_password": newPassword,
		"password":     newPassword,
	})
	return string(out)
}

// chooseConfirmURL picks a confirm URL based on the request URL when
// available. We try a few common sibling paths; the first that contains
// the canonical "confirm" / "reset" segment wins. This keeps the
// detector robust against routes that don't share a base path.
func chooseConfirmURL(resetURL, requestURL string) string {
	// If the request URL already contains "confirm", reuse it.
	for _, hint := range confirmPathHints {
		if hint != "" && strings.Contains(strings.ToLower(requestURL), strings.ToLower(hint)) {
			return requestURL
		}
	}
	for _, hint := range confirmPathHints {
		if hint == "" {
			continue
		}
		candidate := joinPath(resetURL, hint)
		if candidate != requestURL {
			return candidate
		}
	}
	return resetURL
}

// joinPath concatenates a base URL with a path hint. It is intentionally
// dumb — we don't want url.Parse normalization to drop trailing slashes
// or rewrite test-server URLs.
func joinPath(base, hint string) string {
	if hint == "" {
		return base
	}
	base = strings.TrimRight(base, "/")
	hint = strings.TrimLeft(hint, "/")
	return base + "/" + hint
}

// looksLikeConfirmSuccess is the heuristic used to decide whether a
// confirm POST succeeded. We prefer explicit 2xx status codes; for 200
// we also require the body not to mention error / invalid / forbidden.
// 4xx / 5xx is always failure.
func looksLikeConfirmSuccess(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode >= 400 {
		return false
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		lower := strings.ToLower(resp.Body)
		failureMarkers := []string{
			"invalid token",
			"invalid_token",
			"token expired",
			"token_expired",
			"already used",
			"forbidden",
			"unauthorized",
			"\"error\"",
			"not allowed",
		}
		for _, m := range failureMarkers {
			if strings.Contains(lower, m) {
				return false
			}
		}
		return true
	}
	// 3xx redirects: treat as success only if Location is set — many
	// reset flows redirect to /login or /done on success.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Headers["Location"] != ""
	}
	return false
}

// containsAttacker checks whether the attacker host appears in the
// response body or in any link-building response header. We deliberately
// look at headers (Location / Link) AND body — reset-link APIs return
// the URL in JSON, while form-based flows hand it back via Location.
func containsAttacker(resp *http.Response, attacker string) bool {
	if resp == nil {
		return false
	}
	atk := strings.ToLower(attacker)
	for _, hdr := range []string{"Location", "Link", "Refresh", "Content-Location"} {
		if v := resp.Headers[hdr]; v != "" && strings.Contains(strings.ToLower(v), atk) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(resp.Body), atk)
}

// ---------------------------------------------------------------------
// Finding builders
// ---------------------------------------------------------------------

func buildHostHeaderFinding(resetURL, header, attacker string, resp *http.Response) *core.Finding {
	f := core.NewFinding("Password Reset Host Header Poisoning", core.SeverityHigh)
	f.URL = resetURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = fmt.Sprintf(
		"The password-reset endpoint accepted a %s header with an attacker-controlled host (%s) and "+
			"the response carried that host inside the reset link. The transactional reset email would "+
			"therefore point at the attacker's domain — a one-step path to account takeover.",
		header, attacker,
	)
	f.Evidence = fmt.Sprintf("%s: %s\nAttacker host found in response (status %d)\nBody (truncated): %s",
		header, attacker, resp.StatusCode, truncate(resp.Body, 256))
	f.Remediation = "Build the reset link from a server-side allowlist of canonical hosts. Never trust " +
		"the request's Host, X-Forwarded-Host, X-Host or X-Forwarded-Server when generating links used " +
		"in transactional emails. Configure reverse proxies to strip or normalize these headers."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-09"},
		[]string{"A07:2025"},
		[]string{"CWE-640"},
	)
	return f
}

func buildCrossUserFinding(resetURL, userA, userB, token string, resp *http.Response) *core.Finding {
	f := core.NewFinding("Cross-User Reset Token Accepted", core.SeverityCritical)
	f.URL = resetURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceConfirmed
	f.Description = fmt.Sprintf(
		"A password-reset token issued for %q was accepted when submitted to change the password of %q. "+
			"The token is not bound to the requesting account, so anyone holding a token (or guessing one) "+
			"can take over any other account in the system.",
		userA, userB,
	)
	f.Evidence = fmt.Sprintf("Token issued to: %s\nReplayed for: %s\nToken: %s\nConfirm status: %d",
		userA, userB, token, resp.StatusCode)
	f.Remediation = "Bind each reset token to the user it was issued for, and verify on confirmation that " +
		"the supplied identifier matches that binding. Prefer indexing the confirm lookup by token alone " +
		"so the email parameter cannot override the binding."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-09"},
		[]string{"A07:2025"},
		[]string{"CWE-640"},
	)
	return f
}

func buildReplayFinding(resetURL, token string, first, second *http.Response) *core.Finding {
	f := core.NewFinding("Reset Token Replay", core.SeverityHigh)
	f.URL = resetURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceConfirmed
	f.Description = "The password-reset endpoint accepted the same reset token twice in succession. " +
		"Tokens that are not invalidated after first use let an attacker who intercepts a single reset " +
		"email replay it indefinitely, defeating the security boundary of a single-use credential."
	f.Evidence = fmt.Sprintf("Token: %s\nFirst confirm status: %d\nSecond confirm status: %d",
		token, first.StatusCode, second.StatusCode)
	f.Remediation = "Invalidate reset tokens immediately after first successful use. Persist token state " +
		"server-side (used / pending) and reject any subsequent submission for the same token. Pair with " +
		"short expiry (15 minutes is typical)."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-09"},
		[]string{"A07:2025"},
		[]string{"CWE-294"},
	)
	return f
}

// truncate cuts a string to at most n runes for inclusion in evidence
// (avoids dumping multi-megabyte bodies into the finding).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
