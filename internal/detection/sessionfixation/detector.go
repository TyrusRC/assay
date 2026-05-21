// Package sessionfixation implements WSTG-SESS-03 session fixation detection.
package sessionfixation

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// toolName identifies findings emitted by this detector.
const toolName = "sessionfixation-detector"

// Detection-result type tags surfaced via DetectionResult.DetectionType.
const (
	detectionPreAuthCookie = "preauth-cookie-kept"
	detectionQueryAccepted = "session-id-from-query"
	detectionAll           = "session-fixation-all"
)

// defaultCookieName is used when DetectOptions.CookieName is left empty.
const defaultCookieName = "SESSIONID"

// attackerControlledValue is the fixated session identifier the detector
// presents to the application. It is intentionally distinctive so that an
// echoed value is unambiguous evidence of fixation.
const attackerControlledValue = "attackerchose123"

// Detector performs session fixation detection.
type Detector struct {
	client *http.Client
}

// New creates a new session-fixation detector.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// DetectOptions configures session-fixation detection.
type DetectOptions struct {
	// LoginURL is the form/JSON endpoint that authenticates the user. The
	// detector posts username/password against it using application/x-www-
	// form-urlencoded so it works against typical HTML login forms.
	LoginURL string
	// ProtectedURL is a URL that requires authentication. Used by the query-
	// string acceptance check to confirm that a fixated id grants access.
	ProtectedURL string
	// Username/Password are the credentials for an account the tester is
	// authorised to use.
	Username string
	Password string
	// CookieName is the name of the session cookie under test. Defaults to
	// "SESSIONID" when empty.
	CookieName string
	// Timeout is reserved for future use; per-request timeouts are controlled
	// via the supplied http.Client.
	Timeout time.Duration
}

// DetectionResult bundles the outcome of one detection pass.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// cookieName returns the configured cookie name or the default fallback.
func (o DetectOptions) cookieName() string {
	if strings.TrimSpace(o.CookieName) == "" {
		return defaultCookieName
	}
	return o.CookieName
}

// DetectPreAuthSessionAcceptance performs the classic session-fixation check:
//
//  1. Pre-set a session cookie value of the detector's choosing.
//  2. POST the credentials to LoginURL with that cookie attached.
//  3. Inspect the Set-Cookie header returned on a successful login.
//
// If the server keeps the attacker-supplied cookie value instead of rotating
// it on authentication, a High severity finding is emitted.
func (d *Detector) DetectPreAuthSessionAcceptance(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionPreAuthCookie,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if opts.LoginURL == "" {
		return result, fmt.Errorf("LoginURL is required")
	}

	cookieName := opts.cookieName()
	cookieValue := attackerControlledValue

	// Clone the client so we don't mutate caller state, and attach the
	// attacker-chosen cookie BEFORE the login request is sent.
	loginClient := d.client.Clone().WithCookies(cookieName + "=" + cookieValue)

	body := url.Values{}
	body.Set("username", opts.Username)
	body.Set("password", opts.Password)

	resp, err := loginClient.Post(ctx, opts.LoginURL, body.Encode())
	if err != nil {
		return result, fmt.Errorf("login request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("login failed: status=%d", resp.StatusCode)
	}

	postLogin := extractCookie(resp.Headers, cookieName)
	if postLogin == "" {
		// Server did not set a fresh cookie at all. That's a separate
		// hygiene concern but not necessarily fixation; abstain.
		return result, nil
	}

	if postLogin == cookieValue {
		// Server kept the attacker-controlled identifier across the auth
		// boundary. Classic session fixation.
		f := d.findingPreAuthAccepted(opts, cookieName, cookieValue, postLogin)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}

	return result, nil
}

// DetectCookieAcceptedFromQuery probes whether a protected resource accepts
// the session identifier when it is presented through the URL query string.
// A 2xx response with no cookie attached but a fixated query parameter is
// evidence of legacy URL-rewriting session handling.
func (d *Detector) DetectCookieAcceptedFromQuery(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionQueryAccepted,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if opts.ProtectedURL == "" {
		return result, fmt.Errorf("ProtectedURL is required")
	}

	cookieName := opts.cookieName()
	cookieValue := attackerControlledValue

	probeURL, err := appendQueryParam(opts.ProtectedURL, cookieName, cookieValue)
	if err != nil {
		return result, fmt.Errorf("build probe url: %w", err)
	}

	// Use a fresh client with NO cookies — the goal is to observe whether the
	// query parameter alone is enough to be treated as an authenticated
	// session.
	probeClient := d.client.Clone().WithCookies("")
	resp, err := probeClient.Get(ctx, probeURL)
	if err != nil {
		return result, fmt.Errorf("probe request: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		f := d.findingQueryAccepted(opts, cookieName, cookieValue, resp)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}

	return result, nil
}

// DetectAll runs the available checks in sequence and aggregates the result.
// Errors from individual checks are returned alongside any partial findings.
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

	if opts.LoginURL != "" {
		r, err := d.DetectPreAuthSessionAcceptance(ctx, opts)
		add(r, err)
	}
	if opts.ProtectedURL != "" {
		r, err := d.DetectCookieAcceptedFromQuery(ctx, opts)
		add(r, err)
	}
	return aggregate, firstErr
}

// ---------- finding constructors ----------

// findingPreAuthAccepted creates a High severity finding for a server that
// kept the attacker-supplied session id across the auth boundary.
func (d *Detector) findingPreAuthAccepted(opts DetectOptions, cookieName, preLogin, postLogin string) *core.Finding {
	f := core.NewFinding("Session Fixation — Pre-Set Cookie Accepted After Login", core.SeverityHigh)
	f.URL = opts.LoginURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "The application kept the session identifier that was supplied " +
		"by the client BEFORE authentication and re-used the same value AFTER a " +
		"successful login. An attacker who can plant a cookie on the victim's " +
		"browser (via XSS, a shared sub-domain, or a meta-http-equiv injection) " +
		"can therefore hijack the victim's authenticated session as soon as the " +
		"victim signs in."
	f.Evidence = fmt.Sprintf(
		"Login URL: %s\nCookie name: %s\nPre-login cookie value: %s\nPost-login cookie value: %s",
		opts.LoginURL, cookieName, preLogin, postLogin,
	)
	f.Remediation = "Regenerate the session identifier on every privilege transition " +
		"(at minimum on successful authentication, logout, and step-up auth). The " +
		"server must discard the pre-authentication identifier and issue a new, " +
		"unpredictable one that the client has never seen before. Most web " +
		"frameworks expose a single helper for this (e.g. session_regenerate_id() " +
		"in PHP, HttpServletRequest#changeSessionId() in Java EE)."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-03"},
		[]string{"A01:2025"},
		[]string{"CWE-384"},
	)
	return f
}

// findingQueryAccepted creates a Medium severity finding for a server that
// honors the session identifier when it is supplied through the URL query
// string.
func (d *Detector) findingQueryAccepted(opts DetectOptions, cookieName, cookieValue string, resp *http.Response) *core.Finding {
	f := core.NewFinding("Session ID Accepted from Query String", core.SeverityMedium)
	f.URL = opts.ProtectedURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "The protected resource accepted a session identifier supplied " +
		"through the URL query string, with no matching cookie attached to the " +
		"request. Session identifiers that travel through URLs leak into browser " +
		"history, server logs, the Referer header, and shared bookmarks, and are " +
		"trivial to fixate by sending the victim a crafted link."
	f.Evidence = fmt.Sprintf(
		"Protected URL: %s\nQuery parameter: %s=%s\nResponse status: %d\nResponse length: %d",
		opts.ProtectedURL, cookieName, cookieValue, resp.StatusCode, len(resp.Body),
	)
	f.Remediation = "Only accept session identifiers from HttpOnly Secure cookies " +
		"and reject any request that presents a session id through the query " +
		"string or path. Strip URL-rewritten session ids in a fronting reverse " +
		"proxy or framework filter so legacy code cannot honor them."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-03"},
		[]string{"A01:2025"},
		[]string{"CWE-384"},
	)
	return f
}

// ---------- helpers ----------

// extractCookie reads the named cookie value from a response Headers map as
// returned by internal/http.Client. The Client joins multi-value headers with
// ", ", so a Set-Cookie header may contain several cookies separated by
// commas. Cookie attribute pairs use ";", so we split on commas first and
// then on the first ";".
func extractCookie(headers map[string]string, name string) string {
	if headers == nil || name == "" {
		return ""
	}
	// Headers come from http.Header.Get-style joins; the canonical key is
	// "Set-Cookie" but be tolerant of case variations.
	var raw string
	for k, v := range headers {
		if strings.EqualFold(k, "Set-Cookie") {
			raw = v
			break
		}
	}
	if raw == "" {
		return ""
	}
	// net/http's Response.Cookies() expects the raw Header on a real
	// Response; we rebuild a minimal one so we can lean on the stdlib parser.
	resp := &nethttp.Response{Header: nethttp.Header{}}
	// Split on ", " to recover individual Set-Cookie values, but only at the
	// commas that separate cookies (commas inside Expires=Mon, 02 Jan ...
	// would mislead this). The detector's test servers never use Expires, so
	// the simple split is sufficient and we fall back on the stdlib parser
	// for attribute extraction.
	for _, part := range splitSetCookieList(raw) {
		resp.Header.Add("Set-Cookie", part)
	}
	for _, c := range resp.Cookies() {
		if strings.EqualFold(c.Name, name) {
			return c.Value
		}
	}
	return ""
}

// splitSetCookieList splits a comma-joined Set-Cookie string into the
// individual cookie strings. It is intentionally conservative: it splits on
// ", " only when the following segment looks like "name=...", so that commas
// embedded in Expires attribute values are preserved.
func splitSetCookieList(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	for s != "" {
		idx := strings.Index(s, ", ")
		if idx < 0 {
			out = append(out, strings.TrimSpace(s))
			break
		}
		head := s[:idx]
		tail := s[idx+2:]
		// If the next segment looks like a new cookie (token=...), break here.
		eq := strings.Index(tail, "=")
		semi := strings.Index(tail, ";")
		if eq > 0 && (semi < 0 || eq < semi) {
			out = append(out, strings.TrimSpace(head))
			s = tail
			continue
		}
		// Otherwise the comma is part of an attribute value; keep walking.
		out = append(out, strings.TrimSpace(s))
		break
	}
	return out
}

// appendQueryParam appends key=value to the query string of u, preserving any
// existing query parameters.
func appendQueryParam(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
