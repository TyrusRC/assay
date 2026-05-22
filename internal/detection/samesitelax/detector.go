package samesitelax

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector flags auth-bearing cookies whose SameSite attribute leaves the
// app exposed to top-level GET CSRF — the modern-browser default of Lax
// (and the explicit None) both allow cross-site GET navigation to carry
// the session cookie.
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "samesitelax" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Inspects Set-Cookie SameSite attributes on auth-bearing cookies and (optionally) confirms exploitable GET-based state changes against well-known logout paths. Modern browsers default missing SameSite to Lax, which still permits top-level GET CSRF."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	Timeout time.Duration
	// ProbeLogoutPaths enables the GET /logout confirmation phase. When
	// the app accepts a state-changing GET, the finding is promoted from
	// Low (configuration) to Medium (confirmed CSRF surface).
	ProbeLogoutPaths bool
	// LogoutPaths overrides the default logout-candidate list.
	LogoutPaths []string
}

// DefaultOptions returns recommended defaults. GET-logout probing is
// off by default — it's a state-changing request and a scanner shouldn't
// log a user out without explicit opt-in.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second}
}

// DetectionResult carries findings and the list of cookie names flagged.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	ProblemCookies []string
}

// defaultLogoutPaths are the relative paths the detector probes when
// ProbeLogoutPaths is enabled. Curated for low side-effect risk: every
// candidate only invalidates the current session.
func defaultLogoutPaths() []string {
	return []string{"/logout", "/signout", "/sign-out", "/log-out", "/logoff", "/api/logout"}
}

// Detect runs the probe.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:       make([]*core.Finding, 0),
		ProblemCookies: make([]string, 0),
	}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}

	u, err := url.Parse(target)
	if err != nil {
		return res, fmt.Errorf("samesitelax: parse: %w", err)
	}

	baseline, err := d.get(ctx, u.String(), opts.Timeout)
	if err != nil || baseline == nil {
		return res, nil
	}

	cookies := extractCookies(baseline.RawHeaders)
	if len(cookies) == 0 {
		return res, nil
	}

	problems := pickProblemCookies(cookies)
	if len(problems) == 0 {
		return res, nil
	}

	getLogoutConfirmed := ""
	if opts.ProbeLogoutPaths {
		paths := opts.LogoutPaths
		if len(paths) == 0 {
			paths = defaultLogoutPaths()
		}
		getLogoutConfirmed = d.probeGetLogout(ctx, u, paths, opts.Timeout)
	}

	for _, c := range problems {
		res.ProblemCookies = append(res.ProblemCookies, c.Name)
		res.Findings = append(res.Findings, buildFinding(target, c, getLogoutConfirmed))
	}
	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// problemCookie pairs a parsed cookie with the SameSite verdict we
// reached for it (lax / none / missing).
type problemCookie struct {
	Name     string
	SameSite string // "lax", "none", or "" for missing
	Secure   bool
}

// pickProblemCookies returns auth-bearing cookies whose SameSite is
// missing, Lax, or None. Strict cookies are ignored.
func pickProblemCookies(cookies []*http.Cookie) []problemCookie {
	out := make([]problemCookie, 0, len(cookies))
	for _, c := range cookies {
		if !looksAuthBearing(c.Name) {
			continue
		}
		switch c.SameSite {
		case http.SameSiteStrictMode:
			continue
		case http.SameSiteLaxMode:
			out = append(out, problemCookie{Name: c.Name, SameSite: "lax", Secure: c.Secure})
		case http.SameSiteNoneMode:
			out = append(out, problemCookie{Name: c.Name, SameSite: "none", Secure: c.Secure})
		default:
			// http.SameSiteDefaultMode or unset — Chrome 80+ treats as Lax.
			out = append(out, problemCookie{Name: c.Name, SameSite: "", Secure: c.Secure})
		}
	}
	return out
}

// looksAuthBearing applies a case-insensitive name match to decide
// whether the cookie carries session/auth context. Conservative: a
// preference cookie shouldn't trigger a CSRF finding.
func looksAuthBearing(name string) bool {
	n := strings.ToLower(name)
	prefixes := []string{"sess", "sid", "jsession", "phpsess", "token", "auth", "csrf", "xsrf"}
	for _, p := range prefixes {
		if strings.Contains(n, p) {
			return true
		}
	}
	// Express defaults to "connect.sid".
	return n == "connect.sid"
}

// extractCookies pulls Set-Cookie values out of the raw header map.
// Falls back to the joined Headers value when RawHeaders is nil — older
// callers (or mocked tests) may not populate it.
func extractCookies(raw http.Header) []*http.Cookie {
	if raw == nil {
		return nil
	}
	r := http.Response{Header: raw}
	return r.Cookies()
}

// probeGetLogout walks the candidate logout paths and returns the first
// path that accepts a GET and invalidates the session — either by
// returning a clear-session Set-Cookie or by redirecting to a login page.
// Returns "" when no path confirmed.
func (d *Detector) probeGetLogout(ctx context.Context, base *url.URL, paths []string, timeout time.Duration) string {
	for _, p := range paths {
		probe := *base
		probe.Path = p
		probe.RawQuery = ""
		resp, err := d.get(ctx, probe.String(), timeout)
		if err != nil || resp == nil {
			continue
		}
		if logoutConfirmed(resp) {
			return p
		}
	}
	return ""
}

// logoutConfirmed reports whether resp looks like a successful session
// invalidation. Two signals: a Set-Cookie clearing a session cookie, or
// a redirect to a login-like path.
func logoutConfirmed(resp *scanhttp.Response) bool {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := strings.ToLower(resp.Headers["Location"])
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") || strings.Contains(loc, "auth") {
			return true
		}
	}
	cookies := extractCookies(resp.RawHeaders)
	for _, c := range cookies {
		if !looksAuthBearing(c.Name) {
			continue
		}
		// MaxAge < 0 (or Expires in the past) clears a cookie. The
		// net/http parser surfaces MaxAge=-1 as RawExpires set; we
		// check both signals.
		if c.MaxAge < 0 || c.Value == "" {
			return true
		}
	}
	return false
}

func (d *Detector) get(ctx context.Context, target string, timeout time.Duration) (*scanhttp.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.client.Get(reqCtx, target)
}

func buildFinding(target string, c problemCookie, getLogout string) *core.Finding {
	severity := core.SeverityLow
	titleSuffix := "missing/Lax SameSite"
	switch c.SameSite {
	case "lax":
		titleSuffix = "SameSite=Lax"
	case "none":
		titleSuffix = "SameSite=None"
		// SameSite=None requires Secure; without Secure it's worse than
		// Lax (also exposes to plain-HTTP MITM).
	case "":
		titleSuffix = "missing SameSite (browser default is Lax)"
	}

	evidence := fmt.Sprintf("Set-Cookie %s carries %s — top-level GET CSRF surface", c.Name, titleSuffix)
	description := fmt.Sprintf("The auth-bearing cookie %q was issued with %s. Modern browsers send Lax-mode (and None-mode) cookies on top-level GET navigation initiated from another site, so any state-changing endpoint reachable via GET is exploitable via CSRF (e.g., logout, account-link toggles, single-click privilege grants). SameSite=Strict prevents this; the cookie is not sent on any cross-site request.", c.Name, titleSuffix)

	if getLogout != "" {
		severity = core.SeverityMedium
		evidence = fmt.Sprintf("Set-Cookie %s carries %s; GET %s invalidated the session (GET-accepted state-changing endpoint confirmed)", c.Name, titleSuffix, getLogout)
		description += fmt.Sprintf(" An attacker page can force the victim's browser to issue GET %s, logging them out without their knowledge.", getLogout)
	}

	f := core.NewFinding("SameSite CSRF surface", severity)
	f.Title = fmt.Sprintf("Auth cookie %q exposed to top-level GET CSRF (%s)", c.Name, titleSuffix)
	f.URL = target
	f.Tool = "samesitelax-detector"
	f.Description = description
	f.Evidence = evidence
	f.Remediation = "Set SameSite=Strict on session and other auth-bearing cookies whenever possible. When third-party embeds (federated login, payment iframes) require cross-site cookie delivery, use SameSite=None+Secure but pair it with anti-CSRF tokens and reject state-changing requests on GET. Never rely on the browser default — explicitly set SameSite=Strict, Lax, or None."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-02", "WSTG-SESS-05"},
		[]string{"A01:2025", "A07:2025"},
		[]string{"CWE-352", "CWE-1275"},
	)
	return f
}
