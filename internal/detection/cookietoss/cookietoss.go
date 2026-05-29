// Package cookietoss audits Set-Cookie attributes for cookie-tossing
// exposure — the attack where a compromised or attacker-controlled
// subdomain writes a cookie that the parent (or sibling) trusts.
//
// Three classes of footgun the detector flags:
//
//  1. Auth-shaped cookies lacking the __Host- or __Secure- prefix.
//     __Host-Foo cookies are pinned to the exact origin AND require
//     Path=/ AND must be Secure — closing the cookie-tossing window.
//     Auth cookies without either prefix are reachable from any
//     subdomain.
//  2. Cookies with an over-broad Domain attribute. Domain=.example.com
//     means any *.example.com host can write or read this cookie —
//     a takeover of legacy.example.com poisons the main app's session.
//  3. Cookies with no Domain attribute AND no Path scoping AND no
//     SameSite. The "lazy default" — works in the simple case but
//     leaves every dimension of cookie protection at its weakest.
//
// References:
//   - https://blog.ankursundara.com/cookie-bugs/
//   - https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis
//   - https://textslashplain.com/2019/09/27/strict-cookie-prefixes/
package cookietoss

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Issue identifies a specific cookie-tossing weakness class.
type Issue string

const (
	IssueAuthNoPrefix    Issue = "auth_cookie_no_prefix"
	IssueOverbroadDomain Issue = "overbroad_domain"
	IssueNoScoping       Issue = "no_scoping_attributes"
	IssueAuthNoSecure    Issue = "auth_cookie_no_secure"
)

// authNamePatterns lists cookie-name substrings that suggest the cookie
// carries authentication. We match case-insensitively against the FULL
// name; anchored substrings would miss customised names. Keeping the
// list narrow avoids flagging tracking cookies.
var authNamePatterns = []string{
	"session", "sess", "sid", "auth", "token", "jwt", "access",
	"refresh", "csrf", "xsrf", "login", "user",
}

// Detector audits cookies for cookie-tossing exposure.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New constructs a Detector.
func New(client *http.Client) *Detector {
	if client == nil {
		client = http.DefaultClient
	}
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the probe.
type DetectOptions struct {
	Timeout time.Duration
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 6 * time.Second}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Cookies    int // total Set-Cookie headers seen
	Findings   []*core.Finding
	Vulnerable bool
}

// Detect issues one GET and audits every Set-Cookie header in the
// response.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}

	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("cookietoss: build request: %w", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cookietoss: do request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	result := &DetectionResult{URL: target}

	for _, raw := range resp.Header.Values("Set-Cookie") {
		result.Cookies++
		findings := d.auditCookie(target, raw)
		result.Findings = append(result.Findings, findings...)
	}

	for _, f := range result.Findings {
		if f.Severity != core.SeverityInfo {
			result.Vulnerable = true
			break
		}
	}
	return result, nil
}

// auditCookie inspects a single Set-Cookie header and emits findings
// for each weakness it carries. A cookie can trigger multiple
// findings (e.g. an auth cookie with both missing prefix AND
// over-broad Domain).
func (d *Detector) auditCookie(target, raw string) []*core.Finding {
	attrs := parseSetCookie(raw)
	if attrs.name == "" {
		return nil
	}

	var out []*core.Finding
	lookerLikeAuth := isAuthCookie(attrs.name)

	// __Host- and __Secure- prefixes are the cleanest defense.
	hasHostPrefix := strings.HasPrefix(attrs.name, "__Host-")
	hasSecurePrefix := strings.HasPrefix(attrs.name, "__Secure-")

	if lookerLikeAuth && !hasHostPrefix && !hasSecurePrefix {
		out = append(out, d.findingAuthNoPrefix(target, attrs.name))
	}

	if lookerLikeAuth && !attrs.secure {
		out = append(out, d.findingAuthNoSecure(target, attrs.name))
	}

	if attrs.domain != "" && strings.HasPrefix(attrs.domain, ".") {
		out = append(out, d.findingOverbroadDomain(target, attrs.name, attrs.domain))
	}

	// No Domain (host-scoped), no Path (default), no SameSite → "lazy
	// default" that ships the cookie with the minimum protection.
	if attrs.domain == "" && attrs.path == "" && attrs.sameSite == "" {
		out = append(out, d.findingNoScoping(target, attrs.name))
	}

	return out
}

type cookieAttrs struct {
	name     string
	domain   string
	path     string
	sameSite string
	secure   bool
	httpOnly bool
}

// parseSetCookie does a tolerant Set-Cookie parse. We intentionally don't
// use net/http.ParseSetCookie because it's strict — and we want to
// audit the EXACT attributes the server sent, malformed or not.
func parseSetCookie(raw string) cookieAttrs {
	var a cookieAttrs
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return a
	}
	nv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	a.name = strings.TrimSpace(nv[0])
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		lower := strings.ToLower(p)
		switch {
		case strings.HasPrefix(lower, "domain="):
			a.domain = strings.TrimSpace(p[len("domain="):])
		case strings.HasPrefix(lower, "path="):
			a.path = strings.TrimSpace(p[len("path="):])
		case strings.HasPrefix(lower, "samesite="):
			a.sameSite = strings.TrimSpace(p[len("samesite="):])
		case lower == "secure":
			a.secure = true
		case lower == "httponly":
			a.httpOnly = true
		}
	}
	return a
}

// isAuthCookie returns true when the cookie name suggests it carries
// authentication state. Match is case-insensitive against full-name
// substrings; explicit prefixes (__Host- / __Secure-) are not stripped
// because their presence is the very check we want.
func isAuthCookie(name string) bool {
	l := strings.ToLower(name)
	for _, p := range authNamePatterns {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func (d *Detector) findingAuthNoPrefix(target, name string) *core.Finding {
	f := core.NewFinding("cookietoss_"+string(IssueAuthNoPrefix), core.SeverityMedium)
	f.Tool = "cookietoss"
	f.URL = target
	f.Title = "Auth-shaped cookie lacks __Host-/__Secure- prefix"
	f.Confidence = core.ConfidenceMedium
	f.Description = "Cookie `" + name + "` appears to carry authentication state but does not use the __Host- or __Secure- name prefix. " +
		"__Host-Foo cookies are pinned to the exact origin AND require Secure + Path=/ — closing the cookie-tossing window where a compromised or attacker-controlled subdomain writes a cookie that the parent app trusts."
	f.Evidence = "Set-Cookie name: " + name
	f.Metadata["cookie_name"] = name
	f.Remediation = "Rename the cookie to use the `__Host-` prefix (most strict — pins to origin, requires Secure + Path=/) or the `__Secure-` prefix (requires Secure). Renaming requires session-rotation; pair the rename with the next planned login-cycle deploy."
	f.References = []string{
		"https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-cookie-name-prefixes",
		"https://textslashplain.com/2019/09/27/strict-cookie-prefixes/",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-SESS-02"},
		[]string{"A05:2021"},
		[]string{"CWE-1004"},
	)
	return f
}

func (d *Detector) findingAuthNoSecure(target, name string) *core.Finding {
	f := core.NewFinding("cookietoss_"+string(IssueAuthNoSecure), core.SeverityHigh)
	f.Tool = "cookietoss"
	f.URL = target
	f.Title = "Auth-shaped cookie lacks Secure attribute"
	f.Confidence = core.ConfidenceHigh
	f.Description = "Cookie `" + name + "` appears to carry authentication state but lacks the Secure attribute. " +
		"An on-path attacker can downgrade the connection to plaintext HTTP and capture the cookie even when the application is normally accessed over HTTPS."
	f.Evidence = "Set-Cookie name: " + name + "; Secure attribute absent"
	f.Metadata["cookie_name"] = name
	f.Remediation = "Add Secure to the Set-Cookie header. If the cookie name uses the __Secure- or __Host- prefix the browser will already reject it without Secure — making the attribute mandatory."
	f.References = []string{
		"https://owasp.org/www-community/controls/SecureCookieAttribute",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-SESS-02"},
		[]string{"A02:2021"},
		[]string{"CWE-614"},
	)
	return f
}

func (d *Detector) findingOverbroadDomain(target, name, domain string) *core.Finding {
	f := core.NewFinding("cookietoss_"+string(IssueOverbroadDomain), core.SeverityMedium)
	f.Tool = "cookietoss"
	f.URL = target
	f.Title = "Cookie scoped to parent domain — readable by every subdomain"
	f.Confidence = core.ConfidenceHigh
	f.Description = "Cookie `" + name + "` is sent with Domain=" + domain + ". The leading dot scopes the cookie to the entire registrable domain, so every subdomain (including legacy, marketing, and any subdomain takeover surface) can read and write it. " +
		"A takeover of a single subdomain — or any XSS on any subdomain — captures or overwrites this cookie."
	f.Evidence = "Domain=" + domain
	f.Metadata["cookie_name"] = name
	f.Metadata["domain"] = domain
	f.Remediation = "Drop the Domain attribute so the cookie is host-scoped (set only on the exact origin that issued it). If multiple subdomains genuinely need to share the cookie, enumerate them and use distinct sub-cookies instead of relying on a wildcard."
	f.References = []string{
		"https://blog.ankursundara.com/cookie-bugs/",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-SESS-02"},
		[]string{"A05:2021"},
		[]string{"CWE-565"},
	)
	return f
}

func (d *Detector) findingNoScoping(target, name string) *core.Finding {
	f := core.NewFinding("cookietoss_"+string(IssueNoScoping), core.SeverityLow)
	f.Tool = "cookietoss"
	f.URL = target
	f.Title = "Cookie ships with no Domain, Path, or SameSite scoping"
	f.Confidence = core.ConfidenceMedium
	f.Description = "Cookie `" + name + "` lacks Domain, Path, AND SameSite attributes. " +
		"The browser will apply lazy defaults: Domain=current host (good), Path=current path (often too narrow or too wide), SameSite=Lax (acceptable but not strict). " +
		"This is the configuration shape that ships when the developer copy-pasted a `Set-Cookie: name=value` example without tightening it."
	f.Evidence = "Set-Cookie has no Domain, Path, or SameSite"
	f.Metadata["cookie_name"] = name
	f.Remediation = "Add explicit Path=/ and SameSite=Strict (or Lax with deliberate intent) so the protection isn't relying on browser defaults that may shift over time."
	f = f.WithOWASPMapping(
		[]string{"WSTG-SESS-02"},
		[]string{"A05:2021"},
		[]string{"CWE-1004"},
	)
	return f
}
