package xsleaks

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector audits responses for combinations of isolation-policy gaps
// that expose cross-site leak primitives.
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector. A nil client turns Detect into a no-op
// rather than a hard error, matching the convention used by other
// optional detectors.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "xsleaks" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Audits Cross-Origin-Opener/Embedder/Resource-Policy, X-Frame-Options, CSP frame-ancestors, and SameSite cookies for combinations that expose cross-site leak primitives (frame counting, popup-based navigation timing, resource-isolation leaks)."
}

// DetectOptions configures the audit.
type DetectOptions struct {
	Timeout time.Duration
}

// DefaultOptions returns recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second}
}

// DetectionResult carries findings and the raw primitive list.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Primitives []string
}

// Detect fetches the target once and reports xsleak primitives that
// correlate into an exploitable combination.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{Findings: make([]*core.Finding, 0)}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}

	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	resp, err := d.client.Get(reqCtx, target)
	if err != nil {
		return res, fmt.Errorf("xsleaks: fetch: %w", err)
	}

	primitives := collectPrimitives(target, resp.Headers)
	res.Primitives = primitives

	severity := gradeSeverity(primitives)
	if severity == core.SeverityInfo || severity == core.SeverityLow {
		// Single-signal findings are noise — secheaders/ already covers
		// isolated missing headers. Only emit when correlation makes
		// the gap meaningful.
		if severity == core.SeverityLow && !hasCorrelation(primitives) {
			return res, nil
		}
		if severity == core.SeverityInfo {
			return res, nil
		}
	}

	finding := core.NewFinding("Cross-Site Leak Primitive Exposure", severity)
	finding.Title = "Response exposes cross-site leak primitives"
	finding.URL = target
	finding.Tool = "xsleaks-detector"
	finding.Description = "The response exposes cross-site leak (xsleak) primitives. " +
		"An attacker page on a different origin can correlate visible side effects — frame counts, navigation timing, postMessage signals, popup window.length — against the user's authenticated state on this origin. " +
		"The combination of primitives observed: " + strings.Join(primitives, ", ") + "."
	finding.Evidence = "primitives: " + strings.Join(primitives, ", ")
	finding.Remediation = "Set Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp on document responses; set Cross-Origin-Resource-Policy: same-origin (or same-site) on data endpoints; restrict framing via X-Frame-Options: DENY or CSP frame-ancestors 'none'; use SameSite=Strict on session cookies for auth-sensitive paths. Reference: https://xsleaks.dev"
	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-13"},
		[]string{"A01:2025", "A04:2025"},
		[]string{"CWE-200", "CWE-1021"},
	)

	res.Findings = append(res.Findings, finding)
	res.Vulnerable = true
	return res, nil
}

// collectPrimitives inspects response headers and the target URL and
// returns the list of xsleak primitives that apply. Order is stable so
// finding evidence is deterministic.
func collectPrimitives(target string, headers map[string]string) []string {
	prims := make([]string, 0, 6)

	hdr := lowerHeaders(headers)
	if isFramable(hdr) {
		prims = append(prims, "framable")
	}
	if !hasCOOP(hdr) {
		prims = append(prims, "no_coop")
	}
	if !hasCOEP(hdr) {
		prims = append(prims, "no_coep")
	}
	if !hasCORP(hdr) {
		prims = append(prims, "no_corp")
	}

	crossSite, _ := analyzeSetCookie(hdr["set-cookie"])
	if crossSite {
		prims = append(prims, "samesite_cross_site")
	}

	if u, err := url.Parse(target); err == nil && isAuthSensitivePath(u.Path) {
		prims = append(prims, "auth_sensitive_path")
	}

	if isJSONContentType(hdr["content-type"]) {
		prims = append(prims, "json_response")
	}

	return prims
}

func lowerHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = v
	}
	return out
}

// isFramable returns true when no header restricts cross-origin framing.
// X-Frame-Options DENY or SAMEORIGIN and CSP frame-ancestors with any
// non-wildcard value both disable framing primitives.
func isFramable(hdr map[string]string) bool {
	xfo := strings.ToLower(strings.TrimSpace(hdr["x-frame-options"]))
	if xfo == "deny" || xfo == "sameorigin" {
		return false
	}
	csp := strings.ToLower(hdr["content-security-policy"])
	if csp != "" {
		if fa := extractCSPDirective(csp, "frame-ancestors"); fa != "" {
			// frame-ancestors 'none' or any explicit allowlist (no '*'
			// without scheme) disables cross-origin framing.
			if !strings.Contains(fa, "*") && !strings.Contains(fa, "http:") && !strings.Contains(fa, "https:") {
				return false
			}
			if strings.Contains(fa, "'none'") {
				return false
			}
		}
	}
	return true
}

// extractCSPDirective returns the value of a single CSP directive (the
// substring between the directive name and the next ';' or end).
func extractCSPDirective(csp, name string) string {
	i := strings.Index(csp, name)
	if i < 0 {
		return ""
	}
	rest := csp[i+len(name):]
	if j := strings.Index(rest, ";"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func hasCOOP(hdr map[string]string) bool {
	v := strings.ToLower(strings.TrimSpace(hdr["cross-origin-opener-policy"]))
	return v != "" && v != "unsafe-none"
}

func hasCOEP(hdr map[string]string) bool {
	v := strings.ToLower(strings.TrimSpace(hdr["cross-origin-embedder-policy"]))
	return v == "require-corp" || v == "credentialless"
}

func hasCORP(hdr map[string]string) bool {
	v := strings.ToLower(strings.TrimSpace(hdr["cross-origin-resource-policy"]))
	return v == "same-origin" || v == "same-site" || v == "cross-origin"
}

// analyzeSetCookie returns (crossSiteSends, hasSession). A cookie is
// considered cross-site-sending if its SameSite attribute is Lax, None,
// or absent. Session cookies are detected by common name patterns —
// good enough to flag the high-severity correlation without parsing the
// app's cookie schema.
func analyzeSetCookie(raw string) (crossSiteSends, hasSession bool) {
	if raw == "" {
		return false, false
	}
	// Multiple cookies may be joined by comma in Go's single-value
	// header map. Split on comma followed by a likely cookie name char.
	cookies := splitCookies(raw)
	for _, c := range cookies {
		name, attrs := parseCookie(c)
		ss := attrs["samesite"]
		sends := false
		switch strings.ToLower(ss) {
		case "strict":
			sends = false
		case "lax", "none", "":
			sends = true
		}
		if isSessionName(name) {
			hasSession = true
			if sends {
				crossSiteSends = true
			}
		}
	}
	return crossSiteSends, hasSession
}

// splitCookies separates a possibly comma-joined Set-Cookie header
// value into individual cookies without confusing the comma used inside
// the Expires attribute (which is followed by a weekday name, not a
// cookie-name=value pair).
func splitCookies(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	current := ""
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if strings.Contains(trimmed, "=") && !looksLikeExpiresWeekday(trimmed) {
			if current != "" {
				out = append(out, current)
			}
			current = trimmed
		} else {
			if current != "" {
				current += "," + p
			}
		}
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

func looksLikeExpiresWeekday(s string) bool {
	// after a comma inside Expires=Wed, 09 Jun 2021 ...
	lower := strings.ToLower(s)
	for _, day := range []string{"mon ", "tue ", "wed ", "thu ", "fri ", "sat ", "sun "} {
		if strings.HasPrefix(lower, day) || strings.HasPrefix(lower, day[:3]+" ") {
			return true
		}
	}
	return false
}

func parseCookie(c string) (name string, attrs map[string]string) {
	attrs = make(map[string]string)
	segs := strings.Split(c, ";")
	if len(segs) == 0 {
		return "", attrs
	}
	first := strings.SplitN(strings.TrimSpace(segs[0]), "=", 2)
	if len(first) > 0 {
		name = strings.TrimSpace(first[0])
	}
	for _, s := range segs[1:] {
		kv := strings.SplitN(strings.TrimSpace(s), "=", 2)
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := ""
		if len(kv) == 2 {
			v = strings.TrimSpace(kv[1])
		}
		attrs[k] = v
	}
	return name, attrs
}

// isSessionName matches common session/auth cookie names. Order of
// patterns: more specific first.
func isSessionName(name string) bool {
	lower := strings.ToLower(name)
	patterns := []string{
		"session", "sess", "sid", "auth", "token", "jwt",
		"phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
		"_csrf", "xsrf",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// isAuthSensitivePath returns true when the path matches a common
// authenticated-resource pattern. Conservative — false negatives are
// preferable to false positives because auth_sensitive_path is what
// pushes severity to High.
func isAuthSensitivePath(p string) bool {
	if p == "" || p == "/" {
		return false
	}
	lower := strings.ToLower(p)
	patterns := []string{
		"/account", "/admin", "/dashboard", "/profile", "/settings",
		"/me", "/api/user", "/api/me", "/api/account", "/api/profile",
		"/user/", "/users/", "/orders", "/billing", "/checkout",
		"/inbox", "/messages",
	}
	for _, prefix := range patterns {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") || strings.HasPrefix(lower, prefix) {
			// allow exact match and prefix match
			if lower == prefix {
				return true
			}
			// avoid /accounting matching /account by requiring the
			// next char to be a path/query boundary.
			if len(lower) > len(prefix) {
				next := lower[len(prefix)]
				if next == '/' || next == '?' || next == '#' {
					return true
				}
			}
		}
	}
	return false
}

func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "+json")
}

// gradeSeverity ranks the combination of primitives. The grading
// reflects pentest reality: a framable auth endpoint with cross-site
// cookies is high (multiple primitives + active leak surface); an
// isolated missing header is low signal and only fires if other
// primitives are present (see hasCorrelation).
func gradeSeverity(primitives []string) core.Severity {
	if len(primitives) == 0 {
		return core.SeverityInfo
	}
	set := make(map[string]bool, len(primitives))
	for _, p := range primitives {
		set[p] = true
	}

	framable := set["framable"]
	noCOOP := set["no_coop"]
	noCORP := set["no_corp"]
	crossSite := set["samesite_cross_site"]
	authPath := set["auth_sensitive_path"]
	jsonResp := set["json_response"]

	// High: framable auth endpoint, OR framable + COOP-missing + auth,
	// OR cross-site cookies on auth endpoint with any leak primitive.
	if authPath && framable && (noCOOP || crossSite) {
		return core.SeverityHigh
	}
	if authPath && noCOOP && crossSite {
		return core.SeverityHigh
	}

	// Medium: public framable + COOP-missing (frame-count primitive
	// available without auth context), or JSON endpoint loadable
	// cross-origin with cross-site cookies (size/timing leak).
	if framable && noCOOP {
		return core.SeverityMedium
	}
	if jsonResp && noCORP && crossSite {
		return core.SeverityMedium
	}

	return core.SeverityLow
}

// hasCorrelation returns true when the primitive set contains at least
// two attack-surface primitives. auth_sensitive_path and json_response
// are modifiers that amplify but don't count alone — without an
// actual leak primitive there's nothing to amplify, and emitting on
// those alone would duplicate secheaders/ noise.
func hasCorrelation(primitives []string) bool {
	attackSurface := map[string]bool{
		"framable":            true,
		"no_coop":             true,
		"no_coep":             true,
		"no_corp":             true,
		"samesite_cross_site": true,
	}
	count := 0
	for _, p := range primitives {
		if attackSurface[p] {
			count++
		}
	}
	return count >= 2
}
