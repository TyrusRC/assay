// Package cspaudit performs deep Content-Security-Policy audits beyond
// the binary header-present check the secheaders package already does.
// Specifically:
//
//   - Nonce reuse: a CSP nonce that's identical across two consecutive
//     responses defeats the entire point of nonces. Static nonces (the
//     server forgot to generate fresh ones) make script-src=nonce-X
//     equivalent to script-src=unsafe-inline.
//   - strict-dynamic with unsafe-baseline: `strict-dynamic` was meant
//     to be combined with a nonce/hash so older-browser fallbacks like
//     'unsafe-inline' are ignored. When the policy combines
//     strict-dynamic with explicit script-src=*  or http: schemes, the
//     strict-dynamic protection is bypassable.
//   - 'unsafe-eval' + nonce: a policy that has a nonce but also
//     'unsafe-eval' is broken — any nonced script can call eval().
//
// References:
//   - https://csp-evaluator.withgoogle.com/ (the gold-standard external auditor)
//   - https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists/
//   - Lukas Weichselbaum et al., CCS 2016.
package cspaudit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Issue identifies a specific CSP weakness class.
type Issue string

const (
	IssueNonceReuse       Issue = "nonce_reuse"
	IssueWildcardSource   Issue = "wildcard_source"
	IssueUnsafeInline     Issue = "unsafe_inline_with_nonce"
	IssueUnsafeEval       Issue = "unsafe_eval_with_nonce"
	IssueStrictDynamicBad Issue = "strict_dynamic_with_baseline"
	IssueDataURI          Issue = "data_uri_in_script_src"
	IssueHTTPSchemes      Issue = "http_scheme_in_script_src"
	IssueNoCSP            Issue = "no_csp_header"
	IssueReportOnly       Issue = "csp_in_report_only_mode"
)

// Detector performs CSP policy audits.
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
	// CheckNonceReuse triggers a second GET to compare nonce values.
	// Default true. When false the audit is single-shot (no nonce-reuse
	// check, no extra request budget).
	CheckNonceReuse bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:         8 * time.Second,
		CheckNonceReuse: true,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Policy     string // raw Content-Security-Policy value
	ReportOnly bool
	Findings   []*core.Finding
	Vulnerable bool
}

// Detect audits the target's CSP. Issues one GET (two when nonce-reuse
// is checked) and emits one finding per identified weakness.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	result := &DetectionResult{URL: target}

	first, err := d.fetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("cspaudit: first fetch: %w", err)
	}

	policy, reportOnly := extractCSP(first.Header)
	result.Policy = policy
	result.ReportOnly = reportOnly

	if policy == "" {
		// No CSP header at all is itself a finding — but only at Info
		// severity, since other secheaders coverage already flags it.
		result.Findings = append(result.Findings, d.noCSPFinding(target))
		return result, nil
	}

	if reportOnly {
		result.Findings = append(result.Findings, d.reportOnlyFinding(target, policy))
	}

	// Policy-shape audits.
	for _, finding := range d.shapeAudits(target, policy) {
		result.Findings = append(result.Findings, finding)
	}

	// Nonce-reuse check.
	if opts.CheckNonceReuse {
		firstNonce := extractNonce(policy)
		if firstNonce != "" {
			second, err := d.fetch(ctx, target, opts)
			if err == nil {
				secondPolicy, _ := extractCSP(second.Header)
				secondNonce := extractNonce(secondPolicy)
				if secondNonce != "" && secondNonce == firstNonce {
					result.Findings = append(result.Findings, d.nonceReuseFinding(target, firstNonce))
				}
			}
		}
	}

	for _, f := range result.Findings {
		if f.Severity != core.SeverityInfo {
			result.Vulnerable = true
			break
		}
	}
	return result, nil
}

// fetch issues a GET, drains and discards the body so the response is
// closed before the next call.
func (d *Detector) fetch(ctx context.Context, target string, opts DetectOptions) (*http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp, nil
}

// extractCSP returns the policy string and a bool indicating whether it
// was carried in the report-only header (which means the policy is NOT
// enforced).
func extractCSP(h http.Header) (string, bool) {
	if v := h.Get("Content-Security-Policy"); v != "" {
		return v, false
	}
	if v := h.Get("Content-Security-Policy-Report-Only"); v != "" {
		return v, true
	}
	return "", false
}

var nonceRE = regexp.MustCompile(`'nonce-([A-Za-z0-9+/=_-]+)'`)

// extractNonce returns the first nonce value found in the policy, or
// "" if there isn't one.
func extractNonce(policy string) string {
	m := nonceRE.FindStringSubmatch(policy)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// shapeAudits walks the policy and returns one finding per known weakness.
func (d *Detector) shapeAudits(target, policy string) []*core.Finding {
	var out []*core.Finding
	directives := parseDirectives(policy)

	// script-src is the highest-impact directive; audit it carefully.
	if scriptSrc, ok := directives["script-src"]; ok {
		out = append(out, d.auditScriptSrc(target, scriptSrc)...)
	} else if defaultSrc, ok := directives["default-src"]; ok {
		// Fallback: script-src inherits from default-src when absent.
		out = append(out, d.auditScriptSrc(target, defaultSrc)...)
	}

	// frame-ancestors / object-src absent → potential XFS / Flash gadget.
	// Skipped here; the xfs detector already covers frame-ancestors.

	return out
}

// auditScriptSrc returns findings for the specific weaknesses in the
// script-src (or fallback default-src) directive.
func (d *Detector) auditScriptSrc(target string, sources []string) []*core.Finding {
	var out []*core.Finding

	hasNonce := false
	hasStrictDynamic := false
	hasUnsafeInline := false
	hasUnsafeEval := false
	hasWildcard := false
	hasDataURI := false
	hasHTTPScheme := false

	for _, s := range sources {
		l := strings.ToLower(strings.Trim(s, "'\""))
		switch {
		case strings.HasPrefix(s, "'nonce-"), strings.HasPrefix(s, "\"nonce-"):
			hasNonce = true
		case l == "strict-dynamic":
			hasStrictDynamic = true
		case l == "unsafe-inline":
			hasUnsafeInline = true
		case l == "unsafe-eval":
			hasUnsafeEval = true
		case s == "*":
			hasWildcard = true
		case strings.HasPrefix(l, "data:"):
			hasDataURI = true
		case l == "http:" || l == "https:":
			hasHTTPScheme = true
		}
	}

	if hasWildcard {
		out = append(out, d.policyFinding(target, IssueWildcardSource, core.SeverityHigh,
			"script-src contains a bare '*' source — equivalent to allowing scripts from any origin.",
			"Replace '*' with a finite allowlist. Prefer 'nonce-…' or 'strict-dynamic' over origin lists."))
	}
	if hasNonce && hasUnsafeInline {
		out = append(out, d.policyFinding(target, IssueUnsafeInline, core.SeverityMedium,
			"script-src combines a nonce with 'unsafe-inline'. Modern browsers ignore 'unsafe-inline' when a nonce is present, but older browsers (pre-Edge-Chromium) honour 'unsafe-inline' — defeating the nonce protection.",
			"Drop 'unsafe-inline' from the policy. The nonce alone is sufficient on every modern browser and the legacy compatibility hatch is no longer worth the security cost."))
	}
	if hasNonce && hasUnsafeEval {
		out = append(out, d.policyFinding(target, IssueUnsafeEval, core.SeverityHigh,
			"script-src combines a nonce with 'unsafe-eval'. Any nonced script can then call eval()/new Function()/setTimeout(string,…), which is the most common XSS-gadget vector after a CSP bypass.",
			"Remove 'unsafe-eval'. If a library you depend on requires it (e.g. older Vue templates), upgrade or fork before keeping unsafe-eval enabled."))
	}
	if hasStrictDynamic && (hasWildcard || hasHTTPScheme) {
		out = append(out, d.policyFinding(target, IssueStrictDynamicBad, core.SeverityHigh,
			"script-src declares 'strict-dynamic' alongside a permissive baseline ('*' or http:/https: scheme). 'strict-dynamic' was designed to combine with a nonce/hash and IGNORE legacy schemes; this policy keeps the legacy hatch open.",
			"Combine 'strict-dynamic' with a 'nonce-…' only. Remove the wildcard and scheme entries — they exist for browsers that don't understand strict-dynamic, but the script-src/default-src setting blocks them anyway."))
	}
	if hasDataURI {
		out = append(out, d.policyFinding(target, IssueDataURI, core.SeverityHigh,
			"script-src allows the data: scheme. Any inline-script payload encoded as data:text/javascript,… executes without further restriction.",
			"Remove 'data:' from script-src. If a tooling pipeline needs inline scripts, use nonces or hashes instead."))
	}
	if hasHTTPScheme && !hasStrictDynamic {
		out = append(out, d.policyFinding(target, IssueHTTPSchemes, core.SeverityMedium,
			"script-src contains a bare 'http:' or 'https:' scheme. This allows any script from any host on the scheme — equivalent to '*' for that protocol.",
			"Replace 'http:'/'https:' with explicit origin allowlist entries or move to a nonce-based policy."))
	}
	return out
}

// parseDirectives splits the CSP policy string into a map of directive
// name → list of source expressions.
func parseDirectives(policy string) map[string][]string {
	out := make(map[string][]string)
	for _, dir := range strings.Split(policy, ";") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		parts := strings.Fields(dir)
		if len(parts) == 0 {
			continue
		}
		name := strings.ToLower(parts[0])
		out[name] = parts[1:]
	}
	return out
}

func (d *Detector) policyFinding(target string, issue Issue, sev core.Severity, desc, rem string) *core.Finding {
	f := core.NewFinding("csp_"+string(issue), sev)
	f.Tool = "cspaudit"
	f.URL = target
	f.Title = "CSP weakness: " + string(issue)
	f.Confidence = core.ConfidenceHigh
	f.Description = desc
	f.Evidence = desc
	f.Metadata["issue"] = string(issue)
	f.Remediation = rem
	f.References = []string{
		"https://csp-evaluator.withgoogle.com/",
		"https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists/",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-CLNT-09"},
		[]string{"A05:2021"},
		[]string{"CWE-1021"},
	)
	return f
}

func (d *Detector) nonceReuseFinding(target, nonce string) *core.Finding {
	f := core.NewFinding("csp_nonce_reuse", core.SeverityHigh)
	f.Tool = "cspaudit"
	f.URL = target
	f.Title = "CSP nonce reused across consecutive responses"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The Content-Security-Policy header returned the same nonce value (" + nonce +
		") across two consecutive requests. CSP nonces MUST be cryptographically random and unique per response — a reused nonce is " +
		"equivalent to 'unsafe-inline' (an attacker who once observes the nonce can re-use it in their injected script forever)."
	f.Evidence = "nonce-" + nonce + " seen in two consecutive responses"
	f.Metadata["reused_nonce"] = nonce
	f.Remediation = "Generate a fresh, cryptographically random nonce on every response. " +
		"The runtime cost is negligible (one CSPRNG call) and the security model depends on it. " +
		"Check that your framework's CSP middleware isn't caching the nonce per-process / per-worker / per-template-render."
	f.References = []string{
		"https://www.w3.org/TR/CSP3/#security-considerations",
		"https://csp-evaluator.withgoogle.com/",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-CLNT-09"},
		[]string{"A05:2021"},
		[]string{"CWE-330"},
	)
	return f
}

func (d *Detector) reportOnlyFinding(target, policy string) *core.Finding {
	f := core.NewFinding("csp_report_only", core.SeverityMedium)
	f.Tool = "cspaudit"
	f.URL = target
	f.Title = "CSP delivered in report-only mode — not enforced"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The Content-Security-Policy is delivered via the Content-Security-Policy-Report-Only header. " +
		"This causes the browser to LOG violations to the report-uri but NOT block them. " +
		"Useful as a deployment-soak phase, but production traffic on report-only is not protected by the policy."
	f.Evidence = "policy: " + truncatePolicy(policy, 200)
	f.Remediation = "Once report-only collection has confirmed no false positives, migrate to the enforcing Content-Security-Policy header. " +
		"Keep the report-uri to continue catching new violations."
	f.References = []string{"https://www.w3.org/TR/CSP3/#cspro-header"}
	f = f.WithOWASPMapping(
		[]string{"WSTG-CLNT-09"},
		[]string{"A05:2021"},
		[]string{"CWE-1021"},
	)
	return f
}

func (d *Detector) noCSPFinding(target string) *core.Finding {
	f := core.NewFinding("csp_absent", core.SeverityInfo)
	f.Tool = "cspaudit"
	f.URL = target
	f.Title = "No Content-Security-Policy header"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The response carries no Content-Security-Policy header — neither enforcing nor report-only. " +
		"CSP is one of the most effective XSS mitigations; its absence is informational here because the secheaders detector already covers the broader missing-headers picture."
	f.Remediation = "Ship a CSP header. Start in report-only mode to collect violations from real traffic, then migrate to the enforcing header."
	f = f.WithOWASPMapping(
		[]string{"WSTG-CLNT-09"},
		[]string{"A05:2021"},
		[]string{"CWE-1021"},
	)
	return f
}

func truncatePolicy(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
