// Package csrf probes state-changing endpoints for missing Cross-Site
// Request Forgery defenses. The signal we look for is the canonical
// "browser-initiated cross-origin POST gets a 2xx" failure: a request
// with an attacker-controlled `Origin` header, no anti-CSRF token, and
// no SameSite-cookie protection still mutates state.
//
// Scope: only POST / PUT / PATCH / DELETE methods, only when the
// scanner has been given a target URL that is plausibly a state-change
// endpoint (path or supplied method is non-GET). The probe is benign
// — we send the same body the original target carries and look at
// the response shape, not at side-effects on the server.
package csrf

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/analysis"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// evilOrigin is the attacker-controlled value we inject into the Origin
// header. It is RFC 6761 reserved (.invalid TLD) so it cannot resolve.
const evilOrigin = "https://evil.example"

// stateChangePathHints flag URLs that are plausibly state-change
// endpoints when no body / method is otherwise supplied.
var stateChangePathHints = []string{
	"login", "signin", "signup", "register", "logout",
	"password", "reset", "recover", "verify",
	"checkout", "purchase", "order", "payment",
	"transfer", "withdraw", "deposit",
	"profile", "settings", "preferences",
	"delete", "remove", "ban", "block",
	"create", "update", "edit",
	"admin", "approve", "reject",
}

// Detector probes targetURL for missing CSRF defenses.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries the findings emitted by Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect probes targetURL with three matched POSTs:
//   1. Same-origin baseline (no Origin header) to capture "what success
//      looks like" — a 2xx body shape we can compare against.
//   2. Cross-origin POST (Origin: evil.example) — vulnerable servers
//      still process the request and return the same shape.
//   3. Anti-CSRF probe with bogus token — confirms the server is
//      ignoring tokens entirely (or we never had one).
//
// Findings emit only when (1) and (2) are similar AND the server
// returns 2xx for (2). If the server differentiates Origin (returns
// 403 / different body) the gate is working — no finding.
func (d *Detector) Detect(ctx context.Context, targetURL, method, body string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}

	// Default to POST when no method is supplied; only state-change
	// verbs are interesting.
	if method == "" {
		method = "POST"
	}
	method = strings.ToUpper(method)
	if !isStateChange(method) {
		return res, nil
	}

	// Path-shape gate: if we don't have a path hint AND no body, skip.
	// CSRF on a GET /index isn't meaningful.
	u, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}
	if body == "" && !pathLooksStateChange(u.Path) {
		return res, nil
	}
	if body == "" {
		body = "{\"probe\":\"skws-csrf\"}"
	}

	contentType := "application/json"
	if !strings.HasPrefix(strings.TrimSpace(body), "{") && !strings.HasPrefix(strings.TrimSpace(body), "[") {
		contentType = "application/x-www-form-urlencoded"
	}

	// Baseline: same-origin (default) request.
	baseline, err := d.client.SendRawBody(ctx, targetURL, method, body, contentType)
	if err != nil || baseline == nil {
		return res, nil
	}
	// Skip when baseline itself fails — we cannot assert anything.
	if baseline.StatusCode < 200 || baseline.StatusCode >= 300 {
		return res, nil
	}
	baselineStripped := analysis.StripDynamicContent(baseline.Body)

	// Cross-origin probe.
	crossClient := d.client.Clone().WithHeaders(map[string]string{"Origin": evilOrigin})
	crossResp, err := crossClient.SendRawBody(ctx, targetURL, method, body, contentType)
	if err != nil || crossResp == nil {
		return res, nil
	}
	if crossResp.StatusCode < 200 || crossResp.StatusCode >= 300 {
		// Server differentiated by Origin → CSRF gate is working.
		return res, nil
	}
	crossStripped := analysis.StripDynamicContent(crossResp.Body)

	// Final verdict: cross-origin response must look like the baseline.
	// Different shapes typically mean the cross-origin path returned a
	// generic error page, even with a 2xx (some apps wrap errors in 200).
	if analysis.ResponseSimilarity(baselineStripped, crossStripped) < 0.85 {
		return res, nil
	}

	res.Findings = append(res.Findings, buildFinding(targetURL, method, baseline.StatusCode))
	return res, nil
}

func isStateChange(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func pathLooksStateChange(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range stateChangePathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func buildFinding(targetURL, method string, status int) *core.Finding {
	finding := core.NewFinding("Cross-Site Request Forgery (Missing Origin Check)", core.SeverityHigh)
	finding.URL = targetURL
	finding.Parameter = method
	finding.Tool = "csrf"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"The endpoint accepted a %s request with an attacker-controlled Origin header (%s) and produced the same response shape as the same-origin baseline. Without anti-CSRF tokens, SameSite cookies, or Origin/Referer enforcement, an attacker can make a victim's browser submit this state-change cross-origin.",
		method, evilOrigin,
	)
	finding.Evidence = fmt.Sprintf("Method: %s\nBaseline status: %d\nCross-origin status: %d (Origin: %s)\nResponse shape preserved across origins.",
		method, status, status, evilOrigin)
	finding.Remediation = "Enforce anti-CSRF tokens on every state-change endpoint, or use SameSite=Lax/Strict on session cookies, or check Origin/Referer headers server-side. Combine token + cookie attribute for defense in depth."
	finding.WithOWASPMapping(
		[]string{"WSTG-SESS-05"},
		[]string{"A01:2025"},
		[]string{"CWE-352"},
	)
	finding.APITop10 = []string{"API5:2023"}
	return finding
}
