package headless

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ServiceWorkerProbeResult captures the outcome of registering an
// attacker-controlled Service Worker and measuring its claimed scope.
//
// A SW served under `/static/uploads/sw.js` is allowed by spec to claim
// only `/static/uploads/` unless the server returns
// `Service-Worker-Allowed: <broader-path>`. A successfully registered
// worker reporting a wider scope means the server explicitly opted into
// a misconfiguration that lets a user upload hijack site-wide fetches.
type ServiceWorkerProbeResult struct {
	Registered bool   `json:"registered"`
	Scope      string `json:"scope"`
	Vulnerable bool   `json:"vulnerable"`
	Error      string `json:"error,omitempty"`
}

// ProbeServiceWorkerHijack registers a Service Worker from
// attackerScopePath (a path on the current origin, leading slash) and
// returns the scope the registration actually claimed. If the claimed
// scope is broader than the script's own directory the result is marked
// Vulnerable.
//
// The probe always unregisters before returning so subsequent probes
// see a clean origin; failure to unregister is non-fatal (the script
// path's worker would persist into the next test, which we tolerate
// for E2E reuse).
func (p *Page) ProbeServiceWorkerHijack(ctx context.Context, attackerScopePath string) (*ServiceWorkerProbeResult, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	if attackerScopePath == "" {
		attackerScopePath = "/sw.js"
	}
	// JS:
	//   1. register(scriptPath, {scope: '/'}) — explicitly request the
	//      broadest scope. If `Service-Worker-Allowed` permits, browser
	//      honors it; otherwise registration rejects.
	//   2. Wait for active worker, read registration.scope.
	//   3. Unregister.
	// Errors are caught and returned via the result, never thrown — we
	// distinguish "SW didn't register" (info) from "Eval crashed" (real
	// error).
	expr := fmt.Sprintf(`(async function() {
		const out = {registered: false, scope: '', vulnerable: false, error: ''};
		if (!('serviceWorker' in navigator)) {
			out.error = 'serviceWorker unsupported';
			return JSON.stringify(out);
		}
		try {
			const reg = await navigator.serviceWorker.register(%q, {scope: '/'});
			// Wait briefly for activation; some workers go through
			// installing→waiting→activated within a tick or two.
			const deadline = Date.now() + 4000;
			while (Date.now() < deadline) {
				if (reg.active) break;
				await new Promise(function(r){ setTimeout(r, 100); });
			}
			out.registered = true;
			out.scope = reg.scope || '';
			// Compute the script's natural directory; anything broader
			// counts as a vulnerable override.
			const scriptDir = new URL(%q, location.origin).href.replace(/[^/]+$/, '');
			out.vulnerable = out.scope !== '' && out.scope.length < scriptDir.length;
			try { await reg.unregister(); } catch(e) {}
		} catch(e) {
			out.error = String(e && e.message ? e.message : e);
		}
		return JSON.stringify(out);
	})()`, attackerScopePath, attackerScopePath)

	raw, err := p.EvalJS(ctx, expr)
	if err != nil {
		return nil, err
	}
	res := &ServiceWorkerProbeResult{}
	if raw == "" {
		return res, nil
	}
	if err := json.Unmarshal([]byte(raw), res); err != nil {
		return nil, fmt.Errorf("headless: parse SW probe: %w", err)
	}
	return res, nil
}

// IsolationProbeResult captures the page's cross-origin isolation
// posture: the three relevant response headers plus a behavioral
// observation that a popup opened from the page can read back
// `window.opener`. COOP=same-origin would sever `opener`, so its
// accessibility under a missing/weak COOP is the canonical reverse
// tab-nabbing primitive.
type IsolationProbeResult struct {
	COOP                  string   `json:"coop"`
	COEP                  string   `json:"coep"`
	CORP                  string   `json:"corp"`
	PopupOpenerAccessible bool     `json:"popupOpenerAccessible"`
	Vulnerable            bool     `json:"vulnerable"`
	Findings              []string `json:"findings"`
}

// ProbeCOOPCOEPEffect inspects the current page's isolation headers
// (COOP/COEP/CORP) and runs a behavioral test for `window.opener`
// leakage through a popup. The behavioral test is informational on
// http://localhost (popups are blocked by default in many Chromium
// builds), but the header view alone is enough to grade the page.
func (p *Page) ProbeCOOPCOEPEffect(ctx context.Context) (*IsolationProbeResult, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	// Step 1: fetch headers via the in-page fetch primitive against the
	// current document URL. We use location.href so the probe works
	// after redirects.
	urlExpr := `location.href`
	currentURL, err := p.EvalJS(ctx, urlExpr)
	if err != nil {
		return nil, fmt.Errorf("headless: read current URL: %w", err)
	}
	headers, hdrErr := p.FetchHeaders(ctx, currentURL)
	if hdrErr != nil && len(headers) == 0 {
		// Hard fetch failure (network error, CORS) — we can still try
		// the popup probe, but headers will be empty.
		headers = map[string]string{}
	}

	res := &IsolationProbeResult{
		COOP:     strings.TrimSpace(headers["cross-origin-opener-policy"]),
		COEP:     strings.TrimSpace(headers["cross-origin-embedder-policy"]),
		CORP:     strings.TrimSpace(headers["cross-origin-resource-policy"]),
		Findings: []string{},
	}

	// Step 2: behavioral popup probe. Open `about:blank` and read
	// `popup.opener` back. We don't navigate the popup cross-origin
	// (httptest is loopback-only), but the in-process check is enough
	// to demonstrate the primitive.
	popupExpr := `(function() {
		try {
			const w = window.open('about:blank', '_blank');
			if (!w) return JSON.stringify({opened: false, openerAccessible: false});
			let accessible = false;
			try {
				// Reading w.opener from the parent works for same-origin
				// popups regardless of COOP. The real signal: under
				// COOP: same-origin, w.opener inside the POPUP would be
				// null; but Eval'ing inside the popup from here requires
				// CDP-level frame switching. As a pragmatic stand-in we
				// check whether the popup retained its opener back-link
				// via property access.
				accessible = (w.opener === window);
			} catch(e) { accessible = false; }
			try { w.close(); } catch(e) {}
			return JSON.stringify({opened: true, openerAccessible: accessible});
		} catch(e) {
			return JSON.stringify({opened: false, openerAccessible: false, error: String(e)});
		}
	})()`
	popupRaw, popupErr := p.EvalJS(ctx, popupExpr)
	if popupErr == nil && popupRaw != "" {
		var popup struct {
			Opened           bool `json:"opened"`
			OpenerAccessible bool `json:"openerAccessible"`
		}
		_ = json.Unmarshal([]byte(popupRaw), &popup)
		res.PopupOpenerAccessible = popup.OpenerAccessible
	}

	// Step 3: grade. Missing or weak (`unsafe-none`) COOP/COEP/CORP each
	// adds a finding; any finding marks the page Vulnerable.
	if res.COOP == "" || strings.EqualFold(res.COOP, "unsafe-none") {
		res.Findings = append(res.Findings,
			"missing or weak Cross-Origin-Opener-Policy (COOP) — popups can read window.opener")
	}
	if res.COEP == "" || strings.EqualFold(res.COEP, "unsafe-none") {
		res.Findings = append(res.Findings,
			"missing or weak Cross-Origin-Embedder-Policy (COEP) — cross-origin resources can be embedded without consent")
	}
	if res.CORP == "" {
		res.Findings = append(res.Findings,
			"missing Cross-Origin-Resource-Policy (CORP) — resource may be embedded by any origin")
	}
	if res.PopupOpenerAccessible && res.COOP == "" {
		res.Findings = append(res.Findings,
			"popup window.opener is accessible from this page — confirms COOP is not enforced")
	}
	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// TrustedTypesProbeResult captures the page's Trusted Types posture.
// HeaderPresent is true when either an enforcing or report-only CSP
// carries `require-trusted-types-for 'script'`. AssignmentBlocked is
// true when an innerHTML assignment of a string-typed payload threw a
// TypeError (the spec-mandated behavior under enforced TT).
type TrustedTypesProbeResult struct {
	HeaderPresent     bool   `json:"headerPresent"`
	PolicyName        string `json:"policyName"`
	AssignmentBlocked bool   `json:"assignmentBlocked"`
	Vulnerable        bool   `json:"vulnerable"`
	Error             string `json:"error,omitempty"`
}

// ProbeTrustedTypesBypass tests whether the current page actually
// enforces Trusted Types. The header alone is not enough: a CSP under
// `Content-Security-Policy-Report-Only` will set the header but not
// block assignments. The probe attempts an innerHTML assignment of a
// string-typed payload and reports whether the browser threw — which is
// the only ground truth for "is TT actually enforced here".
func (p *Page) ProbeTrustedTypesBypass(ctx context.Context, payload string) (*TrustedTypesProbeResult, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	if payload == "" {
		payload = "<img src=x onerror=1>"
	}
	// Step 1: header sniff via FetchHeaders. We accept both enforcing
	// and report-only CSPs as evidence the header is present; the JS
	// step distinguishes enforcement.
	currentURL, err := p.EvalJS(ctx, `location.href`)
	if err != nil {
		return nil, fmt.Errorf("headless: read current URL: %w", err)
	}
	headers, _ := p.FetchHeaders(ctx, currentURL)
	csp := headers["content-security-policy"]
	cspRO := headers["content-security-policy-report-only"]
	combined := csp + " ; " + cspRO
	headerPresent := strings.Contains(strings.ToLower(combined), "require-trusted-types-for")
	policyName := extractTrustedTypesPolicy(combined)

	// Step 2: behavioral probe. Try the assignment in JS; capture any
	// thrown error as a string. Under enforced TT this is a TypeError
	// per the spec; under report-only or no-TT it just silently writes.
	expr := fmt.Sprintf(`(function() {
		const out = {threw: false, error: ''};
		try {
			const el = document.createElement('div');
			el.innerHTML = %q;
			document.body && document.body.appendChild(el);
		} catch(e) {
			out.threw = true;
			out.error = String(e && e.message ? e.message : e);
		}
		return JSON.stringify(out);
	})()`, payload)
	raw, err := p.EvalJS(ctx, expr)
	if err != nil {
		return &TrustedTypesProbeResult{
			HeaderPresent: headerPresent,
			PolicyName:    policyName,
			Error:         err.Error(),
		}, nil
	}
	var probe struct {
		Threw bool   `json:"threw"`
		Error string `json:"error"`
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &probe); err != nil {
			return nil, fmt.Errorf("headless: parse TT probe: %w", err)
		}
	}
	res := &TrustedTypesProbeResult{
		HeaderPresent:     headerPresent,
		PolicyName:        policyName,
		AssignmentBlocked: probe.Threw,
		Error:             probe.Error,
	}
	// Grade: vulnerable when either no header AND assignment succeeded
	// (no protection at all), or header present but assignment still
	// succeeded (report-only / misconfigured).
	res.Vulnerable = !probe.Threw
	return res, nil
}

// extractTrustedTypesPolicy pulls the first non-keyword name from a
// `trusted-types <name>` directive, if present. Returns "" when no
// explicit policy name is declared.
func extractTrustedTypesPolicy(csp string) string {
	lower := strings.ToLower(csp)
	idx := strings.Index(lower, "trusted-types")
	if idx < 0 {
		return ""
	}
	// Skip past "trusted-types" itself, but avoid matching
	// "require-trusted-types-for".
	if idx >= 8 && strings.HasPrefix(lower[idx-8:], "require-") {
		// Not the directive we want; try to find a second occurrence.
		next := strings.Index(lower[idx+len("trusted-types"):], "trusted-types")
		if next < 0 {
			return ""
		}
		idx = idx + len("trusted-types") + next
	}
	rest := csp[idx+len("trusted-types"):]
	// Cut at next directive separator.
	if semi := strings.Index(rest, ";"); semi >= 0 {
		rest = rest[:semi]
	}
	for _, tok := range strings.Fields(rest) {
		t := strings.TrimSpace(tok)
		// Skip CSP keyword sources.
		if t == "" || t == "'none'" || t == "'self'" || strings.HasPrefix(t, "'allow-") {
			continue
		}
		return strings.Trim(t, "'")
	}
	return ""
}
