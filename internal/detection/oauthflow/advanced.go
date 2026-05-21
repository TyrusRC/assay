package oauthflow

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// extendedRedirectURIVariants returns the union of the v1 variants
// (defined in detector.go) and the parser-quirk bypasses observed in
// real OAuth bug-bounty reports that the v1 list does not cover.
//
// New patterns:
//   - userinfo split: https://attacker.com@registered.com/cb   —
//     `attacker.com` is the userinfo component per RFC 3986, so a naïve
//     check on the substring `registered.com` passes while the browser
//     actually navigates to `registered.com` *after* sending the
//     authority to `attacker.com`. Inverted form sends the code to
//     `attacker.com` directly.
//   - percent-encoded slash userinfo: https://registered.com%2f@attacker.com/cb
//   - backslash quirk: https://registered.com\@attacker.com/cb  —
//     Go/Java/Node parse differently than browsers on backslash.
//   - fragment confusion: https://registered.com#@attacker.com/cb —
//     anchors the path lookup at registered.com but reconstruction in
//     some libraries appends the fragment to the path.
//   - host case toggle: https://REGISTERED.COM/cb  —  servers that
//     compare bytes pass, browsers compare case-insensitively.
func extendedRedirectURIVariants(registered string) []string {
	v1 := redirectURIVariants(registered)
	u, err := url.Parse(registered)
	if err != nil || u.Host == "" {
		return v1
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}

	extra := []string{
		// userinfo split — code lands on the registered host but the
		// validator that string-matched `registered.com` thought the URI
		// pointed there too.
		fmt.Sprintf("%s://attacker.com@%s%s", scheme, host, path),
		// Inverted userinfo — code lands on attacker.com because the
		// authority is everything between `://` and the first `@`, and
		// after `@` is the *host*, not before.
		fmt.Sprintf("%s://%s@attacker.com%s", scheme, host, path),
		// Percent-encoded slash in the userinfo — defeats validators
		// that split on '/' before parsing the URI.
		fmt.Sprintf("%s://%s%%2f@attacker.com%s", scheme, host, path),
		// Backslash quirk — RFC says `\` is not a delimiter but most
		// browsers treat it as `/`. Parsers differ.
		fmt.Sprintf("%s://%s\\@attacker.com%s", scheme, host, path),
		// Fragment confusion — the fragment is everything after the
		// first `#`, but some validators check the substring of the
		// full URI before parsing.
		fmt.Sprintf("%s://%s%s#@attacker.com/", scheme, host, path),
		// Host case toggle — byte-equality fails, browser navigates fine.
		fmt.Sprintf("%s://%s%s", scheme, strings.ToUpper(host), path),
	}
	return append(v1, extra...)
}

// DetectResponseModeConfusion checks whether the IdP honors a
// response_mode override the client never registered. Confirming that
// `response_mode=query` is accepted when the client expects fragment
// (or vice versa) exposes the implicit-flow code-leak surface:
// query-string responses land in access logs, browser history, and
// Referer headers, while fragments do not. RFC 6749 Bearer Token
// requirements (RFC 6750 §5.3) explicitly warn against passing tokens
// over query parameters.
//
// Severity is medium — the misconfiguration is a precondition rather
// than a direct primitive — unless paired with another finding that
// promotes the leak surface to exploitable.
func (d *Detector) DetectResponseModeConfusion(ctx context.Context, authzURL string, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "response-mode-confusion",
	}

	base, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("parse authzURL: %w", err)
	}

	// Baseline: no response_mode override. Capture the delivery shape
	// the IdP normally uses (query vs fragment) so we can detect a
	// genuine override rather than a server that ignored our hint.
	baselineURL := d.buildAuthzURL(base, opts, map[string]string{
		"state": "assay-mode-baseline",
	}, true)
	baselineResp, err := d.probe(ctx, baselineURL)
	if err != nil || baselineResp == nil || !d.acceptsAuthorize(baselineResp) {
		return result, nil
	}
	baselineDelivery := responseDelivery(baselineResp)

	for _, mode := range []string{"query", "form_post", "fragment"} {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		// Skip the mode that matches the baseline delivery — overriding
		// to what the server already uses tells us nothing.
		if mode == baselineDelivery {
			continue
		}

		probeURL := d.buildAuthzURL(base, opts, map[string]string{
			"response_mode": mode,
			"state":         "assay-mode-" + mode,
		}, true)

		resp, err := d.probe(ctx, probeURL)
		if err != nil || resp == nil {
			continue
		}
		if !d.acceptsAuthorize(resp) {
			continue
		}
		probeDelivery := responseDelivery(resp)
		// The override was honored only when the delivery shape changed
		// in the direction we asked for. A server that ignored our hint
		// returns the same baseline shape — no finding.
		if probeDelivery != mode {
			continue
		}

		result.Findings = append(result.Findings, d.findingResponseModeConfusion(probeURL, mode, resp))
		result.Vulnerable = true
		return result, nil
	}

	return result, nil
}

// responseDelivery inspects the Location header of an authorize response
// and reports whether the code/state arrived via query string, URL
// fragment, or form_post body. Returns "" when no delivery indicator is
// found.
func responseDelivery(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	loc := resp.Headers["Location"]
	if loc == "" {
		loc = resp.Headers["location"]
	}
	if loc == "" {
		if strings.Contains(strings.ToLower(resp.Body), "form_post") ||
			strings.Contains(resp.Body, `name="code"`) {
			return "form_post"
		}
		return ""
	}
	hashIdx := strings.Index(loc, "#")
	queryIdx := strings.Index(loc, "?")
	hasCodeInFragment := hashIdx >= 0 && strings.Contains(loc[hashIdx:], "code=")
	end := len(loc)
	if hashIdx >= 0 {
		end = hashIdx
	}
	hasCodeInQuery := queryIdx >= 0 &&
		(hashIdx < 0 || queryIdx < hashIdx) &&
		strings.Contains(loc[queryIdx:end], "code=")
	switch {
	case hasCodeInFragment:
		return "fragment"
	case hasCodeInQuery:
		return "query"
	}
	return ""
}

// findingResponseModeConfusion constructs the finding for an accepted
// response_mode override.
func (d *Detector) findingResponseModeConfusion(probeURL, mode string, _ interface{}) *core.Finding {
	f := core.NewFinding("OAuth response_mode confusion accepted", core.SeverityMedium)
	f.Title = "Authorization endpoint honors caller-supplied response_mode"
	f.URL = probeURL
	f.Tool = "oauthflow-detector"
	f.Description = "The authorization endpoint accepted a response_mode value (" + mode + ") that the client did not pre-register. response_mode=query routes the authorization code through the URL's query string, where it lands in access logs, browser history, and Referer headers shared with downstream resources. response_mode=form_post adds a POST-back surface that an attacker who controls the redirect_uri host can intercept. RFC 9700 §4.7 requires IdPs to ignore caller-supplied response_mode when the client registered a fixed mode."
	f.Evidence = "GET probe with response_mode=" + mode + " produced a successful authorize response"
	f.Remediation = "Pin response_mode to the client's registered value at the authorization endpoint. Reject (or downgrade to the registered value) any caller-supplied response_mode that differs."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2025"},
		[]string{"CWE-200", "CWE-642"},
	)
	return f
}
