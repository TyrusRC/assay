package domdetect

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// RedirectResult holds the findings from DetectDOMRedirect.
type RedirectResult struct {
	Findings []*core.Finding
}

// evilDomain is the canary destination written into the probed parameter.
// We want a host the target's allow-list almost certainly does not match,
// and one whose own pages will not be visited (we don't follow the
// redirect — we just sample location.host before any real navigation
// happens). example.invalid is reserved by RFC 6761 and cannot resolve.
const evilDomain = "evil.example"

// commonRedirectParams are the query-key names attackers most often probe
// for client-side redirect sinks. We try each in turn — most apps only
// honor one or two.
var commonRedirectParams = []string{
	"returnUrl", "returnURL", "return_url", "return",
	"redirect", "redirectUrl", "redirectURL", "redirect_uri", "redirect_to",
	"next", "url", "dest", "destination", "continue", "goto", "to",
	"forward", "forward_url",
}

// DetectDOMRedirect probes targetURL for DOM-based open redirection. For
// each candidate parameter we navigate to `?<param>=https://<evilDomain>/`
// and then ask the browser for `location.host`. If the host has flipped to
// evilDomain, client JS read the parameter and assigned it to
// window.location — the canonical DOM-based open-redirect sink.
//
// Server-side 30x redirects can't trigger this signal because we sample
// location.host inside the page that the runner navigated to; a server
// redirect would have already completed before we evaluate.
func DetectDOMRedirect(ctx context.Context, runner Runner, targetURL string) (*RedirectResult, error) {
	res := &RedirectResult{}
	if runner == nil {
		return res, nil
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return res, fmt.Errorf("parse target: %w", err)
	}

	// Confirm the runner can land on the original target. If it can't, we
	// have no baseline and would otherwise emit FPs whenever Navigate
	// silently fails for unrelated reasons.
	if err := runner.Navigate(ctx, targetURL); err != nil {
		return res, nil
	}
	baselineHost, err := runner.EvalJS(ctx, `location.host`)
	if err != nil {
		return res, nil
	}
	baselineHost = strings.Trim(baselineHost, `"`)
	if baselineHost == "" {
		return res, nil
	}

	for _, paramName := range commonRedirectParams {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		probeURL := setQueryParam(u, paramName, "https://"+evilDomain+"/")
		if err := runner.Navigate(ctx, probeURL); err != nil {
			continue
		}
		got, err := runner.EvalJS(ctx, `location.host`)
		if err != nil {
			continue
		}
		host := strings.Trim(got, `"`)
		if host == "" || host == baselineHost {
			continue
		}
		if !strings.Contains(strings.ToLower(host), evilDomain) {
			continue
		}

		finding := core.NewFinding("DOM-Based Open Redirection", core.SeverityMedium)
		finding.URL = targetURL
		finding.Parameter = paramName
		finding.Description = fmt.Sprintf(
			"DOM-based open redirection detected in '%s' parameter. Client JS read the parameter value and assigned it to window.location, allowing an attacker to redirect victims off-site.",
			paramName,
		)
		finding.Evidence = fmt.Sprintf("Probe: %s=https://%s/\nlocation.host after navigation: %q", paramName, evilDomain, host)
		finding.Tool = "domdetect-redirect"
		finding.Confidence = core.ConfidenceHigh
		finding.Remediation = "Validate redirect destinations against an allow-list of trusted hosts. Treat URL-shaped parameters as untrusted and never assign them to window.location without a same-origin check."
		finding.WithOWASPMapping(
			[]string{"WSTG-CLNT-04"},
			[]string{"A01:2025"},
			[]string{"CWE-601"},
		)
		res.Findings = append(res.Findings, finding)
		// One confirmed sink is sufficient.
		return res, nil
	}
	return res, nil
}
