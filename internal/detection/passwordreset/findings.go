package passwordreset

import (
	"fmt"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

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
