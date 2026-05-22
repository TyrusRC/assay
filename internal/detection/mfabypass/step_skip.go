package mfabypass

import (
	"context"
	"fmt"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// DetectMFAStepSkip logs in (acquiring a partial pre-MFA session cookie)
// and then attempts to fetch ProtectedURL WITHOUT completing the MFA step.
// A 2xx response means MFA can be bypassed by skipping the OTP exchange.
func (d *Detector) DetectMFAStepSkip(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionStepSkip,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	lr, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}

	probe := d.withCookies(lr.SetCookie)
	resp, err := probe.Get(ctx, opts.ProtectedURL)
	if err != nil {
		return result, fmt.Errorf("protected probe: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		f := d.findingStepSkip(opts, lr, resp)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}
	return result, nil
}

func (d *Detector) findingStepSkip(opts DetectOptions, lr *loginResponse, resp *http.Response) *core.Finding {
	f := core.NewFinding(typeStepSkip, core.SeverityCritical)
	f.URL = opts.ProtectedURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "After logging in with username/password the partial pre-MFA " +
		"session cookie granted access to a protected resource without ever " +
		"completing the MFA step. The server is treating the pre-MFA session as " +
		"a fully-authenticated one, allowing an attacker who has only the " +
		"first-factor credential to bypass the second factor entirely."
	f.Evidence = fmt.Sprintf(
		"Login URL: %s\nProtected URL: %s\nLogin status=%d, Set-Cookie=%s\n"+
			"Protected (no MFA) status=%d, length=%d",
		opts.LoginURL, opts.ProtectedURL, lr.StatusCode, lr.SetCookie,
		resp.StatusCode, len(resp.Body),
	)
	f.Remediation = "Issue a strictly pre-MFA token whose only allowed action is " +
		"completing the MFA challenge. Reject this token at every other " +
		"endpoint. Only after MFA verification should the server upgrade the " +
		"session to a fully-authenticated one."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-11"},
		[]string{"A07:2025"},
		[]string{"CWE-287"},
	)
	return f
}
