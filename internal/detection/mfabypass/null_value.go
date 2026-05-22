package mfabypass

import (
	"context"
	"fmt"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// DetectMFANullValue logs in, then submits MFA OTPs that should be
// rejected by any sane validator (empty string, "0", literal null).
// Any acceptance (2xx) indicates broken validation.
func (d *Detector) DetectMFANullValue(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionNullValue,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	lr, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}

	probe := d.withCookies(lr.SetCookie)

	// Each payload exercises a different "empty-ish" value. The JSON
	// `null` payload requires a separate raw body so the OTP is decoded
	// as nil instead of the literal string "null".
	type attempt struct {
		label string
		body  string
	}
	attempts := []attempt{
		{label: "empty-string", body: `{"otp":""}`},
		{label: "zero-string", body: `{"otp":"0"}`},
		{label: "json-null", body: `{"otp":null}`},
	}

	for _, a := range attempts {
		resp, err := probe.PostJSON(ctx, opts.MFASubmitURL, a.body)
		if err != nil {
			return result, fmt.Errorf("mfa submit (%s): %w", a.label, err)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			f := d.findingNullValue(opts, a.label, a.body, resp)
			result.Findings = append(result.Findings, f)
			result.Vulnerable = true
			// Reporting the first weakness is enough; the rest are duplicates.
			return result, nil
		}
	}
	return result, nil
}

func (d *Detector) findingNullValue(opts DetectOptions, label, body string, resp *http.Response) *core.Finding {
	f := core.NewFinding(typeNullValue, core.SeverityHigh)
	f.URL = opts.MFASubmitURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "The MFA endpoint accepted an OTP value that should never be " +
		"valid (empty / zero / null). Weak validation that treats missing or " +
		"falsy OTP values as a match allows trivial bypass of the second factor."
	f.Evidence = fmt.Sprintf(
		"MFA URL: %s\nAttempt: %s\nRequest body: %s\nResponse status=%d, length=%d",
		opts.MFASubmitURL, label, body, resp.StatusCode, len(resp.Body),
	)
	f.Remediation = "Reject empty, null, and zero-string OTP values before the " +
		"comparison happens. Use constant-time string comparison on the " +
		"server-side TOTP/HOTP value and require a fixed-length numeric input."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-11"},
		[]string{"A07:2025"},
		[]string{"CWE-287"},
	)
	return f
}
