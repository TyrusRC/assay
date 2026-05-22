package mfabypass

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// DetectMFAResponseManipulation submits the MFA challenge, then re-sends
// the request with the verification cookie/header flipped from false to
// true. If the server accepts the manipulated value, the verification
// state is client-controlled (CWE-287).
//
// Requires opts.ResponseFlipPattern (the cookie name to flip). When the
// pattern is empty, the check is a no-op.
func (d *Detector) DetectMFAResponseManipulation(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionRespManipulate,
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if opts.ResponseFlipPattern == "" {
		return result, nil
	}

	lr, err := d.login(ctx, opts)
	if err != nil {
		return result, err
	}
	probe := d.withCookies(lr.SetCookie)

	// First submission with an obviously wrong OTP — we don't care
	// about success; we only need the server to set its verification
	// cookie/header to a false-ish value we can flip.
	first, err := probe.PostJSON(ctx, opts.MFASubmitURL, `{"otp":"000000"}`)
	if err != nil {
		return result, fmt.Errorf("mfa submit #1: %w", err)
	}

	flipped, ok := flipVerifiedCookie(first.Headers["Set-Cookie"], opts.ResponseFlipPattern)
	if !ok {
		// Server didn't emit a verification cookie we could flip.
		return result, nil
	}

	// Replay with the flipped cookie attached.
	tampered := d.client.Clone().WithCookies(flipped)
	resp, err := tampered.Get(ctx, opts.ProtectedURL)
	if err != nil {
		return result, fmt.Errorf("tampered probe: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		f := d.findingRespManipulation(opts, flipped, resp)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}
	return result, nil
}

// flipVerifiedCookie searches a Set-Cookie header for a cookie whose name
// matches pattern (case-insensitive) and whose value is "false" / "0".
// If found, it returns a Cookie request-header string with that value
// rewritten to "true" / "1" and ok=true.
func flipVerifiedCookie(setCookie, pattern string) (string, bool) {
	if setCookie == "" {
		return "", false
	}
	// Set-Cookie headers may carry multiple cookies separated by commas
	// (per the Client's header-flattening in internal/http). Each entry
	// has the form "name=value; attr=...; attr=...".
	entries := strings.Split(setCookie, ",")
	out := make([]string, 0, len(entries))
	flipped := false
	patternLower := strings.ToLower(pattern)
	for _, e := range entries {
		nameVal := strings.SplitN(strings.TrimSpace(e), ";", 2)[0]
		kv := strings.SplitN(nameVal, "=", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if strings.EqualFold(name, patternLower) || strings.Contains(strings.ToLower(name), patternLower) {
			switch strings.ToLower(val) {
			case "false":
				val = "true"
				flipped = true
			case "0":
				val = "1"
				flipped = true
			}
		}
		out = append(out, name+"="+val)
	}
	if !flipped {
		return "", false
	}
	return strings.Join(out, "; "), true
}

func (d *Detector) findingRespManipulation(opts DetectOptions, flippedCookie string, resp *http.Response) *core.Finding {
	f := core.NewFinding(typeRespManipulate, core.SeverityCritical)
	f.URL = opts.ProtectedURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "The server's MFA verification state is carried in a " +
		"client-controllable cookie/header. Flipping the value (e.g. " +
		"mfa_verified=false to mfa_verified=true) was accepted by a " +
		"protected endpoint, meaning MFA verification can be forged " +
		"client-side without ever solving the challenge."
	f.Evidence = fmt.Sprintf(
		"Protected URL: %s\nFlip pattern: %s\nFlipped Cookie header: %s\n"+
			"Tampered response status=%d, length=%d",
		opts.ProtectedURL, opts.ResponseFlipPattern, flippedCookie,
		resp.StatusCode, len(resp.Body),
	)
	f.Remediation = "Never derive MFA verification state from a client-side cookie " +
		"value. Track verification status server-side (signed/encrypted " +
		"session record or short-lived signed token) and refuse to honor any " +
		"client-supplied 'verified' flag."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-11"},
		[]string{"A07:2025"},
		[]string{"CWE-287"},
	)
	return f
}
