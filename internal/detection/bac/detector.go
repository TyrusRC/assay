package bac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/TyrusRC/assay/internal/core"
	httpx "github.com/TyrusRC/assay/internal/http"
)

// Principal is a named identity with its own authenticated HTTP client.
type Principal struct {
	// Name identifies the principal (e.g. "user-a", "anonymous").
	Name string
	// Client carries the principal's session (cookies/headers).
	Client *httpx.Client
}

// Detector compares endpoint access across a privileged principal and one or
// more lower principals to find broken function-level authorization.
type Detector struct {
	privileged Principal
	others     []Principal
}

// New creates a Detector with a privileged baseline principal and the other
// principals to test against it (e.g. a second user and/or anonymous).
func New(privileged Principal, others ...Principal) *Detector {
	return &Detector{privileged: privileged, others: others}
}

// Detect requests each endpoint as every principal and flags those where a
// lower principal receives content equivalent to the privileged baseline.
func (d *Detector) Detect(ctx context.Context, endpoints []string) []*core.Finding {
	if len(d.others) == 0 || d.privileged.Client == nil {
		return nil
	}
	var findings []*core.Finding
	for _, endpoint := range endpoints {
		priv, ok := d.observe(ctx, d.privileged, endpoint)
		if !ok || !isSuccess(priv.Status) {
			continue
		}
		others := d.observeOthers(ctx, endpoint)
		if v := Classify(priv, others); v.Broken {
			findings = append(findings, buildFinding(endpoint, v))
		}
	}
	return findings
}

// observeOthers gathers observations for every non-privileged principal.
func (d *Detector) observeOthers(ctx context.Context, endpoint string) []AccessObservation {
	out := make([]AccessObservation, 0, len(d.others))
	for _, p := range d.others {
		if obs, ok := d.observe(ctx, p, endpoint); ok {
			out = append(out, obs)
		}
	}
	return out
}

// observe performs a single GET as a principal and summarizes the response.
func (d *Detector) observe(ctx context.Context, p Principal, endpoint string) (AccessObservation, bool) {
	if p.Client == nil {
		return AccessObservation{}, false
	}
	resp, err := p.Client.Get(ctx, endpoint)
	if err != nil || resp == nil {
		return AccessObservation{}, false
	}
	return AccessObservation{
		Principal: p.Name,
		Status:    resp.StatusCode,
		BodyLen:   len(resp.Body),
		BodyHash:  hashBody(resp.Body),
	}, true
}

// hashBody returns a stable hex hash of a response body.
func hashBody(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// buildFinding constructs the BAC finding for a confirmed violation.
func buildFinding(endpoint string, v Verdict) *core.Finding {
	f := core.NewFinding("Broken Function Level Authorization", core.SeverityHigh)
	f.At(endpoint, "").ByTool("bac")
	f.Confidence = core.ConfidenceHigh
	f.Title = "Broken access control: " + v.Kind
	f.Description = "Broken access control detected. " + v.Detail + ". " +
		"The endpoint enforces no (or insufficient) authorization: a lower-privileged " +
		"principal obtained the same content served to the privileged user."
	f.Evidence = v.Detail
	f.CWE = []string{"CWE-862"}
	f.WSTG = []string{"WSTG-ATHZ-02"}
	f.Top10 = []string{"A01:2025"}
	f.APITop10 = []string{"API5:2023"}
	f.Remediation = "Enforce server-side authorization on every endpoint and action, checking the " +
		"authenticated principal's privileges against the requested resource. Deny by default."
	f.References = []string{
		"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
	}
	return f
}
