package apispec

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Runner exercises every endpoint in a Spec against a base URL and
// emits findings on the canonical "spec lies vs reality" failure modes
// the OWASP API Top-10 cares about: documented authentication that the
// server does not enforce (API2/API5), and undocumented HTTP verbs that
// nonetheless return a 2xx (API5/API9, verb tampering at the function
// level).
type Runner struct {
	client *skwshttp.Client
}

// NewRunner returns a Runner backed by the project's shared HTTP client.
func NewRunner(client *skwshttp.Client) *Runner {
	return &Runner{client: client}
}

// Result carries findings emitted by Run.
type Result struct {
	Findings        []*core.Finding
	EndpointsProbed int
}

// Run probes every endpoint in spec against baseURL.
//
// Two probes per endpoint:
//
//   1. Spec vs reality: when the operation is marked as requiring auth
//      we send an unauthenticated request and flag any 2xx response.
//      That is API2 / API5 territory: the spec advertises a security
//      requirement that the server does not enforce.
//   2. Verb survey: send OPTIONS, then PUT/PATCH/DELETE for endpoints
//      whose spec doesn't document them. Servers that handle a verb the
//      spec doesn't acknowledge are typically routing to the same
//      handler anyway — and that handler often skips the auth check it
//      relies on the documented verb performing.
//
// The runner is intentionally read-mostly: it never sends a request body
// for unsafe verbs because mutating data on a real target would be
// dangerous. The 2xx-on-undocumented-verb signal is enough.
func (r *Runner) Run(ctx context.Context, spec *Spec, baseURL string) (*Result, error) {
	res := &Result{}
	if r.client == nil || spec == nil {
		return res, nil
	}

	for _, ep := range spec.Endpoints {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		fullURL, err := spec.ResolveURL(baseURL, ep, nil)
		if err != nil {
			continue
		}
		res.EndpointsProbed++

		// 1. Auth-bypass probe — only meaningful for endpoints the spec
		//    flagged as requiring auth AND verbs that don't mutate state
		//    (so we never "succeed" by accidentally creating data).
		if ep.RequiresAuth && isSafeVerb(ep.Method) {
			resp, err := r.client.Get(ctx, fullURL)
			if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				res.Findings = append(res.Findings, buildAuthBypassFinding(fullURL, ep, resp))
			}
		}

		// 2. Undocumented-verb probe — only verbs the operation didn't
		//    document. We don't send bodies; servers that route the
		//    handler at all will surface a 2xx without needing one.
		documented := documentedVerbs(spec, ep.Path)
		for _, verb := range []string{"OPTIONS", "PUT", "PATCH", "DELETE"} {
			if documented[verb] {
				continue
			}
			if !isSafeForUndocProbe(verb) {
				continue
			}
			ok, status := r.probeVerb(ctx, verb, fullURL)
			if ok {
				res.Findings = append(res.Findings, buildUndocVerbFinding(fullURL, ep, verb, status))
			}
		}
	}
	return res, nil
}

// documentedVerbs returns the set of HTTP verbs the spec declares for
// the given path. Unknown paths return an empty set.
func documentedVerbs(spec *Spec, path string) map[string]bool {
	out := map[string]bool{}
	for _, ep := range spec.Endpoints {
		if ep.Path == path {
			out[ep.Method] = true
		}
	}
	return out
}

// probeVerb sends a single request with the given verb. Returns
// (true, status) for a 2xx, (false, _) otherwise.
func (r *Runner) probeVerb(ctx context.Context, verb, target string) (bool, int) {
	resp, err := r.client.SendRawBody(ctx, target, verb, "", "")
	if err != nil || resp == nil {
		return false, 0
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300, resp.StatusCode
}

// isSafeVerb returns true for read-only HTTP verbs.
func isSafeVerb(v string) bool {
	switch strings.ToUpper(v) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// isSafeForUndocProbe returns the verbs we are willing to send during
// the undocumented-verb survey. PUT/PATCH/DELETE are listed because
// without a body they are functionally idempotent on most servers — the
// router rejects or accepts them based on routing alone.
func isSafeForUndocProbe(v string) bool {
	switch v {
	case "OPTIONS", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func buildAuthBypassFinding(url string, ep Endpoint, resp *skwshttp.Response) *core.Finding {
	finding := core.NewFinding("Spec-Documented Auth Not Enforced", core.SeverityCritical)
	finding.URL = url
	finding.Parameter = ep.Path
	finding.Tool = "apispec"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"The OpenAPI spec marks %s %s as requiring authentication, but the server returned a %d to an unauthenticated request. Any caller can reach this endpoint without credentials.",
		ep.Method, ep.Path, resp.StatusCode,
	)
	finding.Evidence = fmt.Sprintf("Spec method: %s\nSpec path: %s\nUnauthenticated status: %d\nResponse length: %d",
		ep.Method, ep.Path, resp.StatusCode, len(resp.Body))
	finding.Remediation = "Ensure the auth middleware is registered for every documented operation. A server-side route table that bypasses the documented security requirement is a far more dangerous posture than missing documentation."
	finding.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2025"},
		[]string{"CWE-862"},
	)
	finding.APITop10 = []string{"API2:2023", "API5:2023"}
	return finding
}

func buildUndocVerbFinding(url string, ep Endpoint, verb string, status int) *core.Finding {
	finding := core.NewFinding("Undocumented HTTP Verb Accepted", core.SeverityMedium)
	finding.URL = url
	finding.Parameter = verb
	finding.Tool = "apispec"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = fmt.Sprintf(
		"%s is not in the spec for %s but the server returned %d. Verbs that the spec does not document often skip the auth and validation logic the documented verbs depend on.",
		verb, ep.Path, status,
	)
	finding.Evidence = fmt.Sprintf("Spec path: %s\nUndocumented verb: %s\nStatus: %d", ep.Path, verb, status)
	finding.Remediation = "Reject undeclared verbs at the router. Either add the verb to the spec and apply the same auth/validation it should have, or return 405 Method Not Allowed."
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-06"},
		[]string{"A05:2025"},
		[]string{"CWE-749"},
	)
	finding.APITop10 = []string{"API5:2023", "API9:2023"}
	return finding
}
