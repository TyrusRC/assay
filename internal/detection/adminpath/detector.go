// Package adminpath probes a target for admin / debug / internal endpoints
// that should not be reachable from the public internet (OWASP API5:2023
// Broken Function Level Authorization, plus API8:2023 / A05:2025 Security
// Misconfiguration).
//
// Two-pass design:
//   - Anonymous pass: probes every wordlist path with no auth headers and
//     emits findings on any 2xx (or auth-bypass-shaped 3xx) response.
//   - Authenticated pass (when scan-config carries Headers/Cookies):
//     re-probes the same paths and additionally flags admin paths
//     reachable to a non-privileged caller. The current detector only
//     surfaces the anonymous tier; cross-role checking is layered on
//     once the scanner can drive multiple identity contexts.
//
// FP guards: a baseline GET on a known-bogus path establishes the site's
// "soft 404" body shape; matches against that body are suppressed.
package adminpath

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/analysis"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// adminWordlist is the curated probe set. Entries are root-relative
// paths; the detector resolves each against the target host. Severity is
// fixed per category so reports can group findings without re-keying on
// regex matches.
var adminWordlist = []struct {
	path     string
	severity core.Severity
	note     string
}{
	// Admin UIs and APIs.
	{"/admin", core.SeverityHigh, "admin entry-point"},
	{"/admin/", core.SeverityHigh, "admin entry-point (trailing slash)"},
	{"/admin/login", core.SeverityHigh, "admin login"},
	{"/manage", core.SeverityMedium, "management UI"},
	{"/management", core.SeverityMedium, "management UI"},
	{"/console", core.SeverityMedium, "operator console"},
	{"/_admin", core.SeverityHigh, "underscore-prefixed admin"},
	{"/api/admin", core.SeverityHigh, "API admin namespace"},
	{"/api/v1/admin", core.SeverityHigh, "API v1 admin"},
	{"/api/v2/admin", core.SeverityHigh, "API v2 admin"},
	{"/api/internal", core.SeverityHigh, "internal API namespace"},
	{"/api/private", core.SeverityHigh, "private API namespace"},
	{"/internal", core.SeverityMedium, "internal endpoint"},
	{"/private", core.SeverityMedium, "private endpoint"},
	{"/staff", core.SeverityMedium, "staff-only endpoint"},
	{"/superadmin", core.SeverityHigh, "superadmin endpoint"},

	// Debug / observability.
	{"/debug", core.SeverityMedium, "debug endpoint"},
	{"/debug/pprof", core.SeverityHigh, "Go pprof handler"},
	{"/debug/pprof/", core.SeverityHigh, "Go pprof handler"},
	{"/debug/vars", core.SeverityMedium, "expvar handler"},
	{"/_debug", core.SeverityMedium, "underscore-debug endpoint"},
	{"/healthz?verbose=true", core.SeverityLow, "verbose healthz"},
	{"/metrics", core.SeverityLow, "Prometheus metrics"},
	{"/_status", core.SeverityLow, "status endpoint"},
	{"/server-status", core.SeverityMedium, "Apache server-status"},
	{"/server-info", core.SeverityMedium, "Apache server-info"},

	// Spring Boot Actuator.
	{"/actuator", core.SeverityMedium, "Spring Boot Actuator root"},
	{"/actuator/env", core.SeverityHigh, "actuator env (config dump)"},
	{"/actuator/heapdump", core.SeverityCritical, "actuator heapdump"},
	{"/actuator/beans", core.SeverityMedium, "actuator beans"},
	{"/actuator/mappings", core.SeverityMedium, "actuator mappings"},
	{"/actuator/trace", core.SeverityHigh, "actuator request trace"},
	{"/actuator/httptrace", core.SeverityHigh, "actuator httptrace"},

	// API documentation / specs (info disclosure tier).
	{"/swagger", core.SeverityLow, "Swagger UI"},
	{"/swagger/index.html", core.SeverityLow, "Swagger UI"},
	{"/swagger-ui", core.SeverityLow, "Swagger UI"},
	{"/swagger-ui.html", core.SeverityLow, "Swagger UI"},
	{"/swagger.json", core.SeverityLow, "Swagger JSON"},
	{"/openapi.json", core.SeverityLow, "OpenAPI JSON"},
	{"/openapi.yaml", core.SeverityLow, "OpenAPI YAML"},
	{"/api-docs", core.SeverityLow, "API docs"},
	{"/v2/api-docs", core.SeverityLow, "Swagger v2 docs"},
	{"/v3/api-docs", core.SeverityLow, "OpenAPI v3 docs"},
	{"/graphql", core.SeverityMedium, "GraphQL endpoint"},
	{"/graphiql", core.SeverityMedium, "GraphiQL UI"},

	// Misc developer leaks.
	{"/.env", core.SeverityCritical, "exposed .env"},
	{"/.git/config", core.SeverityCritical, "exposed .git config"},
	{"/.aws/credentials", core.SeverityCritical, "AWS creds file"},
	{"/config.json", core.SeverityHigh, "exposed config.json"},
	{"/composer.lock", core.SeverityLow, "PHP composer.lock"},
	{"/package.json", core.SeverityLow, "Node package.json"},
	{"/.well-known/openid-configuration", core.SeverityLow, "OIDC discovery"},
	{"/.well-known/security.txt", core.SeverityLow, "security.txt"},
}

// Detector probes the target for admin/debug/internal paths.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries detector findings.
type Result struct {
	Findings []*core.Finding
}

// Detect probes targetURL's host for every entry in adminWordlist. Only
// the host is used — path/query of targetURL are stripped so we hit the
// wordlist absolutely. The baseline soft-404 body is captured once.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}

	base, err := url.Parse(targetURL)
	if err != nil {
		return res, fmt.Errorf("parse target: %w", err)
	}

	// Soft-404 baseline: GET a randomly-named path; whatever the server
	// returns is the "this path does not exist" body shape we must
	// dissimilar-from to claim a real hit.
	canary := "/" + randomPath()
	canaryURL := *base
	canaryURL.Path = canary
	canaryURL.RawQuery = ""
	baselineResp, _ := d.client.Get(ctx, canaryURL.String())
	baselineBody, baselineStatus := "", 0
	if baselineResp != nil {
		baselineBody = analysis.StripDynamicContent(baselineResp.Body)
		baselineStatus = baselineResp.StatusCode
	}

	for _, entry := range adminWordlist {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		probeURL := *base
		probeURL.RawQuery = ""
		// Allow path entries that include their own query string.
		if i := strings.Index(entry.path, "?"); i >= 0 {
			probeURL.Path = entry.path[:i]
			probeURL.RawQuery = entry.path[i+1:]
		} else {
			probeURL.Path = entry.path
		}

		resp, err := d.client.Get(ctx, probeURL.String())
		if err != nil || resp == nil {
			continue
		}

		// Only 2xx is treated as "endpoint reachable". 401 / 403 / 404 mean
		// the access controls are working as intended; we don't flag them.
		// 3xx Location going off-host is a redirect-hop, not a hit.
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		// Soft-404 suppression: if status matches baseline AND body is
		// near-identical to the canary's, the server is returning the
		// same "not found" page for everything.
		if resp.StatusCode == baselineStatus &&
			analysis.ResponseSimilarity(analysis.StripDynamicContent(resp.Body), baselineBody) >= 0.95 {
			continue
		}

		res.Findings = append(res.Findings, buildFinding(probeURL.String(), entry.path, entry.note, entry.severity, resp))
	}
	return res, nil
}

func buildFinding(probedURL, path, note string, severity core.Severity, resp *skwshttp.Response) *core.Finding {
	finding := core.NewFinding("Reachable Admin / Debug Endpoint", severity)
	finding.URL = probedURL
	finding.Parameter = path
	finding.Tool = "adminpath"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"%s is reachable on the target host. Privileged endpoints should reject unauthenticated callers with 401/403; a 2xx response means the path is exposed without an access-control gate.",
		note,
	)
	bodyLen := 0
	if resp != nil {
		bodyLen = len(resp.Body)
	}
	finding.Evidence = fmt.Sprintf("Path: %s\nNote: %s\nStatus: %d\nResponse length: %d",
		path, note, statusOf(resp), bodyLen)
	finding.Remediation = "Require authentication on this path, restrict by IP / VPC, or remove the route from production builds. Debug and observability endpoints should never be reachable from the public internet."
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-04"},
		[]string{"A05:2025"},
		[]string{"CWE-749"},
	)
	finding.APITop10 = []string{"API5:2023", "API8:2023"}
	return finding
}

func statusOf(r *skwshttp.Response) int {
	if r == nil {
		return 0
	}
	return r.StatusCode
}

func randomPath() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "skws-noexist-" + hex.EncodeToString(b[:])
}
