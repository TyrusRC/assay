package cachedeception

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detector probes a target for web cache deception (Omer Gil, 2017).
type Detector struct {
	authedClient *internalhttp.Client
	verbose      bool
}

// New creates a Detector bound to the shared HTTP client. The client is
// expected to carry the authentication state (cookies, auth headers) of
// the user we're probing on behalf of — without auth there's nothing for
// the cache to leak, so the detector becomes a no-op.
func New(client *internalhttp.Client) *Detector {
	return &Detector{authedClient: client}
}

// WithVerbose enables verbose finding evidence.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "cache-deception" }

// Description returns the detector description.
func (d *Detector) Description() string {
	return "Web cache deception detector: probes cacheable-extension and path-normalization variants of a target URL to find places where a downstream cache may store the authenticated user's private response under a public-looking key."
}

// Detect probes target for cache deception. The caller is responsible
// for ensuring the shared client carries auth state (cookies / Bearer)
// for the user whose response we're trying to leak — the detector reads
// the client's snapshot to derive an unauth comparison transport for the
// optional verification step.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.MaxProbes == 0 {
		opts = DefaultOptions()
	}
	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	baselineResp, err := d.authedClient.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("baseline %s: %w", target, err)
	}
	if baselineResp.StatusCode < 200 || baselineResp.StatusCode >= 400 {
		return result, fmt.Errorf("baseline returned non-success status %d", baselineResp.StatusCode)
	}
	baselineBody := baselineResp.Body
	if len(baselineBody) < 16 {
		// Too small to fingerprint reliably — bail rather than emit an FP.
		return result, nil
	}

	probes := generateProbeURLs(target, opts.Strategies, opts.Extensions, opts.MaxProbes)
	result.TestedPayloads = len(probes)

	for _, p := range probes {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		resp, err := d.authedClient.Get(ctx, p.URL)
		if err != nil {
			continue
		}
		if !bodySimilar(resp.Body, baselineBody) {
			continue
		}
		// First leg met: the deceptive URL returns the authenticated body.

		cacheable := looksCacheable(resp.Headers)
		confirmed := false
		var verifyEvidence string

		if opts.VerifyWithUnauth && d.canRunUnauthVerify() {
			confirmed, verifyEvidence = d.unauthVerify(ctx, p.URL, baselineBody)
		}

		// Emit a finding even when neither cacheable-headers nor unauth-
		// confirmation hold — the application bug (private content served
		// at a deceptive URL) is itself reportable. Severity is graded:
		//   - confirmed by unauth replay → Critical
		//   - cacheable headers seen → High
		//   - neither → Medium (the application precondition alone)
		finding := d.buildFinding(target, p, resp, cacheable, confirmed, verifyEvidence)
		result.Findings = append(result.Findings, finding)
		result.Vulnerable = true
	}

	return result, nil
}

// canRunUnauthVerify reports whether we can stand up an unauthenticated
// transport that mirrors the proxy/insecure plumbing of the authed client
// but strips cookies and auth headers. A nil snapshot can never confirm.
func (d *Detector) canRunUnauthVerify() bool {
	if d.authedClient == nil {
		return false
	}
	snap := d.authedClient.Snapshot()
	return snap.Cookies != "" || hasAuthHeader(snap.Headers)
}

func hasAuthHeader(h map[string]string) bool {
	for k := range h {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "x-auth-token" || strings.HasPrefix(lk, "x-csrf") {
			return true
		}
	}
	return false
}

// unauthVerify performs the second-leg confirmation: fetch the deceptive
// URL with no auth state and check whether the cache served us the
// authenticated body anyway. This is the smoking gun — the cache having
// stored a private response under a public-looking key.
func (d *Detector) unauthVerify(ctx context.Context, probeURL, authedBody string) (bool, string) {
	snap := d.authedClient.Snapshot()
	unauth := internalhttp.NewClient().
		WithFollowRedirects(false).
		WithUserAgent(snap.UserAgent).
		WithInsecure(snap.Insecure)
	if snap.ProxyURL != "" {
		unauth.WithProxy(snap.ProxyURL)
	}
	// Mirror non-auth headers but strip auth-flavored ones.
	headers := make(map[string]string, len(snap.Headers))
	for k, v := range snap.Headers {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "cookie" || strings.HasPrefix(lk, "x-csrf") || lk == "x-auth-token" {
			continue
		}
		headers[k] = v
	}
	if len(headers) > 0 {
		unauth.WithHeaders(headers)
	}

	resp, err := unauth.Get(ctx, probeURL)
	if err != nil {
		return false, fmt.Sprintf("unauth probe error: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Sprintf("unauth probe got status %d (cache likely did not serve)", resp.StatusCode)
	}
	if !bodySimilar(resp.Body, authedBody) {
		return false, "unauth probe got a different body — cache did not serve the authed response"
	}
	return true, fmt.Sprintf("unauth probe to %s returned the authenticated body — cache served private content to a non-authenticated request", probeURL)
}

func (d *Detector) buildFinding(target string, p probeURL, resp *internalhttp.Response, cacheable, confirmed bool, verifyEv string) *core.Finding {
	severity := core.SeverityMedium
	title := "Web Cache Deception (Application Precondition Only)"
	switch {
	case confirmed:
		severity = core.SeverityCritical
		title = "Web Cache Deception (Confirmed via Unauth Replay)"
	case cacheable:
		severity = core.SeverityHigh
		title = "Web Cache Deception (Cacheable Response)"
	}

	finding := core.NewFinding(title, severity)
	finding.URL = p.URL
	finding.Tool = "cache-deception-detector"
	finding.Description = fmt.Sprintf(
		"The deceptive URL %s returned the same authenticated response body as the canonical target %s. Strategy: %s.",
		p.URL, target, p.Strategy,
	)
	if confirmed {
		finding.Description += " The unauthenticated replay confirmed the response was served from cache."
	} else if !cacheable {
		finding.Description += " No cache-vendor headers or positive Cache-Control directives were observed; the application bug exists but a downstream cache may still classify the response as cacheable based on extension alone (CDN defaults frequently do)."
	}

	var evid []string
	evid = append(evid, "strategy: "+string(p.Strategy))
	evid = append(evid, "deceptive URL: "+p.URL)
	if v := headerValue(resp.Headers, "Cache-Control"); v != "" {
		evid = append(evid, "Cache-Control: "+v)
	}
	for _, h := range cacheVendorHeaders {
		if v := headerValue(resp.Headers, h); v != "" {
			evid = append(evid, h+": "+v)
		}
	}
	if verifyEv != "" {
		evid = append(evid, "verification: "+verifyEv)
	}
	finding.Evidence = strings.Join(evid, "\n")

	finding.Remediation = "Ensure the application returns a non-private response (404 or canonical redirect) for any URL that does not match a routed handler — do not silently strip extensions, semicolons, or path suffixes during routing. As a defense in depth, set Cache-Control: private, no-store on every authenticated response, and configure CDN cache rules to never store responses with a Set-Cookie header or a non-empty Authorization request header. Reference: https://www.omergil.com/2017/03/web-cache-deception-attack.html and PortSwigger Web Security Academy 'Web cache deception'."

	finding.WithOWASPMapping(
		[]string{"WSTG-ATHN-06", "WSTG-CONF-08"},
		[]string{"A04:2025", "A05:2025"},
		[]string{"CWE-524", "CWE-525"},
	)
	finding.APITop10 = []string{"API1:2023", "API3:2023"}
	return finding
}
