// Package ratelimit probes whether a target endpoint enforces a server
// side request rate limit (OWASP API4:2023 Unrestricted Resource
// Consumption). The detector sends a controlled, time-bounded burst of
// HEAD/GET requests and looks for the canonical rate-limit signals:
// 429 Too Many Requests, 503 Service Unavailable, or RFC 6585 Retry-After
// / X-RateLimit-* headers.
//
// The probe is intentionally conservative: a small request count over a
// short window, all with low-side-effect verbs. It is not a load test;
// it exists to detect the *absence* of any limit, which is the API4
// signal. Endpoints that handle authentication, password reset, or
// signup are flagged at higher severity because the absence of a limit
// there enables credential stuffing and account abuse.
package ratelimit

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detector probes targetURL for a rate limit by sending a small burst.
type Detector struct {
	client *skwshttp.Client
	// burstSize is how many requests we send. 12 is enough for any sane
	// server to start signalling a limit, while staying below threshold-
	// of-pain for a target.
	burstSize int
	// burstWindow is how long we spread the burst over. 2s × 12 requests
	// = 6 req/s, which sits within typical IP-rate-limit policies but
	// well over per-endpoint limits.
	burstWindow time.Duration
}

// New returns a Detector with conservative burst defaults.
func New(client *skwshttp.Client) *Detector {
	return &Detector{
		client:      client,
		burstSize:   12,
		burstWindow: 2 * time.Second,
	}
}

// Result carries findings from Detect.
type Result struct {
	Findings []*core.Finding
}

// rateLimitHeaderRe matches header NAMES that indicate the endpoint is
// rate-limit-aware even when the burst didn't trigger throttling. We
// inspect every response header set returned during the probe.
var rateLimitHeaderRe = regexp.MustCompile(`(?i)^(retry-after|x-ratelimit(-|_)|ratelimit-|x-rate-limit-)`)

// sensitiveEndpointHints elevate severity from Medium to High. Any
// path containing one of these substrings is treated as "high-value"
// for credential-stuffing / abuse purposes.
var sensitiveEndpointHints = []string{
	"login", "signin", "signup", "register", "password", "passwd",
	"reset", "forgot", "recover", "verify", "otp", "mfa",
	"checkout", "payment", "purchase", "order",
}

// Detect sends burstSize requests across burstWindow and inspects the
// response set for rate-limit signals. No throttling and no rate-limit
// headers anywhere → emit a finding. Returns an empty Result on a nil
// client or unparsable URL — failure to probe is never a finding.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	gap := d.burstWindow / time.Duration(d.burstSize)
	if gap <= 0 {
		gap = 50 * time.Millisecond
	}

	var (
		throttled       bool
		sawHeaderHint   bool
		statuses        []int
		successCount    int
	)

	ticker := time.NewTicker(gap)
	defer ticker.Stop()

	for i := 0; i < d.burstSize; i++ {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		if i > 0 {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return res, ctx.Err()
			}
		}

		resp, err := d.client.Get(ctx, targetURL)
		if err != nil || resp == nil {
			continue
		}
		statuses = append(statuses, resp.StatusCode)

		switch {
		case resp.StatusCode == 429, resp.StatusCode == 503:
			throttled = true
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			successCount++
		}

		for name := range resp.Headers {
			if rateLimitHeaderRe.MatchString(name) {
				sawHeaderHint = true
				break
			}
		}

		// Once we've confirmed a limit is in place, stop early — no
		// reason to keep poking.
		if throttled || sawHeaderHint {
			break
		}
	}

	// Only flag when we sent the full burst, every reply was 2xx, and we
	// saw no header hint and no throttling. That combination is the API4
	// signal: the server is willing to keep serving us indefinitely.
	if throttled || sawHeaderHint {
		return res, nil
	}
	if successCount < d.burstSize {
		// Some 4xx/5xx that wasn't a throttle — endpoint may be broken
		// or behind auth. Don't claim "no rate limit" without a clean
		// burst.
		return res, nil
	}

	res.Findings = append(res.Findings, buildFinding(targetURL, u, statuses))
	return res, nil
}

func buildFinding(targetURL string, u *url.URL, statuses []int) *core.Finding {
	severity := core.SeverityMedium
	pathLower := strings.ToLower(u.Path)
	for _, hint := range sensitiveEndpointHints {
		if strings.Contains(pathLower, hint) {
			severity = core.SeverityHigh
			break
		}
	}
	finding := core.NewFinding("Missing Rate Limit", severity)
	finding.URL = targetURL
	finding.Tool = "ratelimit"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = "The endpoint accepted a burst of identical requests without throttling and returned no rate-limit signalling headers (Retry-After, X-RateLimit-*). Missing rate limits enable credential-stuffing, business-flow abuse, and resource-exhaustion attacks."
	finding.Evidence = fmt.Sprintf(
		"Sent %d requests within ~%dms; all returned 2xx with no rate-limit headers.\nObserved statuses: %v",
		len(statuses), 50*len(statuses), statuses,
	)
	finding.Remediation = "Apply per-IP and per-user rate limits at the edge or application layer. Authentication, password-reset, signup, and checkout flows in particular should ship with strict short-window limits and CAPTCHA or PoW for high-volume callers."
	finding.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A04:2025"},
		[]string{"CWE-770"},
	)
	finding.APITop10 = []string{"API4:2023", "API6:2023"}
	return finding
}
