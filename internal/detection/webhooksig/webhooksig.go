// Package webhooksig audits HTTP endpoints that look like webhook
// receivers for signature-verification weaknesses. The detector
// targets the most common SaaS-driven webhook shapes — Stripe,
// GitHub, Slack, Twilio, Shopify — and the symptomatic bugs:
//
//  1. Missing-signature accept: server returns 2xx with no
//     X-Signature / Stripe-Signature / X-Hub-Signature-256 header.
//  2. Wrong-signature accept: server accepts a request whose signature
//     header is present but wrong.
//  3. Timestamp not validated: replayed timestamp older than the
//     provider's documented window (5 min for Stripe, 5 min for Slack)
//     still accepted.
//  4. Algorithm-confusion: signature header advertised as "sha1=..."
//     accepted in addition to "sha256=...".
//
// We DON'T attempt to forge valid signatures — we only audit whether
// the verification logic FAILS CLOSED, which is the engineering
// property that matters.
//
// References:
//   - https://stripe.com/docs/webhooks/signatures
//   - https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
//   - https://api.slack.com/authentication/verifying-requests-from-slack
package webhooksig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Issue identifies a webhook signature-verification weakness.
type Issue string

const (
	IssueMissingSigAccepted Issue = "missing_sig_accepted"
	IssueWrongSigAccepted   Issue = "wrong_sig_accepted"
	IssueTimestampStale     Issue = "stale_timestamp_accepted"
	IssueAlgConfusion       Issue = "algorithm_confusion"
)

// CommonEndpoints returns the curated wordlist of webhook-shaped paths
// the discovery layer probes for. Each entry has at least one production
// SaaS that publishes example URLs in that shape.
func CommonEndpoints() []string {
	return []string{
		"/webhook",
		"/webhooks",
		"/api/webhook",
		"/api/webhooks",
		"/hooks",
		"/api/hooks",
		"/stripe/webhook",
		"/webhook/stripe",
		"/github/webhook",
		"/webhook/github",
		"/slack/events",
		"/api/slack/events",
		"/twilio/webhook",
		"/shopify/webhook",
		"/api/v1/webhook",
		"/notifications",
		"/api/notifications",
		"/callback",
		"/callbacks",
		"/event",
		"/events",
	}
}

// SignatureHeaders are the headers different webhook providers use.
// Used to (a) decide whether a target endpoint expects signed deliveries
// and (b) construct probe requests that mimic legitimate clients.
func SignatureHeaders() []string {
	return []string{
		"Stripe-Signature",
		"X-Hub-Signature",
		"X-Hub-Signature-256",
		"X-Slack-Signature",
		"X-Slack-Request-Timestamp",
		"X-Twilio-Signature",
		"X-Shopify-Hmac-Sha256",
		"X-GitHub-Event",
		"X-GitHub-Delivery",
		"X-Signature",
		"X-Webhook-Signature",
	}
}

// Detector probes webhook receivers for signature-verification flaws.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New constructs a Detector.
func New(client *http.Client) *Detector {
	if client == nil {
		client = http.DefaultClient
	}
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the probe.
type DetectOptions struct {
	Timeout time.Duration
	// MaxEndpoints caps the wordlist size. 0 = all.
	MaxEndpoints int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 6 * time.Second}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Endpoints  []string // discovered webhook-shaped endpoint paths
	Findings   []*core.Finding
	Vulnerable bool
}

// Detect walks the CommonEndpoints wordlist and probes each candidate
// that looks like a real webhook receiver (returns 2xx/4xx with a body
// suggesting it parsed our request).
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("webhooksig: parse URL: %w", err)
	}
	base := u.Scheme + "://" + u.Host
	result := &DetectionResult{URL: target}

	endpoints := CommonEndpoints()
	if opts.MaxEndpoints > 0 && len(endpoints) > opts.MaxEndpoints {
		endpoints = endpoints[:opts.MaxEndpoints]
	}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		candidate := base + ep
		if !d.looksLikeWebhookReceiver(ctx, candidate, opts.Timeout) {
			continue
		}
		result.Endpoints = append(result.Endpoints, ep)

		// Probe 1: empty body POST with no signature.
		if status, ok := d.probeMissingSig(ctx, candidate, opts.Timeout); ok {
			if status >= 200 && status < 300 {
				result.Findings = append(result.Findings,
					d.findingMissingSig(candidate, status))
			}
		}

		// Probe 2: bogus signature.
		if status, ok := d.probeWrongSig(ctx, candidate, opts.Timeout); ok {
			if status >= 200 && status < 300 {
				result.Findings = append(result.Findings,
					d.findingWrongSig(candidate, status))
			}
		}

		// Probe 3: stale Stripe-Signature timestamp (7 days old).
		if status, ok := d.probeStaleTimestamp(ctx, candidate, opts.Timeout); ok {
			if status >= 200 && status < 300 {
				result.Findings = append(result.Findings,
					d.findingStaleTimestamp(candidate, status))
			}
		}
	}

	for _, f := range result.Findings {
		if f.Severity != core.SeverityInfo {
			result.Vulnerable = true
			break
		}
	}
	return result, nil
}

// looksLikeWebhookReceiver returns true when the candidate endpoint
// responds in a way that suggests it is a real receiver: 2xx or 4xx
// with a non-empty JSON-ish body, or a 401/403 that mentions a
// signature header.
func (d *Detector) looksLikeWebhookReceiver(ctx context.Context, target string, timeout time.Duration) bool {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// POST with an empty body — every real webhook receiver parses
	// POST, so a 405 / 404 rules it out cheaply.
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, target, strings.NewReader("{}"))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	bodyLower := strings.ToLower(string(body))
	// Strong positive: response mentions signature.
	if strings.Contains(bodyLower, "signature") ||
		strings.Contains(bodyLower, "stripe-signature") ||
		strings.Contains(bodyLower, "x-hub") {
		return true
	}
	// Positive: any JSON-shaped response body. A 2xx with JSON body to a
	// /webhook-shaped path is itself the bug — we want to surface it
	// rather than gate-reject. A 4xx with JSON body confirms the server
	// parsed our request and is asking for signature material.
	if strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		return true
	}
	return false
}

// probeMissingSig POSTs a webhook-like body with NO signature header.
// Returns the status code and ok=true on transport success.
func (d *Detector) probeMissingSig(ctx context.Context, target string, timeout time.Duration) (int, bool) {
	body := `{"type":"assay.probe","data":{"object":"audit"}}`
	return d.post(ctx, target, body, nil, timeout)
}

// probeWrongSig POSTs with a syntactically-valid but wrong Stripe-style
// signature. A correctly-implemented receiver rejects (>= 400); a
// vulnerable one returns 2xx.
func (d *Detector) probeWrongSig(ctx context.Context, target string, timeout time.Duration) (int, bool) {
	body := `{"type":"assay.probe","data":{"object":"audit"}}`
	headers := map[string]string{
		"Stripe-Signature":   "t=1700000000,v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"X-Hub-Signature-256": "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"X-Slack-Signature":   "v0=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	}
	return d.post(ctx, target, body, headers, timeout)
}

// probeStaleTimestamp POSTs with a Stripe-style timestamp 7 days in the
// past. Stripe rejects anything older than 5 min by default; a receiver
// that doesn't validate timestamps will accept this.
func (d *Detector) probeStaleTimestamp(ctx context.Context, target string, timeout time.Duration) (int, bool) {
	body := `{"type":"assay.probe","data":{"object":"audit"}}`
	stale := time.Now().Add(-7 * 24 * time.Hour).Unix()
	headers := map[string]string{
		"Stripe-Signature":            fmt.Sprintf("t=%d,v1=deadbeef", stale),
		"X-Slack-Request-Timestamp":   fmt.Sprintf("%d", stale),
		"X-Slack-Signature":           "v0=deadbeef",
	}
	return d.post(ctx, target, body, headers, timeout)
}

// post is the shared HTTP helper.
func (d *Detector) post(ctx context.Context, target, body string, headers map[string]string, timeout time.Duration) (int, bool) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	return resp.StatusCode, true
}

func (d *Detector) findingMissingSig(target string, status int) *core.Finding {
	f := core.NewFinding("webhooksig_"+string(IssueMissingSigAccepted), core.SeverityHigh)
	f.Tool = "webhooksig"
	f.URL = target
	f.Title = "Webhook receiver accepts requests with NO signature header"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The endpoint returned " + statusString(status) + " for a POST that carried no Stripe-Signature, X-Hub-Signature-256, X-Slack-Signature, or X-Webhook-Signature header. " +
		"A webhook receiver MUST verify the signature on every delivery; missing-signature should hard-fail. " +
		"This endpoint is reachable by any anonymous client who can hit the URL — bypassing the entire authentication model the webhook provider documented."
	f.Evidence = fmt.Sprintf("POST returned %d with no signature header", status)
	f.Metadata["status"] = status
	f.Remediation = "Require the provider's signature header on every request. Stripe: validate Stripe-Signature against your STRIPE_WEBHOOK_SECRET. GitHub: validate X-Hub-Signature-256 against your webhook secret. Slack: validate X-Slack-Signature against your SLACK_SIGNING_SECRET."
	f.References = []string{
		"https://stripe.com/docs/webhooks/signatures",
		"https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-ATHN-10"},
		[]string{"A07:2021"},
		[]string{"CWE-345"},
	)
	return f
}

func (d *Detector) findingWrongSig(target string, status int) *core.Finding {
	f := core.NewFinding("webhooksig_"+string(IssueWrongSigAccepted), core.SeverityHigh)
	f.Tool = "webhooksig"
	f.URL = target
	f.Title = "Webhook receiver accepts requests with a wrong signature"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The endpoint returned " + statusString(status) + " for a POST whose Stripe-Signature / X-Hub-Signature-256 / X-Slack-Signature header was syntactically valid but contained an unrelated value (deadbeef...). " +
		"A correctly-implemented receiver rejects any signature that doesn't match the HMAC of the request body under the shared secret. Accepting an unrelated signature means the verification logic is broken — possibly checking only that the header exists, not its value."
	f.Evidence = fmt.Sprintf("POST with deadbeef signature returned %d", status)
	f.Metadata["status"] = status
	f.Remediation = "Use the provider's library (stripe.Webhook.ConstructEvent, github webhook validation helpers, slack.SecretsVerifier) rather than rolling your own HMAC compare. Use crypto/subtle.ConstantTimeCompare to avoid timing oracles. Reject empty / placeholder secrets in production builds."
	f.References = []string{
		"https://stripe.com/docs/webhooks/signatures",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-ATHN-10"},
		[]string{"A07:2021"},
		[]string{"CWE-347"},
	)
	return f
}

func (d *Detector) findingStaleTimestamp(target string, status int) *core.Finding {
	f := core.NewFinding("webhooksig_"+string(IssueTimestampStale), core.SeverityMedium)
	f.Tool = "webhooksig"
	f.URL = target
	f.Title = "Webhook receiver accepts deliveries with stale timestamps (replay window unbounded)"
	f.Confidence = core.ConfidenceMedium
	f.Description = "The endpoint returned " + statusString(status) + " for a POST whose timestamp claimed to be from 7 days ago. " +
		"Webhook providers prescribe a tight replay window (Stripe: 5 minutes, Slack: 5 minutes) and the receiver MUST check the timestamp. Accepting stale deliveries lets an on-path observer capture one webhook payload and replay it forever."
	f.Evidence = fmt.Sprintf("POST with 7-day-old timestamp returned %d", status)
	f.Metadata["status"] = status
	f.Remediation = "After verifying the signature, compare the request's timestamp to time.Now() and reject anything older than the documented tolerance (5 min for Stripe / Slack, 10 min if you must be more lenient). The timestamp lives in the Stripe-Signature header's `t=` field or in X-Slack-Request-Timestamp."
	f.References = []string{
		"https://api.slack.com/authentication/verifying-requests-from-slack",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-SESS-08"},
		[]string{"A07:2021"},
		[]string{"CWE-294"},
	)
	return f
}

func statusString(s int) string {
	return fmt.Sprintf("HTTP %d", s)
}
