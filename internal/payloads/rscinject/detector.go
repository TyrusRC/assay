package rscinject

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/payloads/paraminject"
)

// Detector probes a target for React Server Components / Next.js
// Server-Action injection by fingerprinting RSC use in the baseline
// response and then firing each payload's pre-built Method/Headers/Body
// against the target.
//
// Signals (in priority order):
//   - Body differential vs baseline that includes RSC sigils ("$1"
//     references) we did NOT see in the baseline.
//   - Server-Action error responses that reveal the action ID was
//     processed (Next.js bubbles up specific errors).
//   - 5xx response specifically referencing flight-parser internals.
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
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxPayloads  int
	// ConfirmedRSCOnly gates active payloads behind a fingerprint hit.
	// When true (default), the detector first looks for RSC fingerprints
	// in the baseline and only fires payloads if Next.js is confirmed.
	ConfirmedRSCOnly bool
	// BaselineCache, when non-nil, shares the baseline GET with other
	// detectors targeting the same URL.
	BaselineCache *paraminject.Cache
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:          10 * time.Second,
		MaxBodyBytes:     256 << 10, // RSC payloads are bigger than typical bodies
		MaxPayloads:      6,
		ConfirmedRSCOnly: true,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL         string
	RSCDetected bool
	Findings    []*core.Finding
	Vulnerable  bool
}

// Detect runs the RSC injection probe.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 256 << 10
	}
	if opts.MaxPayloads <= 0 {
		opts.MaxPayloads = 6
	}

	result := &DetectionResult{URL: target}

	baselineBody, baselineHash, err := d.baseline(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("rscinject: baseline: %w", err)
	}
	if hasFingerprint(baselineBody) {
		result.RSCDetected = true
	}

	if opts.ConfirmedRSCOnly && !result.RSCDetected {
		return result, nil
	}

	payloads := GetPayloads()
	if len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		body, hash, ok := d.fire(ctx, target, p, opts)
		if !ok {
			continue
		}
		marker := evaluationMarker(p, body, baselineBody, hash, baselineHash)
		if marker == "" {
			continue
		}
		result.Findings = append(result.Findings, d.toFinding(target, p, marker))
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// baseline fetches the target via the per-scan cache when one is
// supplied. Returns the body and a content-hash used for differential
// comparisons.
func (d *Detector) baseline(ctx context.Context, target string, opts DetectOptions) (string, string, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	body, _, err := opts.BaselineCache.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
	if err != nil {
		return "", "", err
	}
	return body, hashBody(body), nil
}

// fire issues the per-payload request and returns the response body
// and content hash. The third return is false on transport errors.
func (d *Detector) fire(ctx context.Context, target string, p Payload, opts DetectOptions) (string, string, bool) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	body := strings.NewReader(p.Body)
	req, err := http.NewRequestWithContext(rctx, p.Method, target, body)
	if err != nil {
		return "", "", false
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	s := string(got)
	return s, hashBody(s), true
}

// evaluationMarker decides whether a response shows the payload landed.
// Signals (in priority):
//   - New RSC sigil ("$1", "$2", …) present in response but not baseline
//     — indicates a component-tree was returned for this request that
//     wasn't in the baseline.
//   - Flight-parser error string returned.
//   - Body hash differs from baseline AND response is not the standard
//     401 / 403 / 404 / 405 shape (which is what a hardened server should
//     return for our payloads).
func evaluationMarker(p Payload, body, baseline, hash, baselineHash string) string {
	if hash == baselineHash {
		return ""
	}

	// New RSC sigil present.
	for _, sigil := range []string{`"$1"`, `"$2"`, `"$3"`, `__next_f.push`} {
		if strings.Contains(body, sigil) && !strings.Contains(baseline, sigil) {
			return "new RSC sigil: " + sigil
		}
	}

	// Flight-parser / server-action error string surfaced.
	parserErrors := []string{
		"Cannot read properties of undefined",
		"reading 'apply'",
		"Maximum call stack size exceeded",
		"Invalid action id",
		"Server Action not found",
		"Failed to find Server Action",
		"Cannot find Server Action",
	}
	for _, e := range parserErrors {
		if strings.Contains(body, e) {
			return "flight-parser error: " + e
		}
	}

	// Generic body differential. Suppress unless this is one of the
	// vectors where a differential alone is the signal (cache poison,
	// header injection — the response shape changed because the server
	// honoured our header).
	switch p.Vector {
	case VectorCacheKey, VectorHeaderInjection, VectorComponentLeak:
		return fmt.Sprintf("body differential (hash %s ≠ baseline %s)", hash[:12], baselineHash[:12])
	}
	return ""
}

func hashBody(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:16])
}

// hasFingerprint reports whether the body shows RSC / Next.js
// fingerprints. A single hit is enough — the fingerprint list is
// already curated to high-signal markers.
func hasFingerprint(body string) bool {
	for _, fp := range Fingerprints() {
		if strings.Contains(body, fp) {
			return true
		}
	}
	return false
}

func (d *Detector) toFinding(target string, p Payload, marker string) *core.Finding {
	sev := mapSeverity(p.Impact)
	f := core.NewFinding("rsc_"+string(p.Vector), sev)
	f.Tool = "rscinject"
	f.URL = target
	f.Title = "React Server Components / Next.js Server-Action issue: " + p.Name
	f.Confidence = core.ConfidenceMedium
	f.Description = "A Next.js / RSC endpoint accepted a malformed Server-Action or RSC-negotiation request without the expected reject. " + p.Description
	f.Evidence = "payload `" + p.Name + "` (" + p.Method + ") → " + marker
	f.Metadata["vector"] = string(p.Vector)
	f.Metadata["impact"] = string(p.Impact)
	f.Remediation = remediationFor(p.Vector)
	f.References = []string{
		"https://nextjs.org/docs/app/api-reference/functions/server-actions",
		"https://react.dev/reference/rsc/server-components",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A04:2021"},
		[]string{"CWE-1357"},
	)
	return f
}

func mapSeverity(i Impact) core.Severity {
	switch i {
	case ImpactRCE:
		return core.SeverityCritical
	case ImpactPrivilegeEscalation, ImpactAuthBypass:
		return core.SeverityHigh
	case ImpactCachePoison, ImpactStateCorruption:
		return core.SeverityHigh
	case ImpactComponentLeak, ImpactInfoLeak:
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

func remediationFor(v Vector) string {
	switch v {
	case VectorActionIDConfusion:
		return "Bind Server Actions to the route segment that declares them; reject calls where the route in the URL doesn't match the action's declaring route. Rotate action IDs on every deploy so stale IDs from old builds stop resolving."
	case VectorPayloadShape:
		return "Validate Server-Action arguments server-side with a strict schema (zod/yup). Never trust the flight reviver's reconstructed shape; recursively check `Object.hasOwn` rather than relying on prototype lookup."
	case VectorHeaderInjection:
		return "Treat Next-Router-State-Tree and Next-Url as untrusted user input. Enforce auth on every route segment independently, including parallel routes (@modal, @sidebar, …)."
	case VectorCacheKey:
		return "Include the auth cookie / user identifier in the cache key for any response that varies by user. The default CDN normalisation drops these — explicit `Vary` plus a key-deriving function is required."
	case VectorComponentLeak:
		return "Enforce route-level auth on parallel route slots. The intercepting-route mechanism in App Router does NOT inherit the host route's auth check."
	case VectorActionReplay:
		return "Bind Server Actions to the issuing session via a per-session token that the action validates. Action-ID signing alone is not sufficient; the action must check the caller's identity against the data it mutates."
	}
	return "Validate Server-Action payload shape and bind actions to issuing session + declaring route."
}
