package cachekey

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector probes for cache-key parser-divergence quirks.
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "cachekey" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Probes for cache-key parser-divergence: semicolon param cloaking, duplicate-param pollution, and encoded-slash normalization quirks that let an attacker poison cache entries for legitimate URLs."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	// Timeout per request.
	Timeout time.Duration
}

// DefaultOptions returns recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second}
}

// DetectionResult carries findings and the list of techniques that
// triggered.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Techniques []string
}

// Detect runs the three probes against target. Each probe is
// independent.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:   make([]*core.Finding, 0),
		Techniques: make([]string, 0),
	}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}

	u, err := url.Parse(target)
	if err != nil {
		return res, fmt.Errorf("cachekey: parse: %w", err)
	}

	if u.RawQuery != "" {
		// Query-string probes only fire when there's at least one
		// existing parameter to cloak/duplicate. Without that, the
		// signal is too noisy.
		if d.probeSemicolonCloaking(ctx, u, opts) {
			res.Techniques = append(res.Techniques, "semicolon_param_cloaking")
			res.Findings = append(res.Findings, buildFinding("semicolon_param_cloaking", target))
		}
		if d.probeDuplicateParam(ctx, u, opts) {
			res.Techniques = append(res.Techniques, "duplicate_param_pollution")
			res.Findings = append(res.Findings, buildFinding("duplicate_param_pollution", target))
		}
	}

	if d.probeEncodedSlash(ctx, u, opts) {
		res.Techniques = append(res.Techniques, "encoded_slash_normalization")
		res.Findings = append(res.Findings, buildFinding("encoded_slash_normalization", target))
	}

	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// probeSemicolonCloaking sends the original URL then a mutated URL
// with a semicolon-separated duplicate of the first parameter, and
// reports a hit when the app processed the cloaked value as a distinct
// parameter (marker present *and* baseline value gone).
func (d *Detector) probeSemicolonCloaking(ctx context.Context, u *url.URL, opts DetectOptions) bool {
	param, value, ok := firstParam(u)
	if !ok {
		return false
	}
	poison := "ASSAYCACHEKEYPOISON"
	baseline, err := d.get(ctx, u.String(), opts.Timeout)
	if err != nil {
		return false
	}
	mutated := *u
	q := mutated.Query()
	q.Set(param, q.Get(param))
	mutated.RawQuery = q.Encode() + ";" + param + "=" + poison
	probe, err := d.get(ctx, mutated.String(), opts.Timeout)
	if err != nil {
		return false
	}
	return cloakingHit(baseline, probe, value, poison)
}

// probeDuplicateParam sends the original URL then a mutated URL with
// a second occurrence of the same parameter. A hit means the app's
// chosen occurrence differs from what a cache would key on.
func (d *Detector) probeDuplicateParam(ctx context.Context, u *url.URL, opts DetectOptions) bool {
	param, value, ok := firstParam(u)
	if !ok {
		return false
	}
	poison := "ASSAYCACHEKEYPOISON"
	baseline, err := d.get(ctx, u.String(), opts.Timeout)
	if err != nil {
		return false
	}
	mutated := *u
	mutated.RawQuery = u.RawQuery + "&" + param + "=" + poison
	probe, err := d.get(ctx, mutated.String(), opts.Timeout)
	if err != nil {
		return false
	}
	return cloakingHit(baseline, probe, value, poison)
}

// cloakingHit returns true only when the probe response shows the
// app picked the *poisoned* value over the baseline value — i.e., the
// poison marker appears in the probe body, and the baseline value no
// longer does. This is the precondition for cache poisoning: cache
// keys on baseline (since `;...` or duplicate `&...` is normalized
// away upstream) but app processed the poison.
func cloakingHit(baseline, probe *scanhttp.Response, baselineValue, poison string) bool {
	if baseline == nil || probe == nil {
		return false
	}
	if !strings.Contains(probe.Body, poison) {
		return false
	}
	if strings.Contains(baseline.Body, poison) {
		return false
	}
	// If the probe still surfaces the original baseline value the app
	// likely treated the cloak as part of a single combined string
	// (e.g., `id=baseline;id=POISON` as one value) — that's not a
	// parser divergence, that's just reflection.
	if baselineValue != "" && strings.Contains(probe.Body, baselineValue) {
		return false
	}
	return true
}

// probeEncodedSlash compares `/a/b` (or whatever the path is) against
// the same path with one literal `/` replaced by `%2F`. Different
// responses mean the backend distinguishes them — a cache-key
// smuggling primitive.
func (d *Detector) probeEncodedSlash(ctx context.Context, u *url.URL, opts DetectOptions) bool {
	if u.Path == "" || !strings.Contains(u.Path, "/") {
		return false
	}
	// Replace the first internal '/' with %2F. Skip leading slash.
	idx := strings.Index(u.Path[1:], "/")
	if idx < 0 {
		return false
	}
	idx++ // adjust for the trimmed leading slash
	encoded := *u
	encoded.RawPath = u.Path[:idx] + "%2F" + u.Path[idx+1:]
	encoded.Path = u.Path // keep Path so net/url retains RawPath semantics

	baseline, err := d.get(ctx, u.String(), opts.Timeout)
	if err != nil {
		return false
	}
	probe, err := d.get(ctx, encoded.String(), opts.Timeout)
	if err != nil {
		return false
	}
	return baseline.Body != probe.Body || baseline.StatusCode != probe.StatusCode
}

// firstParam returns the name and value of the first query parameter
// in u, plus an ok flag.
func firstParam(u *url.URL) (string, string, bool) {
	q := u.Query()
	if len(q) == 0 {
		return "", "", false
	}
	// url.Values is unordered, so re-parse RawQuery to pick the first
	// occurrence in source order.
	for _, pair := range strings.Split(u.RawQuery, "&") {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		return pair[:eq], pair[eq+1:], true
	}
	return "", "", false
}

func (d *Detector) get(ctx context.Context, target string, timeout time.Duration) (*scanhttp.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.client.Get(reqCtx, target)
}

// severityFor maps a technique label to its severity. Exposed for
// tests; the public Detector uses it inside buildFinding.
func severityFor(technique string) core.Severity {
	switch technique {
	case "semicolon_param_cloaking", "duplicate_param_pollution",
		"encoded_slash_normalization":
		return core.SeverityMedium
	default:
		return core.SeverityLow
	}
}

func buildFinding(technique, target string) *core.Finding {
	titles := map[string]string{
		"semicolon_param_cloaking":    "Cache key parser divergence — semicolon-separated parameter cloaking",
		"duplicate_param_pollution":   "Cache key parser divergence — duplicate-parameter pollution",
		"encoded_slash_normalization": "Cache key parser divergence — encoded slash normalization",
	}
	descs := map[string]string{
		"semicolon_param_cloaking":    "The application parses semicolon-separated parameters (?id=A;id=B) and returned a response that reflected the cloaked second value. Cache appliances almost universally treat the entire ;... segment as part of the first value (or strip it before keying), so the cache will key on ?id=A while the app processes ?id=B. An attacker can poison the cache for any legitimate URL by injecting a ;param=evil cloak.",
		"duplicate_param_pollution":   "The application's chosen parameter occurrence (typically the last) differs from what a cache would key on (typically the first). ?id=A&id=B routes to one entry in the cache and a different entry in the application — the cache-key smuggling precondition for poisoning.",
		"encoded_slash_normalization": "The backend returns different responses for /a/b and /a%2Fb. Caches that URL-normalize before keying merge both into a single entry, but the backend routes them to distinct handlers — letting an attacker request /a%2Fb to populate the cache slot used by the legitimate /a/b URL.",
	}
	f := core.NewFinding("Cache key parser divergence", severityFor(technique))
	f.Title = titles[technique]
	f.URL = target
	f.Tool = "cachekey-detector"
	f.Description = descs[technique]
	f.Evidence = "paired-request differential — baseline and " + technique + " probe diverged in body or status"
	f.Remediation = "Align the cache-key parser and the application parser. Prefer keying on the fully-decoded canonical URL, configure the application to reject duplicate-parameter forms (or pick the same occurrence the cache uses), and disable semicolon-as-separator parsing on backends behind a CDN."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-15"},
		[]string{"A05:2025"},
		[]string{"CWE-444"},
	)
	return f
}
