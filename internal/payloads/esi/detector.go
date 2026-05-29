package esi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/payloads/paraminject"
)

// Detector probes URL parameters for Edge Side Includes injection by
// injecting a small set of fingerprint payloads and looking for either
// (a) engine response-header tells, or (b) the payload-induced marker
// in the response body (e.g. $(HTTP_HOST) interpolated, <esi:debug
// reflected, or an iframe/include URL appearing verbatim where the
// engine inlined it).
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
	// MaxPayloadsPerParam caps probes per parameter so a wide URL
	// (?a=1&b=2&c=3) doesn't fan out 13 payloads × params.
	MaxPayloadsPerParam int
	// BaselineCache, when non-nil, shares the baseline GET response with
	// other detectors targeting the same URL. Per-payload fetches are
	// never cached — each injected URL is unique by construction.
	BaselineCache *paraminject.Cache
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             10 * time.Second,
		MaxBodyBytes:        128 << 10,
		MaxPayloadsPerParam: 6,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Engine     string // detected engine via fingerprint, "" if none
	Findings   []*core.Finding
	Vulnerable bool
}

// Detect injects ESI payloads into each URL parameter and emits a
// finding whenever a payload's marker appears in the response that
// wasn't in the baseline.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 128 << 10
	}
	if opts.MaxPayloadsPerParam <= 0 {
		opts.MaxPayloadsPerParam = 6
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("esi: parse URL: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		// Nothing to inject into. The detector is parameter-based.
		return &DetectionResult{URL: target}, nil
	}

	result := &DetectionResult{URL: target}

	// Engine fingerprint preflight: passive header check on the baseline
	// response. Used to score confidence on each subsequent finding.
	if eng := d.fingerprintEngine(ctx, target, opts); eng != "" {
		result.Engine = eng
	}

	baseline, _, err := d.cachedFetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("esi: baseline: %w", err)
	}

	payloads := GetPayloads()
	if opts.MaxPayloadsPerParam > 0 && len(payloads) > opts.MaxPayloadsPerParam {
		payloads = payloads[:opts.MaxPayloadsPerParam]
	}

	seen := map[string]bool{} // param|payload de-dup
	for paramName := range params {
		for _, p := range payloads {
			key := paramName + "|" + p.Value
			if seen[key] {
				continue
			}
			seen[key] = true

			injectedURL := injectParam(u, paramName, p.Value)
			body, _, err := d.fetch(ctx, injectedURL, opts)
			if err != nil {
				continue
			}
			marker := evaluationMarker(p, body, baseline)
			if marker == "" {
				continue
			}
			result.Findings = append(result.Findings, d.toFinding(target, paramName, p, marker, result.Engine))
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// fingerprintEngine fires a single debug-vars probe and matches against
// the known engine response tells.
func (d *Detector) fingerprintEngine(ctx context.Context, target string, opts DetectOptions) string {
	resp, err := d.head(ctx, target, opts)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	for _, fp := range GetEngineFingerprints() {
		for name, contains := range fp.Headers {
			v := resp.Header.Get(name)
			if v == "" {
				continue
			}
			if contains == "" || strings.Contains(strings.ToLower(v), strings.ToLower(contains)) {
				return fp.Engine
			}
		}
	}
	return ""
}

// fetch wraps paraminject.Fetch with this detector's per-request
// timeout. The shared helper handles body-capping and response read.
func (d *Detector) fetch(ctx context.Context, target string, opts DetectOptions) (string, *http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return paraminject.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
}

// cachedFetch is the baseline-fetch variant that consults the per-scan
// baseline cache when set. Per-payload fetches go through fetch (above)
// because each injected URL is unique by construction.
func (d *Detector) cachedFetch(ctx context.Context, target string, opts DetectOptions) (string, *http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return opts.BaselineCache.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
}

// head is fetch's HEAD-only variant for the engine fingerprint preflight.
func (d *Detector) head(ctx context.Context, target string, opts DetectOptions) (*http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodHead, target, nil)
	if err != nil {
		return nil, err
	}
	return d.client.Do(req)
}

// evaluationMarker decides whether a response shows the ESI payload
// fired. Three signals (in priority order):
//   - The payload's explicit Marker substring appears in the response
//     and was NOT in the baseline (engine evaluated, output reflected).
//   - The payload's raw value is absent (engine consumed/stripped it),
//     but the baseline includes neither the payload value nor its
//     marker — confirming the engine recognised and processed the tag.
//   - The OAST callback path appears in the response (rare; left for
//     out-of-band collection by the scanner's OOB client).
func evaluationMarker(p Payload, body, baseline string) string {
	if p.Marker != "" && strings.Contains(body, p.Marker) && !strings.Contains(baseline, p.Marker) {
		return "marker reflected: " + p.Marker
	}
	// If the engine accepted the tag and stripped it cleanly, the raw
	// value should NOT appear in the response — and the baseline didn't
	// contain that string either (so it's not a pre-existing fragment).
	// This is the most signal-rich tell after the explicit marker.
	if !strings.Contains(body, p.Value) && !strings.Contains(baseline, p.Value) && reflectsAttribute(p.Value, body) {
		return "tag accepted (stripped from output, attribute reflected)"
	}
	return ""
}

// reflectsAttribute is a heuristic: did the response include any href/
// src/url attribute that points at the payload's include URL? When ESI
// inlines, the URL often surfaces as a relative link or as inserted
// content.
func reflectsAttribute(value, body string) bool {
	// Pull any quoted strings inside the payload and look for them in body.
	for _, q := range []string{`"`, `'`} {
		i := strings.Index(value, q)
		if i < 0 {
			continue
		}
		j := strings.Index(value[i+1:], q)
		if j <= 0 {
			continue
		}
		inner := value[i+1 : i+1+j]
		if len(inner) > 8 && strings.Contains(body, inner) {
			return true
		}
	}
	return false
}

// injectParam is a thin wrapper around paraminject.InjectParam kept
// only so internal tests that call injectParam() compile unchanged.
func injectParam(u *url.URL, name, value string) string {
	return paraminject.InjectParam(u, name, value)
}

func (d *Detector) toFinding(target, paramName string, p Payload, marker, engine string) *core.Finding {
	conf := core.ConfidenceMedium
	if engine != "" {
		conf = core.ConfidenceHigh
	}
	f := core.NewFinding("esi_injection", core.SeverityHigh)
	f.Tool = "esi"
	f.URL = target
	f.Parameter = paramName
	f.Title = "Edge Side Includes (ESI) injection"
	f.Confidence = conf
	f.Description = "A user-controlled value is reflected into a response that an edge processor (Akamai, Varnish, Fastly, Squid) parses as ESI markup. " +
		"This yields SSRF from the CDN's network position (often inside the operator's trust boundary), cookie exfiltration via include URLs, and on Akamai stylesheet-include RCE."
	f.Evidence = "payload `" + paraminject.Truncate(p.Value, 80) + "` → " + marker
	f.Metadata["technique"] = p.Description
	if engine != "" {
		f.Metadata["edge_engine"] = engine
	}
	f.Remediation = "Treat user input on edge-cached responses as code. Either disable ESI parsing on routes that reflect untrusted data, or HTML-encode `<` and `&` before reflection."
	f.References = []string{
		"https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/",
		"https://owasp.org/www-community/attacks/Edge_Side_Includes_Injection",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-15"},
		[]string{"A03:2021"},
		[]string{"CWE-94"},
	)
	return f
}

