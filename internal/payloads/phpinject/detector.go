package phpinject

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

// Detector probes URL parameters for PHP user-controlled-sink
// vulnerabilities by injecting PHP-sink payloads (extract overwrite,
// assert string-eval, preg_replace /e modifier, include() wrapper
// chains) and matching the response against the PHP error fingerprint
// set. Mirrors AWVS PHP_User_Controlled_Vulns.script.
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
	Timeout             time.Duration
	MaxBodyBytes        int64
	MaxPayloadsPerParam int
	// ConfirmedPHPOnly gates high-impact payloads (RCE-class sinks)
	// behind a confirmed PHP fingerprint in the baseline response.
	ConfirmedPHPOnly bool
	// BaselineCache, when non-nil, shares the baseline GET response
	// with other detectors targeting the same URL.
	BaselineCache *paraminject.Cache
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             10 * time.Second,
		MaxBodyBytes:        128 << 10,
		MaxPayloadsPerParam: 8,
		ConfirmedPHPOnly:    true,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL         string
	PHPDetected bool
	Findings    []*core.Finding
	Vulnerable  bool
}

// Detect injects PHP-sink payloads into URL parameters.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 128 << 10
	}
	if opts.MaxPayloadsPerParam <= 0 {
		opts.MaxPayloadsPerParam = 8
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("phpinject: parse URL: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		return &DetectionResult{URL: target}, nil
	}

	baselineBody, baselineResp, err := d.cachedFetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("phpinject: baseline: %w", err)
	}

	result := &DetectionResult{URL: target}
	if isPHPResponse(baselineResp, baselineBody) {
		result.PHPDetected = true
	}

	payloads := GetPayloads()
	seen := map[string]bool{}
	emitted := 0
	for paramName := range params {
		fired := 0
		for _, p := range payloads {
			if fired >= opts.MaxPayloadsPerParam {
				break
			}
			key := paramName + "|" + p.Value
			if seen[key] {
				continue
			}
			seen[key] = true

			if opts.ConfirmedPHPOnly && !result.PHPDetected && isHighImpactSink(p.Sink) {
				continue
			}

			injectedURL := injectParam(u, paramName, p.Value)
			body, _, err := d.fetch(ctx, injectedURL, opts)
			if err != nil {
				continue
			}
			marker := evaluationMarker(body, baselineBody)
			if marker == "" {
				continue
			}
			if !result.PHPDetected {
				result.PHPDetected = true
			}
			result.Findings = append(result.Findings, d.toFinding(target, paramName, p, marker, result.PHPDetected))
			emitted++
			fired++
		}
	}
	result.Vulnerable = emitted > 0
	return result, nil
}

func (d *Detector) fetch(ctx context.Context, target string, opts DetectOptions) (string, *http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return paraminject.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
}

// cachedFetch routes the baseline through the per-scan cache when set.
func (d *Detector) cachedFetch(ctx context.Context, target string, opts DetectOptions) (string, *http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return opts.BaselineCache.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
}

// isPHPResponse reports whether the baseline shows PHP fingerprints in
// either response headers (X-Powered-By, Server) or body markers.
func isPHPResponse(resp *http.Response, body string) bool {
	if resp != nil {
		if v := resp.Header.Get("X-Powered-By"); strings.Contains(strings.ToLower(v), "php") {
			return true
		}
		if v := resp.Header.Get("Server"); strings.Contains(strings.ToLower(v), "php") {
			return true
		}
		for _, c := range resp.Header.Values("Set-Cookie") {
			if strings.HasPrefix(strings.ToUpper(c), "PHPSESSID=") {
				return true
			}
		}
	}
	for _, p := range GetErrorPatterns() {
		if strings.Contains(body, p) {
			return true
		}
	}
	// Tell-tale phpinfo dump.
	if strings.Contains(body, "phpinfo()") || strings.Contains(body, "PHP Version") {
		return true
	}
	return false
}

func evaluationMarker(body, baseline string) string {
	// Direct phpinfo() output is the strongest signal.
	if strings.Contains(body, "PHP Version") && !strings.Contains(baseline, "PHP Version") {
		return "phpinfo output: PHP Version"
	}
	for _, p := range GetErrorPatterns() {
		if strings.Contains(body, p) && !strings.Contains(baseline, p) {
			return "error pattern: " + p
		}
	}
	return ""
}

func isHighImpactSink(s Sink) bool {
	switch s {
	case SinkAssert, SinkPregReplace, SinkCallUserFunc, SinkCreateFunction, SinkInclude, SinkUnsafeUnser:
		return true
	}
	return false
}

func injectParam(u *url.URL, name, value string) string {
	return paraminject.InjectParam(u, name, value)
}

func (d *Detector) toFinding(target, paramName string, p Payload, marker string, phpConfirmed bool) *core.Finding {
	sev := mapSeverity(p.Sink)
	conf := core.ConfidenceMedium
	if phpConfirmed {
		conf = core.ConfidenceHigh
	}
	f := core.NewFinding("php_"+string(p.Sink), sev)
	f.Tool = "phpinject"
	f.URL = target
	f.Parameter = paramName
	f.Title = "PHP user-controlled sink: " + string(p.Sink)
	f.Confidence = conf
	f.Description = "A user-controlled value reaches a dangerous PHP function (" + string(p.Sink) + "). " +
		p.Description
	f.Evidence = "payload `" + paraminject.Truncate(p.Value, 80) + "` → " + marker
	f.Metadata["sink"] = string(p.Sink)
	if p.MaxPHP != "" {
		f.Metadata["max_php"] = p.MaxPHP
	}
	if p.MinPHP != "" {
		f.Metadata["min_php"] = p.MinPHP
	}
	f.Remediation = remediationFor(p.Sink)
	f.References = []string{
		"https://owasp.org/www-community/attacks/Code_Injection",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},
		[]string{"A03:2021"},
		[]string{"CWE-94"},
	)
	return f
}

func mapSeverity(s Sink) core.Severity {
	switch s {
	case SinkAssert, SinkPregReplace, SinkCallUserFunc, SinkCreateFunction, SinkInclude, SinkUnsafeUnser:
		return core.SeverityCritical
	case SinkObjectInst:
		return core.SeverityHigh
	default:
		return core.SeverityMedium
	}
}

func remediationFor(s Sink) string {
	switch s {
	case SinkExtract:
		return "Pass EXTR_SKIP to extract() and never call it on $_GET / $_POST. Prefer explicit variable assignment from a known-shape array."
	case SinkAssert:
		return "Remove assert() from production code paths. Pass only booleans, never strings; PHP 7.0+ deprecates string-eval and PHP 8.0 removes it."
	case SinkPregReplace:
		return "Use preg_replace_callback() with a static replacement function. The /e modifier was removed in PHP 7."
	case SinkCallUserFunc, SinkCreateFunction:
		return "Allowlist callable names server-side; never pass $_GET / $_POST directly. create_function() is removed in PHP 8."
	case SinkInclude:
		return "Validate include/require paths against an allowlist. Disable allow_url_include and the data:// + expect:// + phar:// wrappers in production."
	case SinkUnsafeUnser:
		return "Replace unserialize() with json_decode(); if PHP serialisation is unavoidable, pass [\"allowed_classes\" => []]."
	case SinkObjectInst:
		return "Allowlist class names server-side. Dynamic instantiation of SoapClient or SimpleXMLElement from user input enables SSRF and XXE."
	}
	return "Validate user input against an allowlist before passing it into PHP runtime sinks."
}

