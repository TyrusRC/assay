package nodejsinject

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

// Detector probes URL parameters for Server-Side JavaScript Injection
// targeting Node.js sinks (eval, Function constructor, vm sandbox
// escape via constructor.constructor, child_process). Combines three
// detection signals: Node-class error patterns in the response, the
// payload's marker reflected in the body, and time-blind sleep
// (TypeBlind / "sleep" payloads cause a measurable delay).
//
// Mirrors AWVS NodeJs_Injection.script.
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
	// TimeBlindThreshold is the minimum delay (probe minus baseline)
	// considered a vulnerability for sleep-based payloads. Defaults
	// to 3s — matches the typical `sleep 5` payload, less the
	// network-noise floor.
	TimeBlindThreshold time.Duration
	// ConfirmedNodeOnly gates RCE-class payloads behind a confirmed
	// Node runtime fingerprint in the baseline.
	ConfirmedNodeOnly bool
	// NOTE: this detector deliberately does NOT honor a baseline cache.
	// The time-blind probe requires a freshly-measured baseline
	// duration; a cached body returns near-zero lookup time and
	// invalidates the delta comparison. The body cost of one extra
	// baseline GET per scan is a tolerable trade for accurate timing.
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             15 * time.Second,
		MaxBodyBytes:        128 << 10,
		MaxPayloadsPerParam: 8,
		TimeBlindThreshold:  3 * time.Second,
		ConfirmedNodeOnly:   true,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL          string
	NodeDetected bool
	Findings     []*core.Finding
	Vulnerable   bool
}

// Detect runs the injection probe.
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
	if opts.TimeBlindThreshold <= 0 {
		opts.TimeBlindThreshold = 3 * time.Second
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("nodejsinject: parse URL: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		return &DetectionResult{URL: target}, nil
	}

	baselineBody, baselineDur, baselineResp, err := d.timedFetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("nodejsinject: baseline: %w", err)
	}

	result := &DetectionResult{URL: target}
	if isNodeResponse(baselineResp, baselineBody) {
		result.NodeDetected = true
	}

	payloads := GetPayloads()
	seen := map[string]bool{}
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

			if opts.ConfirmedNodeOnly && !result.NodeDetected && p.Impact == ImpactRCE {
				continue
			}

			injectedURL := injectParam(u, paramName, p.Value)
			body, dur, _, err := d.timedFetch(ctx, injectedURL, opts)
			if err != nil {
				continue
			}
			marker := evaluationMarker(p, body, baselineBody, dur, baselineDur, opts.TimeBlindThreshold)
			if marker == "" {
				continue
			}
			if !result.NodeDetected {
				result.NodeDetected = true
			}
			result.Findings = append(result.Findings, d.toFinding(target, paramName, p, marker, result.NodeDetected))
			fired++
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

func (d *Detector) timedFetch(ctx context.Context, target string, opts DetectOptions) (string, time.Duration, *http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	start := time.Now()
	body, resp, err := paraminject.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
	return body, time.Since(start), resp, err
}

func isNodeResponse(resp *http.Response, body string) bool {
	if resp != nil {
		if v := resp.Header.Get("X-Powered-By"); v != "" {
			lv := strings.ToLower(v)
			if strings.Contains(lv, "express") || strings.Contains(lv, "node") || strings.Contains(lv, "next.js") {
				return true
			}
		}
		if v := resp.Header.Get("Server"); v != "" {
			lv := strings.ToLower(v)
			if strings.Contains(lv, "node") {
				return true
			}
		}
	}
	for _, p := range GetErrorPatterns() {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

// evaluationMarker decides whether a payload landed:
//   - For TypeBlind sleep payloads: a response-time delta exceeding the
//     TimeBlindThreshold (baseline-corrected).
//   - For all payloads: a Node error pattern appearing in the response
//     that was NOT in the baseline.
func evaluationMarker(p Payload, body, baseline string, dur, baselineDur, threshold time.Duration) string {
	if strings.Contains(strings.ToLower(p.Technique), "sleep") || strings.Contains(strings.ToLower(p.Technique), "time_based") {
		if dur-baselineDur >= threshold {
			return fmt.Sprintf("time delta: %v (baseline %v, threshold %v)", dur-baselineDur, baselineDur, threshold)
		}
	}
	if hit := paraminject.FirstNewMatch(body, baseline, GetErrorPatterns()); hit != "" {
		return "error pattern: " + hit
	}
	return ""
}

func injectParam(u *url.URL, name, value string) string {
	return paraminject.InjectParam(u, name, value)
}

func (d *Detector) toFinding(target, paramName string, p Payload, marker string, nodeConfirmed bool) *core.Finding {
	sev := mapSeverity(p.Impact)
	conf := core.ConfidenceMedium
	if nodeConfirmed {
		conf = core.ConfidenceHigh
	}
	f := core.NewFinding("nodejs_ssji_"+string(p.Impact), sev)
	f.Tool = "nodejsinject"
	f.URL = target
	f.Parameter = paramName
	f.Title = "Server-Side JavaScript Injection: " + p.Technique
	f.Confidence = conf
	f.Description = "A user-controlled value reaches a Node.js code-execution sink. " + p.Description
	f.Evidence = "payload `" + paraminject.Truncate(p.Value, 100) + "` → " + marker
	f.Metadata["technique"] = p.Technique
	f.Metadata["impact"] = string(p.Impact)
	f.Remediation = "Never call eval, new Function, vm.runInThisContext, vm.runInContext, or setTimeout(string, …) on tainted strings. " +
		"For sandboxed evaluation, use a hardened runtime (isolated-vm) instead of the built-in vm module — the constructor-chain escape is unfixable in vm."
	f.References = []string{
		"https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_07A-2_Staicu_paper.pdf",
		"https://owasp.org/www-community/attacks/Server_Side_JavaScript_Injection",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},
		[]string{"A03:2021"},
		[]string{"CWE-95"},
	)
	return f
}

func mapSeverity(i Impact) core.Severity {
	switch i {
	case ImpactRCE:
		return core.SeverityCritical
	case ImpactSandboxEsc:
		return core.SeverityHigh
	case ImpactInfoLeak:
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

