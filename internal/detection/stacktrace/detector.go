package stacktrace

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// DetectOptions tunes the DetectFromBaseline probe.
type DetectOptions struct {
	// Timeout caps each individual probe. Zero means use the client's
	// default timeout.
	Timeout time.Duration
	// CustomProbes is an optional list of raw query strings (e.g.
	// "?foo=bar") or path suffixes appended to the target URL. They
	// run after the built-in probes.
	CustomProbes []string
}

// DetectionResult captures the outcome of DetectFromBaseline.
type DetectionResult struct {
	Vulnerable         bool
	Findings           []*core.Finding
	DetectedFrameworks []string
}

// Detector probes a target for leaked framework stack traces.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the provided HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// builtinProbes is the curated set of malformed-input probes. Each
// entry is a (method, path-or-query suffix, body, content-type) tuple
// designed to coax an unhandled exception out of common frameworks.
type probe struct {
	method      string
	suffix      string // appended to URL (query string or extra path)
	body        string
	contentType string
}

var builtinProbes = []probe{
	// Oversized query parameter — many frameworks trip on unexpected
	// type coercion or length limits.
	{method: "GET", suffix: "?q=" + strings.Repeat("A", 8192)},
	// NaN coercion — Spring/Express commonly throw NumberFormatException /
	// TypeError when a numeric parser sees this.
	{method: "GET", suffix: "?_=NaN"},
	// Path-traversal markers — even when filtered, the filter itself
	// sometimes panics.
	{method: "GET", suffix: "/../../../../etc/passwd"},
	// Malformed JSON body — exercises the JSON parser.
	{method: "POST", body: `{"a":`, contentType: "application/json"},
	// Invalid Content-Type — some servers throw on unknown media types.
	{method: "POST", body: "x=1", contentType: "application/x-not-a-real-type"},
}

// DetectFromBaseline fetches a clean baseline of targetURL, then sends
// each malformed-input probe (built-in plus any CustomProbes). For
// every probe response it scans for framework stack-trace patterns; a
// match that is NOT also present in the baseline body emits a Medium
// information-disclosure finding.
func (d *Detector) DetectFromBaseline(ctx context.Context, targetURL string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{}
	if d.client == nil {
		return res, nil
	}
	if _, err := url.Parse(targetURL); err != nil {
		return res, nil
	}

	probeCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	baseResp, err := d.client.Get(probeCtx, targetURL)
	baselineBody := ""
	if err == nil && baseResp != nil {
		baselineBody = baseResp.Body
	}
	baselineFrameworks := matchedFrameworks(baselineBody)

	seenFrameworks := map[string]struct{}{}
	probes := append([]probe(nil), builtinProbes...)
	for _, custom := range opts.CustomProbes {
		probes = append(probes, probe{method: "GET", suffix: custom})
	}

	for _, p := range probes {
		select {
		case <-probeCtx.Done():
			return res, nil
		default:
		}

		probeURL := joinSuffix(targetURL, p.suffix)
		var resp *skwshttp.Response
		var perr error
		switch p.method {
		case "POST":
			resp, perr = d.client.Do(probeCtx, &skwshttp.Request{
				Method:      "POST",
				URL:         probeURL,
				Body:        p.body,
				ContentType: p.contentType,
			})
		default:
			resp, perr = d.client.Get(probeCtx, probeURL)
		}
		if perr != nil || resp == nil {
			continue
		}

		matches := matchedFrameworks(resp.Body)
		for fw, sample := range matches {
			if _, already := baselineFrameworks[fw]; already {
				continue
			}
			if _, dup := seenFrameworks[fw]; dup {
				continue
			}
			seenFrameworks[fw] = struct{}{}
			res.DetectedFrameworks = append(res.DetectedFrameworks, fw)
			res.Findings = append(res.Findings, buildFinding(targetURL, probeURL, p, fw, sample, resp))
		}
	}
	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// matchedFrameworks returns the set of frameworks whose patterns match
// somewhere in body, keyed by framework name with the first matched
// substring as the value (used as evidence).
func matchedFrameworks(body string) map[string]string {
	out := map[string]string{}
	if body == "" {
		return out
	}
	for _, fp := range frameworkPatterns {
		if _, already := out[fp.Framework]; already {
			continue
		}
		if loc := fp.Pattern.FindStringIndex(body); loc != nil {
			out[fp.Framework] = body[loc[0]:loc[1]]
		}
	}
	return out
}

// joinSuffix appends a probe suffix to a target URL. If the suffix
// starts with "?", it replaces any existing query string. Otherwise
// it's appended to the path.
func joinSuffix(target, suffix string) string {
	if suffix == "" {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target + suffix
	}
	if strings.HasPrefix(suffix, "?") {
		u.RawQuery = strings.TrimPrefix(suffix, "?")
		return u.String()
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(suffix, "/")
	return u.String()
}

func buildFinding(target, probeURL string, p probe, framework, sample string, resp *skwshttp.Response) *core.Finding {
	f := core.NewFinding("Stack Trace Disclosure", core.SeverityMedium)
	f.URL = target
	f.Tool = "stacktrace-detector"
	f.Confidence = core.ConfidenceHigh
	f.Description = fmt.Sprintf(
		"A malformed-input probe coaxed the target into returning a %s stack trace in the HTTP response. Leaked traces reveal internal class names, file paths, library versions and code structure — the exact reconnaissance data an attacker needs to chain into deserialization, path-traversal or known-CVE exploits.",
		framework,
	)
	f.Evidence = fmt.Sprintf(
		"Framework: %s\nProbe: %s %s%s\nMatched fragment: %s\nResponse status: %d",
		framework, p.method, probeURL,
		bodyHint(p.body, p.contentType),
		truncate(sample, 200),
		resp.StatusCode,
	)
	f.Remediation = "Disable verbose error pages in production. Return generic 5xx bodies (`{\"error\":\"internal_server_error\"}`) and log full stack traces server-side only. Verify framework-specific switches: Spring `server.error.include-stacktrace=never`, ASP.NET `<customErrors mode=\"On\">`, Django `DEBUG=False`, PHP `display_errors=Off`, Express `app.disable('x-powered-by')` + custom error middleware."
	f.WithOWASPMapping(
		[]string{"WSTG-ERRH-02"},
		[]string{"A02:2025"},
		[]string{"CWE-209", "CWE-200"},
	)
	return f
}

func bodyHint(body, ct string) string {
	if body == "" {
		return ""
	}
	return fmt.Sprintf("\nBody (%s): %s", ct, truncate(body, 80))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
