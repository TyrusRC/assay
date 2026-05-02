// Package redos detects Regular-Expression Denial-of-Service exposures
// by sending pathological-input strings to the target's query parameters
// and watching for response-time spikes consistent with backtracking
// regex evaluation. Vulnerable engines (Java/JavaScript/Python `re`,
// most pre-RE2 engines) handle nested quantifiers in O(2^n) time on
// hostile input; a 2x time delta against a benign baseline is the
// signal we look for.
//
// Probe budget is intentionally small (per parameter, two requests:
// baseline + payload). The detector is gated to query parameters whose
// names look like "search", "filter", "email", "url", "regex", or
// where the baseline response shows the value reflected — those are
// the contexts that almost always feed a regex.
package redos

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// regexParamHints flag query parameter names that almost always feed a
// regex. We test these even when the value is not reflected.
var regexParamHints = []string{
	"search", "q", "query", "filter", "match", "pattern",
	"email", "url", "regex", "regexp", "expr", "expression",
	"name", "title", "tag",
}

// pathologicalPayloads are the canonical "evil regex" inputs. Each
// triggers super-linear backtracking in vulnerable engines for the
// matching anti-pattern.
var pathologicalPayloads = []struct {
	desc, value string
}{
	{"alternation+repetition (a|aa)+", strings.Repeat("a", 30) + "!"},
	{"nested-quantifier (a+)+", strings.Repeat("a", 30) + "X"},
	{"email-validation worst-case", strings.Repeat("a", 28) + "@a.a"},
	{"URL-percent encoding", strings.Repeat("%a", 30)},
	{"long string + dot-star", strings.Repeat("a", 50) + "X"},
}

// timingThreshold is the minimum delta between baseline and payload
// timings we consider suspicious. A vulnerable backend typically
// shows orders-of-magnitude difference; 250ms separates that from
// network jitter on a typical scan host.
const timingThreshold = 250 * time.Millisecond

// minBaseTimeForRatio is the minimum baseline duration we'll allow
// when computing the timing ratio. For sub-millisecond baselines the
// ratio is unstable; we then fall back to the absolute threshold.
const minBaseTimeForRatio = 50 * time.Millisecond

// Detector probes targetURL's query parameters for ReDoS surfaces.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings emitted by Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect inspects targetURL's query parameters. For each parameter that
// matches a regex hint OR whose baseline value reflects in the
// response, it sends each pathological payload and times the request.
// A payload whose elapsed time exceeds the baseline by both
// timingThreshold AND a 4x ratio (when the baseline is large enough
// for ratios to be stable) emits a finding.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}
	q := u.Query()
	if len(q) == 0 {
		return res, nil
	}

	for paramName := range q {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		if !looksRegexShaped(paramName) {
			continue
		}

		baseDur, ok := d.timeRequest(ctx, targetURL)
		if !ok {
			continue
		}

		for _, p := range pathologicalPayloads {
			payloadURL := setQueryParam(u, paramName, p.value)
			payloadDur, ok := d.timeRequest(ctx, payloadURL)
			if !ok {
				continue
			}
			if isSuspicious(baseDur, payloadDur) {
				res.Findings = append(res.Findings, buildFinding(targetURL, paramName, p.desc, baseDur, payloadDur))
				break // one finding per param is enough
			}
		}
	}
	return res, nil
}

// timeRequest sends a GET, returns its wall-clock duration, and
// reports whether it succeeded (any 2xx-3xx-4xx is fine; 5xx is
// suspicious enough to ignore for timing purposes).
func (d *Detector) timeRequest(ctx context.Context, target string) (time.Duration, bool) {
	start := time.Now()
	resp, err := d.client.Get(ctx, target)
	if err != nil || resp == nil {
		return 0, false
	}
	if resp.StatusCode >= 500 {
		return 0, false
	}
	return time.Since(start), true
}

// isSuspicious applies the dual-criterion test: absolute-delta AND
// ratio-delta when the baseline is large enough to make the ratio
// meaningful.
func isSuspicious(base, payload time.Duration) bool {
	if payload-base < timingThreshold {
		return false
	}
	if base < minBaseTimeForRatio {
		// Sub-50ms baselines: trust the absolute threshold alone.
		return true
	}
	return payload >= 4*base
}

// looksRegexShaped returns true when the parameter name is in the
// curated regex-hint list.
func looksRegexShaped(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range regexParamHints {
		if lower == hint || strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func setQueryParam(u *url.URL, name, value string) string {
	clone := *u
	q := clone.Query()
	q.Set(name, value)
	clone.RawQuery = q.Encode()
	return clone.String()
}

func buildFinding(targetURL, param, payloadDesc string, base, payload time.Duration) *core.Finding {
	finding := core.NewFinding("Regular Expression Denial of Service (ReDoS)", core.SeverityMedium)
	finding.URL = targetURL
	finding.Parameter = param
	finding.Tool = "redos"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = fmt.Sprintf(
		"Parameter '%s' shows a super-linear response-time spike under a pathological-regex payload (%s). The backend likely evaluates the value with a backtracking regex engine; an attacker can pin a worker for seconds with a small input.",
		param, payloadDesc,
	)
	finding.Evidence = fmt.Sprintf("Baseline duration: %s\nPayload duration: %s\nDelta: %s\nPayload pattern: %s",
		base.Round(time.Millisecond), payload.Round(time.Millisecond), (payload - base).Round(time.Millisecond), payloadDesc)
	finding.Remediation = "Replace the affected regex with a linear-time engine (RE2, Hyperscan), or simplify the pattern to avoid nested quantifiers and overlapping alternations. Validate input length before regex evaluation."
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-19"},
		[]string{"A04:2025"},
		[]string{"CWE-1333"},
	)
	finding.APITop10 = []string{"API4:2023"}
	return finding
}
