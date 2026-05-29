package xfs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector wraps Analyze in the scanner-side Detector convention.
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

// DetectOptions tunes the active probe.
type DetectOptions struct {
	Timeout      time.Duration
	MaxBodyBytes int64 // body cap for framebuster detection (default 256 KiB)
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second, MaxBodyBytes: 256 << 10}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Analysis   Result
	Findings   []*core.Finding
	Vulnerable bool
}

// Detect performs one GET, evaluates framing exposure, and emits
// one Finding when the page is Frameable.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 256 << 10
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("xfs: build request: %w", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xfs: do request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	analysis := Analyze(resp.Header, body)
	result := &DetectionResult{URL: target, Analysis: analysis, Vulnerable: analysis.Frameable}
	if analysis.Frameable {
		result.Findings = append(result.Findings, d.toFinding(target, analysis))
	}
	return result, nil
}

func (d *Detector) toFinding(target string, a Result) *core.Finding {
	f := core.NewFinding("clickjacking_exposure", mapSeverity(a.Severity))
	f.Tool = "xfs"
	f.URL = target
	f.Title = "Clickjacking / Cross-Frame Scripting exposure"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The page can be framed by an attacker-controlled origin, enabling clickjacking and cross-frame UI confusion. " +
		"Modern browsers honor CSP frame-ancestors and X-Frame-Options DENY/SAMEORIGIN; ALLOW-FROM is deprecated and ignored. " +
		"JS framebusters are not reliable: they can be defeated with sandbox iframes."
	if len(a.Reasons) > 0 {
		f.Evidence = a.Reasons[0]
		for _, r := range a.Reasons[1:] {
			f.Evidence += "; " + r
		}
	}
	f.Metadata["protection"] = string(a.Protection)
	f.Remediation = "Add `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` for same-origin embedding). " +
		"Optionally add `X-Frame-Options: DENY` for legacy browser fallback. Do not rely on JS framebusters."
	f.References = []string{
		"https://owasp.org/www-community/attacks/Clickjacking",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-CLNT-09"},
		[]string{"A05:2021"},
		[]string{"CWE-1021"},
	)
	return f
}

func mapSeverity(s Severity) core.Severity {
	switch s {
	case SeverityHigh:
		return core.SeverityHigh
	case SeverityMedium:
		return core.SeverityMedium
	case SeverityLow:
		return core.SeverityLow
	default:
		return core.SeverityInfo
	}
}
