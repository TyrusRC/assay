package wafdetect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector is the scanner-side wrapper around the pure passive
// fingerprinter. It issues one GET request, runs Detect() on the
// response + body, and emits a core.Finding per matched WAF vendor.
//
// Findings are SeverityInfo by design: detecting a WAF is itself not a
// vulnerability — it is environmental context downstream selectors use
// to switch payload sets. Severity bumps to Medium only if the WAF is
// in a known-misconfigured state (signalled by a duplicate match or an
// unexpected block code).
type Detector struct {
	client  *http.Client
	verbose bool
}

// New constructs a scanner Detector.
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
	Timeout time.Duration
	// MaxBodyBytes caps how many bytes of the response body are buffered
	// for body-tell matching. 64 KiB is plenty for any realistic block page.
	MaxBodyBytes int64
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second, MaxBodyBytes: 64 << 10}
}

// DetectionResult mirrors the scanner-side convention used by other
// detectors (Findings + Vulnerable bool).
type DetectionResult struct {
	URL        string
	WAFs       []Match
	Findings   []*core.Finding
	Vulnerable bool // always true if at least one WAF was detected (informational, not a defect)
}

// Detect performs one GET, fingerprints any WAF, and returns findings.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 64 << 10
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("wafdetect: build request: %w", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wafdetect: do request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))

	matches := Detect(resp, body)
	result := &DetectionResult{URL: target, WAFs: matches, Vulnerable: len(matches) > 0}
	for _, m := range matches {
		result.Findings = append(result.Findings, d.toFinding(target, m))
	}
	return result, nil
}

func (d *Detector) toFinding(target string, m Match) *core.Finding {
	f := core.NewFinding("waf_detected", core.SeverityInfo)
	f.Tool = "wafdetect"
	f.URL = target
	f.Title = "Web Application Firewall detected: " + m.Vendor
	f.Confidence = mapConfidence(m.Confidence)
	f.Description = fmt.Sprintf(
		"Passive WAF fingerprinting identified %s in front of the target. This is informational — payload selection downstream should switch to evasion-class variants for this vendor.",
		m.Vendor,
	)
	f.Evidence = m.Evidence
	f.Metadata["vendor"] = m.Vendor
	f.Metadata["confidence_score"] = m.Confidence
	f.Remediation = ""
	f.References = []string{"https://owasp.org/www-community/Web_Application_Firewall"}
	return f
}

func mapConfidence(score int) core.Confidence {
	switch {
	case score >= 85:
		return core.ConfidenceHigh
	case score >= 60:
		return core.ConfidenceMedium
	default:
		return core.ConfidenceLow
	}
}
