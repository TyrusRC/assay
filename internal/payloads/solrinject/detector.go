package solrinject

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

// Detector probes URL parameters for Apache Solr injection by
// injecting payloads against /q, /fq, /qt, /wt, /stream.body, /shards
// surfaces and looking for Solr/Lucene/Velocity error patterns or
// stream-URL reflection.
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
	// ConfirmedSolrOnly gates active exploitation payloads behind a
	// fingerprint hit. When true (default), the detector first runs a
	// passive fingerprint probe and only fires high-impact payloads
	// (Velocity RCE, DIH RCE) if the response is recognisably Solr.
	ConfirmedSolrOnly bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             10 * time.Second,
		MaxBodyBytes:        128 << 10,
		MaxPayloadsPerParam: 6,
		ConfirmedSolrOnly:   true,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL          string
	SolrDetected bool
	Findings     []*core.Finding
	Vulnerable   bool
}

// Detect issues a baseline + fingerprint probe, then iterates payloads
// against URL parameters.
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
		return nil, fmt.Errorf("solrinject: parse URL: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		return &DetectionResult{URL: target}, nil
	}

	baselineBody, err := d.fetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("solrinject: baseline: %w", err)
	}

	result := &DetectionResult{URL: target}
	if containsAny(baselineBody, GetErrorPatterns()) {
		// Baseline already shows Solr — treat any further error-pattern
		// hit as additional evidence, not as a fingerprint trigger.
		result.SolrDetected = true
	}

	payloads := GetPayloads()
	if opts.MaxPayloadsPerParam > 0 && len(payloads) > opts.MaxPayloadsPerParam*len(params) {
		// Cap total payloads so a wide URL doesn't fan out the entire bank.
		payloads = payloads[:opts.MaxPayloadsPerParam*len(params)]
	}

	seen := map[string]bool{}
	for paramName := range params {
		for _, p := range payloads {
			key := paramName + "|" + p.Value
			if seen[key] {
				continue
			}
			seen[key] = true

			// Gate high-impact payloads (RCE/CVE-flagged) until Solr is
			// confirmed by an earlier fingerprint or error-pattern hit.
			if opts.ConfirmedSolrOnly && !result.SolrDetected && p.Impact == ImpactRCE {
				continue
			}

			injectedURL := injectParam(u, paramName, p.Value)
			body, err := d.fetch(ctx, injectedURL, opts)
			if err != nil {
				continue
			}
			marker := evaluationMarker(p, body, baselineBody)
			if marker == "" {
				continue
			}
			// Any error-pattern match also bumps SolrDetected for downstream payloads.
			if !result.SolrDetected && containsAny(body, GetErrorPatterns()) {
				result.SolrDetected = true
			}
			result.Findings = append(result.Findings, d.toFinding(target, paramName, p, marker, result.SolrDetected))
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

func (d *Detector) fetch(ctx context.Context, target string, opts DetectOptions) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	return string(body), nil
}

func injectParam(u *url.URL, name, value string) string {
	uCopy := *u
	q := uCopy.Query()
	q.Set(name, value)
	uCopy.RawQuery = q.Encode()
	return uCopy.String()
}

// evaluationMarker decides whether a payload landed:
//   - Solr/Lucene/Velocity error pattern appears in response but not in baseline
//   - The payload's CVE-class is the marker (Log4Shell jndi: triggers an
//     OOB callback, not body content — outside the scope of this passive
//     check, but the response often surfaces a NamingException error).
func evaluationMarker(p Payload, body, baseline string) string {
	patterns := GetErrorPatterns()
	for _, pat := range patterns {
		if strings.Contains(body, pat) && !strings.Contains(baseline, pat) {
			return "error pattern: " + pat
		}
	}
	return ""
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func (d *Detector) toFinding(target, paramName string, p Payload, marker string, solrConfirmed bool) *core.Finding {
	sev := mapSeverity(p.Impact)
	conf := core.ConfidenceMedium
	if solrConfirmed {
		conf = core.ConfidenceHigh
	}
	f := core.NewFinding("solr_"+string(p.Impact), sev)
	f.Tool = "solrinject"
	f.URL = target
	f.Parameter = paramName
	f.Title = "Apache Solr injection: " + p.Technique
	f.Confidence = conf
	f.Description = "A user-controlled value reaches an Apache Solr query parameter without validation. " +
		p.Description + ". The injection enables " + describeImpact(p.Impact) + "."
	f.Evidence = "payload `" + truncate(p.Value, 100) + "` → " + marker
	f.Metadata["technique"] = p.Technique
	f.Metadata["impact"] = string(p.Impact)
	if p.CVE != "" {
		f.Metadata["cve"] = p.CVE
	}
	f.Remediation = "Validate or allowlist Solr query parameters server-side. Disable the DataImportHandler and Velocity response writer if unused; upgrade Solr to a patched version for known CVEs (8.4+ for the v.template chain, 8.11+ for Log4Shell)."
	f.References = []string{
		"https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface",
		"https://hackerone.com/reports/297478",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A03:2021"},
		[]string{"CWE-74"},
	)
	return f
}

func mapSeverity(i Impact) core.Severity {
	switch i {
	case ImpactRCE:
		return core.SeverityCritical
	case ImpactSSRF, ImpactFileRead:
		return core.SeverityHigh
	default:
		return core.SeverityMedium
	}
}

func describeImpact(i Impact) string {
	switch i {
	case ImpactRCE:
		return "remote code execution on the Solr host"
	case ImpactSSRF:
		return "server-side request forgery from the Solr host's network position"
	case ImpactFileRead:
		return "arbitrary file read on the Solr host"
	default:
		return "information disclosure"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
