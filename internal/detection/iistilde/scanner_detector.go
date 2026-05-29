package iistilde

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector is the scanner-side wrapper around the differential probe.
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
	Timeout time.Duration
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Probe      Result
	Findings   []*core.Finding
	Vulnerable bool
}

// DetectWithOptions runs the differential probe and emits one finding
// when the IIS short-name (tilde) handler leaks.
func (d *Detector) DetectWithOptions(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	// Sub-context wraps an existing client; the package-level Detect
	// doesn't take a context, so the timeout is enforced via the client.
	client := *d.client
	if client.Timeout == 0 || opts.Timeout < client.Timeout {
		client.Timeout = opts.Timeout
	}

	done := make(chan struct {
		r   Result
		err error
	}, 1)
	go func() {
		r, err := Detect(target, &client)
		done <- struct {
			r   Result
			err error
		}{r, err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("iistilde: %w", ctx.Err())
	case out := <-done:
		if out.err != nil {
			return nil, fmt.Errorf("iistilde: %w", out.err)
		}
		result := &DetectionResult{URL: target, Probe: out.r, Vulnerable: out.r.Vulnerable}
		if out.r.Vulnerable {
			result.Findings = append(result.Findings, d.toFinding(target, out.r))
		}
		return result, nil
	}
}

func (d *Detector) toFinding(target string, r Result) *core.Finding {
	f := core.NewFinding("iis_tilde_disclosure", core.SeverityMedium)
	f.Tool = "iistilde"
	f.URL = target
	f.Title = "IIS short-name (8.3 / tilde) enumeration"
	f.Confidence = core.ConfidenceHigh
	f.Description = "IIS leaks the existence of files and directories whose 8.3 short-name prefix matches a wildcard. " +
		"An attacker can enumerate names a directory listing would never reveal, harvesting source files, " +
		"backup copies, and admin endpoints reachable by their short alias."
	f.Evidence = r.Evidence
	f.Metadata["probe_method"] = r.Method
	f.Metadata["probes_sent"] = r.Probes
	f.Remediation = "Disable the 8.3 name generation: `fsutil 8dot3name set 1` then strip existing short names with " +
		"`fsutil 8dot3name strip /s /v <webroot>`. Restart IIS afterward."
	f.References = []string{
		"https://soroush.me/blog/2014/07/iis-short-file-name-disclosure-is-back-cve-2014-2013/",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-CONF-04"},
		[]string{"A01:2021"},
		[]string{"CWE-200", "CWE-548"},
	)
	return f
}
