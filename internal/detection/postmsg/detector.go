package postmsg

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
)

// Detector probes a target for postMessage handlers that act on
// attacker-origin events without origin validation. It piggybacks on
// the shared headless pool — a nil pool turns the detector into a no-op
// rather than a hard error, mirroring how storageinj behaves when
// Chrome is unavailable.
type Detector struct {
	pool    *headless.Pool
	verbose bool
}

// New constructs a Detector bound to the shared browser pool. The pool
// may be nil; Detect will return an empty result in that case.
func New(pool *headless.Pool) *Detector {
	return &Detector{pool: pool}
}

// WithVerbose toggles per-step diagnostics on stderr.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "postmsg" }

// Description returns a human-readable description.
func (d *Detector) Description() string {
	return "Dispatches a synthetic MessageEvent from an attacker-controlled origin and reports listeners that mutated DOM/storage without validating event.origin."
}

// DetectOptions configures the probe. AttackerOrigin defaults to a
// well-known synthetic value; tests override to assert specific
// behavior. Payload is the marker dispatched into the listener — pick
// something distinctive enough that incidental string equality won't
// trigger a false-positive sink-diff.
type DetectOptions struct {
	AttackerOrigin string
	Payload        string
	Timeout        time.Duration
}

// DefaultOptions returns the recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		AttackerOrigin: "https://attacker.skws.invalid",
		Payload:        "__skws_postmessage_probe_marker__",
		Timeout:        15 * time.Second,
	}
}

// DetectionResult carries the findings and the raw probe result. The
// probe result is stashed so callers that want to render the mutation
// list themselves can do so without re-running the browser.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Probe      *headless.PostMessageProbeResult
}

// Detect navigates to target, dispatches the synthetic MessageEvent,
// and emits a finding when the page's listeners mutated any sink. The
// severity grades on which sink mutated:
//   - innerHTML / location → High (DOM XSS or open redirect chain)
//   - localStorage / sessionStorage / documentCookie → High
//     (auth-token tampering)
//   - title only → Medium (cosmetic but still origin-validation bug)
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{Findings: make([]*core.Finding, 0)}
	if d == nil || d.pool == nil {
		return res, nil
	}
	if opts.Payload == "" || opts.AttackerOrigin == "" {
		def := DefaultOptions()
		if opts.Payload == "" {
			opts.Payload = def.Payload
		}
		if opts.AttackerOrigin == "" {
			opts.AttackerOrigin = def.AttackerOrigin
		}
		if opts.Timeout == 0 {
			opts.Timeout = def.Timeout
		}
	}

	probeCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	page, err := d.pool.Acquire(probeCtx)
	if err != nil {
		return res, fmt.Errorf("postmsg: acquire page: %w", err)
	}
	defer d.pool.Release(page)

	if d.verbose {
		fmt.Fprintf(os.Stderr, "[*] postmsg: navigating to %s\n", target)
	}
	if err := page.Navigate(probeCtx, target); err != nil {
		return res, fmt.Errorf("postmsg: navigate: %w", err)
	}

	probe, err := page.ProbePostMessageOrigin(probeCtx, opts.AttackerOrigin, opts.Payload)
	if err != nil {
		return res, fmt.Errorf("postmsg: probe: %w", err)
	}
	res.Probe = probe
	if probe == nil || !probe.HandlerFired {
		return res, nil
	}

	// Severity grades on which sink the handler reached.
	severity := gradeSeverity(probe.Mutations)
	finding := core.NewFinding("Unvalidated postMessage Origin", severity)
	finding.Title = "postMessage handler accepts unverified origin"
	finding.URL = target
	finding.Tool = "postmsg-detector"
	finding.Description = fmt.Sprintf(
		"The page registered a window.message listener that mutated %s in response to a synthetic MessageEvent claiming origin %q. A real attacker on any origin can frame this page, post the same payload, and trigger the same mutation — the listener does not validate event.origin against an allowlist.",
		strings.Join(probe.Mutations, ", "),
		probe.AttackerOrigin,
	)
	finding.Evidence = strings.Join([]string{
		"attacker origin: " + probe.AttackerOrigin,
		"sinks mutated:   " + strings.Join(probe.Mutations, ", "),
	}, "\n")
	finding.Remediation = "Validate event.origin in every window.message listener before acting on event.data. Compare against an allowlist of trusted origins; never use startsWith / regex / includes against the origin string. Reference: https://developer.mozilla.org/docs/Web/API/Window/postMessage and OWASP WSTG-CLNT-11."
	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-11"},
		[]string{"A03:2025", "A04:2025"},
		[]string{"CWE-346", "CWE-942"},
	)

	res.Findings = append(res.Findings, finding)
	res.Vulnerable = true
	return res, nil
}

// gradeSeverity returns the highest severity the touched sinks warrant.
// A handler that wrote attacker-origin data to innerHTML or location is
// a DOM-XSS / open-redirect primitive; one that only mutated the title
// is still a bug but rarely exploitable on its own.
func gradeSeverity(sinks []string) core.Severity {
	high := false
	medium := false
	for _, s := range sinks {
		switch s {
		case "innerHTML", "location",
			"localStorage", "sessionStorage", "documentCookie":
			high = true
		case "title":
			medium = true
		}
	}
	switch {
	case high:
		return core.SeverityHigh
	case medium:
		return core.SeverityMedium
	default:
		return core.SeverityLow
	}
}
