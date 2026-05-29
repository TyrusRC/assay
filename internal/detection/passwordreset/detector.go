// Package passwordreset probes a password-reset endpoint for the three
// classic account-takeover flaws — host-header poisoning of the reset
// link, cross-user token acceptance, and single-use token replay.
//
// File layout:
//
//	detector.go      — types, constructor, DetectAll dispatcher
//	probes.go        — the three probe methods (DetectHostHeaderPoisoning,
//	                   DetectCrossUserToken, DetectTokenReplay)
//	http_helpers.go  — requestToken, body builders, URL hint helpers,
//	                   success / attacker-host matchers
//	findings.go      — Finding builders for the three probe outcomes
package passwordreset

import (
	"context"
	"fmt"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// attackerHost is the canary host injected into the Host /
// X-Forwarded-Host headers. It uses a reserved label (.example) so it
// cannot accidentally collide with a real production host.
const attackerHost = "assay-passwordreset-poison.example"

// toolName is the value emitted in Finding.Tool for all findings in
// this package.
const toolName = "passwordreset-detector"

// requestPathHints / confirmPathHints are the substrings we add to the
// reset base URL when probing for the two-step (request, confirm) flow.
// Most apps expose the flow under /password/forgot or /password/reset
// and /password/confirm; we accept the base URL as-is and try both
// "request" and "confirm" suffixes alongside it.
var (
	requestPathHints = []string{"", "/request", "/forgot"}
	confirmPathHints = []string{"/confirm", "/reset", ""}
)

// Detector probes a password-reset endpoint for the three classic
// account-takeover flaws (host-header poison, cross-user replay,
// single-use bypass).
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a Detector wired to the shared HTTP client.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose enables verbose output for the detector.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the password-reset audit. UserA is always
// required; UserB is required only for the cross-user check.
type DetectOptions struct {
	UserA   string
	UserB   string
	Timeout time.Duration
}

// DetectionResult bundles findings from a single sub-check.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// DetectAll runs every sub-check and returns one DetectionResult per
// check in stable order (host-header, cross-user, replay). Errors from
// individual checks are surfaced via the returned error only when they
// prevent the check from running at all — per-request failures are
// silently skipped, matching the rest of the detector package.
func (d *Detector) DetectAll(ctx context.Context, resetURL string, opts DetectOptions) ([]*DetectionResult, error) {
	results := make([]*DetectionResult, 0, 3)

	host, err := d.DetectHostHeaderPoisoning(ctx, resetURL, opts)
	if err != nil {
		return results, fmt.Errorf("host-header check failed: %w", err)
	}
	results = append(results, host)

	cross, err := d.DetectCrossUserToken(ctx, resetURL, opts)
	if err != nil {
		return results, fmt.Errorf("cross-user check failed: %w", err)
	}
	results = append(results, cross)

	replay, err := d.DetectTokenReplay(ctx, resetURL, opts)
	if err != nil {
		return results, fmt.Errorf("replay check failed: %w", err)
	}
	results = append(results, replay)

	return results, nil
}
