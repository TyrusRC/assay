package racecond

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detector probes a target for race-condition / TOCTOU vulnerabilities.
//
// Unlike the legacy "fan out goroutines and look for any variance"
// approach, the detector uses two improvements that together cut the
// false-positive rate to near zero:
//
//  1. Transmission synchronization — by default, requests are sent over
//     keep-alive HTTP/1.1 connections with last-byte sync, narrowing the
//     server-side arrival window from goroutine-scheduling jitter (5-50 ms)
//     to OS write fan-out (sub-ms).
//  2. Baseline-differential analysis — a sequential warm-up baseline is
//     captured first, and the burst is only flagged when it produces a
//     response shape the baseline never produced. This suppresses the
//     entire class of FPs caused by per-request counters, timestamps,
//     load-balancer affinity, and naturally varying responses.
type Detector struct {
	client  *internalhttp.Client
	verbose bool
}

// New creates a Detector bound to the shared HTTP client.
func New(client *internalhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose enables verbose finding evidence.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "racecond" }

// DetectionResult is the outcome of a single Detect call.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Detect probes target / param / method for a race window. The probe is:
//
//  1. Issue opts.BaselineRequests sequential warm-up requests.
//  2. Issue opts.ConcurrentRequests requests via the configured sync mode.
//  3. Compare the burst against the baseline; emit a finding only when
//     the burst contains a response shape the baseline never produced.
//
// The finding is reported at Medium severity and marked unconfirmed —
// observing a race window does not by itself prove exploitation. To
// promote to Critical+Confirmed, use DetectWithVerifier with a callback
// that re-reads server-side state and confirms a double-applied effect.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	return d.DetectWithVerifier(ctx, target, param, method, opts, nil)
}

// DetectWithVerifier behaves like Detect, but if the optional verifier
// callback reports a multi-effect (e.g., wallet balance debited twice
// when only one debit was issued) the finding is promoted to Critical
// and marked Confirmed in the description.
func (d *Detector) DetectWithVerifier(ctx context.Context, target, param, method string, opts DetectOptions, verify Verifier) (*DetectionResult, error) {
	opts = applyDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	method = strings.ToUpper(method)
	if method == "" {
		method = "POST"
	}

	baseline, baseErr := d.collectBaseline(ctx, target, param, method, opts)
	if baseErr != nil {
		return result, fmt.Errorf("baseline: %w", baseErr)
	}

	burst, burstErr := d.collectBurst(ctx, target, param, method, opts)
	if burstErr != nil {
		return result, fmt.Errorf("burst: %w", burstErr)
	}
	result.TestedPayloads = len(burst)

	signal := analyzeBaselineDiff(baseline, burst)
	if signal == nil {
		return result, nil
	}

	confirmed := false
	verifyEvidence := ""
	if verify != nil {
		multi, ev, err := verify(ctx)
		if err == nil && multi {
			confirmed = true
			verifyEvidence = ev
		}
	}

	finding := d.buildFinding(target, param, method, baseline, burst, signal, confirmed, verifyEvidence)
	result.Findings = append(result.Findings, finding)
	result.Vulnerable = true
	return result, nil
}

// collectBaseline issues N sequential requests with full read of body, so
// the analyzer sees the same body-hash buckets as the burst. We use the
// shared client so any global Headers/Cookies/UA/Proxy plumbing applies.
func (d *Detector) collectBaseline(ctx context.Context, target, param, method string, opts DetectOptions) ([]recordedResponse, error) {
	if opts.BaselineRequests < 1 {
		return nil, nil
	}
	out := make([]recordedResponse, 0, opts.BaselineRequests)
	for i := 0; i < opts.BaselineRequests; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		resp, err := d.client.SendPayload(ctx, target, param, "skws_race_baseline", method)
		if err != nil {
			out = append(out, recordedResponse{Err: err})
			continue
		}
		out = append(out, recordResponseFromClient(resp))
	}
	return out, nil
}

// collectBurst dispatches the synchronized burst. For SyncH1LastByte and
// SyncH2SinglePacket we drop to raw TCP/TLS to implement transmission
// synchronization. For SyncParallel (legacy fallback) we fan out the
// shared client which handles plumbing but provides no real sync.
//
// The h2 path automatically falls back to h1 last-byte if the server
// doesn't negotiate h2 via ALPN — this keeps the detector usable against
// h1-only targets without requiring the caller to pre-probe.
func (d *Detector) collectBurst(ctx context.Context, target, param, method string, opts DetectOptions) ([]recordedResponse, error) {
	body := fmt.Sprintf("%s=skws_race_burst", param)
	headers := d.client.Snapshot().Headers
	switch opts.SyncMode {
	case SyncH1LastByte:
		return d.h1LastByteBurst(ctx, target, method, body, headers, opts.ConcurrentRequests, opts.PreSyncDelay)
	case SyncH2SinglePacket:
		out, err := d.h2SinglePacketBurst(ctx, target, method, body, headers, opts.ConcurrentRequests, opts.PreSyncDelay)
		if errors.Is(err, errH2NotNegotiated) {
			return d.h1LastByteBurst(ctx, target, method, body, headers, opts.ConcurrentRequests, opts.PreSyncDelay)
		}
		return out, err
	case SyncParallel:
		return d.parallelBurst(ctx, target, param, method, opts.ConcurrentRequests)
	default:
		return nil, fmt.Errorf("unknown sync mode %q", opts.SyncMode)
	}
}

// parallelBurst is the legacy fan-out kept available as a fallback for
// targets that refuse keep-alive or where last-byte sync isn't viable.
func (d *Detector) parallelBurst(ctx context.Context, target, param, method string, n int) ([]recordedResponse, error) {
	out := make([]recordedResponse, n)
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			resp, err := d.client.SendPayload(ctx, target, param, "skws_race_burst", method)
			if err != nil {
				out[idx] = recordedResponse{Err: err}
				return
			}
			out[idx] = recordResponseFromClient(resp)
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
	return out, nil
}

func recordResponseFromClient(resp *internalhttp.Response) recordedResponse {
	if resp == nil {
		return recordedResponse{Err: fmt.Errorf("nil response")}
	}
	return recordedResponse{
		StatusCode:    resp.StatusCode,
		ContentLength: len(resp.Body),
		BodyHash:      bodyHash(resp.Body),
		Body:          resp.Body,
	}
}

func bodyHash(body string) string {
	if body == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:8])
}

// applyDefaults fills any missing DetectOptions from DefaultOptions(). Done
// here rather than in DefaultOptions() so callers can pass a partially-
// populated struct without losing its set fields.
func applyDefaults(opts DetectOptions) DetectOptions {
	def := DefaultOptions()
	if opts.ConcurrentRequests <= 0 {
		opts.ConcurrentRequests = def.ConcurrentRequests
	}
	if opts.Timeout <= 0 {
		opts.Timeout = def.Timeout
	}
	if opts.SyncMode == "" {
		opts.SyncMode = def.SyncMode
	}
	if opts.PreSyncDelay <= 0 {
		opts.PreSyncDelay = def.PreSyncDelay
	}
	if opts.BaselineRequests <= 0 {
		opts.BaselineRequests = def.BaselineRequests
	}
	return opts
}

// buildFinding renders the analyzer signal into a core.Finding. Severity
// is Medium for an unconfirmed observation; promoted to Critical when the
// caller's verifier confirmed a double-applied side effect.
func (d *Detector) buildFinding(target, param, method string, baseline, burst []recordedResponse, sig *raceSignal, confirmed bool, verifyEvidence string) *core.Finding {
	severity := core.SeverityMedium
	title := "Race Condition (Unconfirmed)"
	if confirmed {
		severity = core.SeverityCritical
		title = "Race Condition (Confirmed Double-Effect)"
	}

	finding := core.NewFinding(title, severity)
	finding.URL = target
	finding.Parameter = param
	finding.Tool = "racecond-detector"

	finding.Description = fmt.Sprintf(
		"Race window observed on %s %s — burst signal: %s.",
		method, target, sig.Kind,
	)
	if confirmed {
		finding.Description += " Verified: " + verifyEvidence
	} else {
		finding.Description += " Unconfirmed: a verifier callback can promote this finding by re-reading server-side state."
	}

	var ev []string
	ev = append(ev, "signal: "+sig.Kind)
	ev = append(ev, "evidence: "+sig.Evidence)
	ev = append(ev, fmt.Sprintf("baseline (%d): %s", len(baseline), summarizeShapes(baseline)))
	ev = append(ev, fmt.Sprintf("burst (%d): %s", len(burst), summarizeShapes(burst)))
	if verifyEvidence != "" {
		ev = append(ev, "verifier: "+verifyEvidence)
	}
	finding.Evidence = strings.Join(ev, "\n")

	finding.Remediation = "Wrap the state-changing operation in a database transaction with serializable isolation, or take a row-level lock before reading the value the request mutates. Add an idempotency-key header (RFC 8941) for client-driven retries. For scarce resources (coupons, vouchers, balances), prefer optimistic concurrency with a version column over best-effort checks."

	finding.WithOWASPMapping(
		[]string{"WSTG-BUSL-07"},
		[]string{"A04:2021"},
		[]string{"CWE-362", "CWE-367"},
	)
	return finding
}

