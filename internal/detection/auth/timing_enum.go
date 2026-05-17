package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// TimingEnumOptions configures the statistical timing-enumeration probe.
type TimingEnumOptions struct {
	ValidUser   string        // known-good username
	InvalidUser string        // believed-to-not-exist username
	Samples     int           // per-arm sample count (default 8)
	Timeout     time.Duration // per-request timeout (advisory)
}

// TimingEnumResult contains the outcome of a paired timing test.
type TimingEnumResult struct {
	Vulnerable   bool
	Findings     []*core.Finding
	MeanValid    time.Duration
	MeanInvalid  time.Duration
	StdDevValid  time.Duration
	StdDevInv    time.Duration
	SamplesTaken int
	ZScore       float64 // |Δmean| / SE — flagged at ≥ 2.58 (~99% confidence)
}

// DetectTimingEnumeration runs a paired timing probe against a login endpoint.
// It posts identical wrong-password attempts for a known-valid username and a
// believed-invalid username, repeats N samples of each (interleaved to dampen
// jitter), and applies a two-sample z-score on the means. A z-score ≥ 2.58
// indicates the response-time distribution discriminates the two arms with
// ~99% confidence — i.e. an attacker can enumerate accounts via timing alone.
func (d *Detector) DetectTimingEnumeration(ctx context.Context, loginURL string, opts TimingEnumOptions) (*TimingEnumResult, error) {
	result := &TimingEnumResult{Findings: make([]*core.Finding, 0)}
	if opts.Samples <= 0 {
		opts.Samples = 8
	}
	if opts.ValidUser == "" || opts.InvalidUser == "" {
		return result, fmt.Errorf("both ValidUser and InvalidUser are required")
	}

	validDur := make([]time.Duration, 0, opts.Samples)
	invDur := make([]time.Duration, 0, opts.Samples)

	for i := 0; i < opts.Samples; i++ {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		// Interleave to keep both arms exposed to the same network jitter window.
		if dur, ok := d.timeOneLogin(ctx, loginURL, opts.ValidUser); ok {
			validDur = append(validDur, dur)
		}
		if dur, ok := d.timeOneLogin(ctx, loginURL, opts.InvalidUser); ok {
			invDur = append(invDur, dur)
		}
	}
	result.SamplesTaken = len(validDur)
	if len(validDur) < 3 || len(invDur) < 3 {
		return result, nil // not enough data to call it
	}

	mv, sv := meanStdDev(validDur)
	mi, si := meanStdDev(invDur)
	result.MeanValid, result.StdDevValid = mv, sv
	result.MeanInvalid, result.StdDevInv = mi, si

	// Welch z-approximation: |Δmean| / sqrt(σ₁²/n₁ + σ₂²/n₂).
	se := math.Sqrt(
		(float64(sv.Nanoseconds())*float64(sv.Nanoseconds()))/float64(len(validDur)) +
			(float64(si.Nanoseconds())*float64(si.Nanoseconds()))/float64(len(invDur)),
	)
	diff := math.Abs(float64(mv.Nanoseconds() - mi.Nanoseconds()))
	if se > 0 {
		result.ZScore = diff / se
	}

	// Two thresholds: |Δmean| must be operationally meaningful (≥ 25ms is
	// the floor for "an attacker could measure this over the internet") AND
	// the z-score must clear 99% significance. This rejects flaky CI runs
	// where σ inflates and a 1ms mean diff would otherwise alarm.
	if result.ZScore >= 2.58 && diff >= float64(25*time.Millisecond.Nanoseconds()) {
		result.Vulnerable = true
		result.Findings = append(result.Findings, d.createTimingEnumFinding(loginURL, result))
	}
	return result, nil
}

// timeOneLogin posts a single wrong-password attempt for the given username and
// returns the wall-clock duration. The username field name matches the existing
// auth detector's payload shape so behaviour is uniform across both probes.
func (d *Detector) timeOneLogin(ctx context.Context, loginURL, username string) (time.Duration, bool) {
	bodyBytes, _ := json.Marshal(map[string]string{
		"username": username,
		"password": "wrong_password_xyz_aaa",
	})
	resp, err := d.client.PostJSON(ctx, loginURL, string(bodyBytes))
	if err != nil || resp == nil {
		return 0, false
	}
	return resp.Duration, true
}

// meanStdDev returns the arithmetic mean and population standard deviation of
// a non-empty slice of durations.
func meanStdDev(xs []time.Duration) (mean, stddev time.Duration) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum int64
	for _, x := range xs {
		sum += x.Nanoseconds()
	}
	meanNs := float64(sum) / float64(len(xs))
	var ss float64
	for _, x := range xs {
		d := float64(x.Nanoseconds()) - meanNs
		ss += d * d
	}
	return time.Duration(meanNs), time.Duration(math.Sqrt(ss / float64(len(xs))))
}

// createTimingEnumFinding renders the finding for a confirmed timing oracle.
func (d *Detector) createTimingEnumFinding(loginURL string, r *TimingEnumResult) *core.Finding {
	f := core.NewFinding("Account Enumeration via Timing", core.SeverityMedium)
	f.URL = loginURL
	f.Tool = "auth-detector"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The login endpoint's response-time distribution discriminates " +
		"valid from invalid usernames with statistical significance. An attacker " +
		"can enumerate registered accounts via timing alone, even when the response " +
		"body and status are identical."
	f.Evidence = fmt.Sprintf(
		"valid-user mean: %v (σ=%v, n=%d)\n"+
			"invalid-user mean: %v (σ=%v, n=%d)\n"+
			"z-score: %.2f (≥ 2.58 = 99%% significance)",
		r.MeanValid, r.StdDevValid, r.SamplesTaken,
		r.MeanInvalid, r.StdDevInv, r.SamplesTaken,
		r.ZScore,
	)
	f.Remediation = "Normalise response times for both valid and invalid accounts. " +
		"Always run the password hash even when the username does not exist " +
		"(use a fixed dummy hash). Add small randomised jitter as defence-in-depth."
	f.WithOWASPMapping(
		[]string{"WSTG-IDNT-04"},
		[]string{"A07:2025"},
		[]string{"CWE-208"}, // Observable Timing Discrepancy
	)
	return f
}
