package analysis

import (
	"context"
	"math"
	"time"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

const (
	defaultBaselineSamples    = 5
	defaultConfirmationRounds = 3
	defaultRequiredConfirms   = 2
)

// TimingResult contains the result of timing-based analysis.
type TimingResult struct {
	// IsDelayed indicates whether a statistically significant delay was detected.
	IsDelayed bool
	// Confidence is a value between 0.0 and 1.0 representing how confident the
	// analysis is that the measured delay is genuine.
	Confidence float64
	// BaselineMean is the mean response time from baseline requests.
	BaselineMean time.Duration
	// BaselineStdDev is the standard deviation of baseline response times.
	BaselineStdDev time.Duration
	// MeasuredDelay is the average duration measured from delay-payload requests.
	MeasuredDelay time.Duration
}

// TimingAnalyzer performs statistical time-based vulnerability validation by
// comparing baseline response times against delay-payload response times.
type TimingAnalyzer struct {
	baselineSamples    int // number of baseline requests (default 5)
	confirmationRounds int // number of confirmation rounds (default 3)
	requiredConfirms   int // number of required confirmations (default 2)
}

// NewTimingAnalyzer creates a new TimingAnalyzer with default settings:
// 5 baseline samples, 3 confirmation rounds, 2 required confirmations.
func NewTimingAnalyzer() *TimingAnalyzer {
	return &TimingAnalyzer{
		baselineSamples:    defaultBaselineSamples,
		confirmationRounds: defaultConfirmationRounds,
		requiredConfirms:   defaultRequiredConfirms,
	}
}

// Analyze sends baseline requests to establish the normal response time
// distribution (mean and standard deviation), then sends the delay payload and
// checks if the duration exceeds mean + 3*stddev + expectedDelay. It repeats the
// delay payload across multiple confirmation rounds and requires a minimum number
// of confirmations to declare a positive result.
func (ta *TimingAnalyzer) Analyze(
	ctx context.Context,
	client *skwshttp.Client,
	targetURL, param, method, delayPayload string,
	expectedDelay time.Duration,
) *TimingResult {
	result := &TimingResult{}

	// Collect baseline samples.
	baselineDurations := make([]time.Duration, 0, ta.baselineSamples)
	for range ta.baselineSamples {
		if ctx.Err() != nil {
			return result
		}

		resp, err := client.Get(ctx, targetURL)
		if err != nil {
			return result
		}
		baselineDurations = append(baselineDurations, resp.Duration)
	}

	mean, stddev := calculateBaselineStats(baselineDurations)
	result.BaselineMean = mean
	result.BaselineStdDev = stddev

	// Threshold: mean + 3*stddev + expectedDelay.
	// This means the delay must be statistically significant beyond normal variance
	// AND must exceed the expected delay duration.
	threshold := mean + 3*stddev + expectedDelay

	// Run confirmation rounds.
	confirmedCount := 0
	var totalMeasured time.Duration
	roundsCompleted := 0

	for i := range ta.confirmationRounds {
		_ = i
		if ctx.Err() != nil {
			break
		}

		resp, err := client.SendPayload(ctx, targetURL, param, delayPayload, method)
		if err != nil {
			continue
		}

		roundsCompleted++
		totalMeasured += resp.Duration

		if resp.Duration >= threshold {
			confirmedCount++
		}
	}

	if roundsCompleted > 0 {
		result.MeasuredDelay = totalMeasured / time.Duration(roundsCompleted)
	}

	if confirmedCount >= ta.requiredConfirms {
		result.IsDelayed = true
		result.Confidence = float64(confirmedCount) / float64(ta.confirmationRounds)
	}

	return result
}

// calculateBaselineStats computes the mean and population standard deviation of
// a slice of durations. Returns (0, 0) for an empty slice.
func calculateBaselineStats(durations []time.Duration) (mean, stddev time.Duration) {
	n := len(durations)
	if n == 0 {
		return 0, 0
	}

	// Calculate mean.
	var sum int64
	for _, d := range durations {
		sum += d.Nanoseconds()
	}
	meanNs := float64(sum) / float64(n)

	// Calculate population standard deviation.
	var varianceSum float64
	for _, d := range durations {
		diff := float64(d.Nanoseconds()) - meanNs
		varianceSum += diff * diff
	}
	varianceNs := varianceSum / float64(n)
	stddevNs := math.Sqrt(varianceNs)

	return time.Duration(meanNs), time.Duration(stddevNs)
}
