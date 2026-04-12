package racecond

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Detector performs Race Condition vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new Race Condition Detector.
func New(client *http.Client) *Detector {
	return &Detector{
		client: client,
	}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "racecond"
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	ConcurrentRequests int
	Timeout            time.Duration
	BodyLengthVariance float64
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		ConcurrentRequests: 10,
		Timeout:            15 * time.Second,
		BodyLengthVariance: 0.1,
	}
}

// DetectionResult contains race condition detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// concurrentResponse holds the result of a single concurrent request.
type concurrentResponse struct {
	StatusCode    int
	ContentLength int
	Body          string
	Err           error
}

// Detect tests a parameter for Race Condition vulnerabilities.
// It sends multiple identical requests in parallel and compares responses.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	concurrency := opts.ConcurrentRequests
	if concurrency <= 0 {
		concurrency = DefaultOptions().ConcurrentRequests
	}

	// Send concurrent requests
	responses := make([]concurrentResponse, concurrency)
	var wg sync.WaitGroup

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()

			resp, err := d.client.SendPayload(ctx, target, param, "test_race_value", method)
			if err != nil {
				responses[idx] = concurrentResponse{Err: err}
				return
			}

			responses[idx] = concurrentResponse{
				StatusCode:    resp.StatusCode,
				ContentLength: len(resp.Body),
				Body:          resp.Body,
			}
		}(i)
	}

	wg.Wait()
	result.TestedPayloads = concurrency

	// Filter out errored responses
	var validResponses []concurrentResponse
	for _, r := range responses {
		if r.Err == nil {
			validResponses = append(validResponses, r)
		}
	}

	if len(validResponses) < 2 {
		return result, fmt.Errorf("insufficient valid responses: got %d, need at least 2", len(validResponses))
	}

	// Analyze responses for inconsistencies
	inconsistent := d.analyzeResponses(validResponses, opts.BodyLengthVariance)
	if inconsistent {
		finding := d.createFinding(target, param, method, validResponses)
		result.Findings = append(result.Findings, finding)
		result.Vulnerable = true
	}

	return result, nil
}

// analyzeResponses checks if the responses show signs of a race condition.
func (d *Detector) analyzeResponses(responses []concurrentResponse, variance float64) bool {
	if len(responses) < 2 {
		return false
	}

	// Check for different status codes
	statusCodes := make(map[int]int)
	for _, r := range responses {
		statusCodes[r.StatusCode]++
	}

	if len(statusCodes) > 1 {
		return true
	}

	// Check for significant body length variation
	var lengths []int
	for _, r := range responses {
		lengths = append(lengths, r.ContentLength)
	}

	avgLength := averageInt(lengths)
	if avgLength == 0 {
		return false
	}

	for _, l := range lengths {
		diff := math.Abs(float64(l-avgLength)) / float64(avgLength)
		if diff > variance {
			return true
		}
	}

	return false
}

// averageInt returns the average of a slice of ints.
func averageInt(vals []int) int {
	if len(vals) == 0 {
		return 0
	}
	sum := 0
	for _, v := range vals {
		sum += v
	}
	return sum / len(vals)
}

// createFinding creates a Finding from a detected race condition.
func (d *Detector) createFinding(target, param, method string, responses []concurrentResponse) *core.Finding {
	finding := core.NewFinding("Race Condition", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("Potential race condition detected on '%s' parameter using %s method with %d concurrent requests",
		param, method, len(responses))

	// Build evidence from response analysis
	statusCodes := make(map[int]int)
	var lengths []int
	for _, r := range responses {
		statusCodes[r.StatusCode]++
		lengths = append(lengths, r.ContentLength)
	}

	evidence := fmt.Sprintf("Concurrent requests: %d\nStatus code distribution: %v\nBody length range: %d - %d",
		len(responses), statusCodes, minInt(lengths), maxInt(lengths))
	finding.Evidence = evidence
	finding.Tool = "racecond-detector"
	finding.Remediation = "Implement proper locking mechanisms for state-changing operations. " +
		"Use database transactions with appropriate isolation levels. " +
		"Apply idempotency tokens to prevent duplicate processing."

	finding.WithOWASPMapping(
		[]string{"WSTG-BUSL-07"},
		[]string{"A04:2021"},
		[]string{"CWE-362"},
	)

	return finding
}

// minInt returns the minimum value in a slice of ints.
func minInt(vals []int) int {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// maxInt returns the maximum value in a slice of ints.
func maxInt(vals []int) int {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}
