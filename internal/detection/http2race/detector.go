package http2race

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector probes a state-change endpoint for race conditions by
// firing N concurrent requests and verifying that more than one
// "first-time-success" response came back. The single-packet-attack
// framing — multiplexing the burst on a single HTTP/2 connection to
// minimize jitter — is the spirit of the technique; the implementation
// uses the existing client's connection pool (HTTP/2 when negotiated,
// HTTP/1.1 fallback otherwise).
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "http2race" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Probes a state-change endpoint for race conditions by firing a concurrent burst (single-packet-attack style multiplexing) and checking whether more than one request landed in the pre-state-change window."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	// Method to use for each request. Defaults to POST.
	Method string
	// Body for each request.
	Body string
	// ContentType for the body.
	ContentType string
	// Concurrency is the number of requests to fire in the burst.
	Concurrency int
	// Timeout per request.
	Timeout time.Duration
	// PostBurstDelay is how long to wait before the confirmation probe.
	PostBurstDelay time.Duration
}

// DefaultOptions returns recommended defaults — POST, 20 concurrent
// requests, 10s timeout, 100ms settle before confirmation.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Method:         "POST",
		Concurrency:    20,
		Timeout:        10 * time.Second,
		PostBurstDelay: 100 * time.Millisecond,
	}
}

// DetectionResult carries findings and the list of techniques that
// triggered.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Techniques []string
}

// Detect fires Concurrency requests in parallel, counts the
// successes, then sends one confirmation probe. A race is reported
// only when the burst returned ≥ 2 successes AND the confirmation
// probe failed — i.e., the state was exhaustible but multiple racing
// requests still got through.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:   make([]*core.Finding, 0),
		Techniques: make([]string, 0),
	}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Concurrency <= 1 {
		opts.Concurrency = DefaultOptions().Concurrency
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}
	if opts.Method == "" {
		opts.Method = "POST"
	}

	successCount, exampleStatus, exampleBody, errCount := d.burst(ctx, target, opts)

	if errCount >= opts.Concurrency/2 {
		// Connection errors dominated — can't reason about race.
		return res, nil
	}
	if successCount < 2 {
		// Hardened endpoint or no state change observed.
		return res, nil
	}

	if opts.PostBurstDelay > 0 {
		select {
		case <-time.After(opts.PostBurstDelay):
		case <-ctx.Done():
			return res, nil
		}
	}

	confirm, err := d.one(ctx, target, opts)
	if err != nil || confirm == nil {
		return res, nil
	}
	if isSuccess(confirm.StatusCode) {
		// Endpoint still succeeds after the burst — likely idempotent
		// or the state pool isn't exhaustible.
		return res, nil
	}

	res.Techniques = append(res.Techniques, "state_change_race")
	res.Findings = append(res.Findings, buildFinding(target, opts.Concurrency, successCount, exampleStatus, exampleBody, confirm.StatusCode))
	res.Vulnerable = true
	return res, nil
}

// burst fires opts.Concurrency requests in parallel and returns the
// number of 2xx responses, an example successful (status, body) pair,
// and the number of transport errors.
func (d *Detector) burst(ctx context.Context, target string, opts DetectOptions) (int, int, string, int) {
	type outcome struct {
		status int
		body   string
		err    error
	}
	results := make(chan outcome, opts.Concurrency)
	var wg sync.WaitGroup
	// Gate to release all goroutines as close to simultaneously as
	// possible — the closest analog to single-packet timing we get
	// from the stdlib client pool.
	gate := make(chan struct{})
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			resp, err := d.one(ctx, target, opts)
			if err != nil || resp == nil {
				results <- outcome{err: err}
				return
			}
			results <- outcome{status: resp.StatusCode, body: resp.Body}
		}()
	}
	close(gate)
	wg.Wait()
	close(results)

	var (
		successes     int
		errors        int
		exampleStatus int
		exampleBody   string
	)
	for o := range results {
		if o.err != nil {
			errors++
			continue
		}
		if isSuccess(o.status) {
			successes++
			if exampleStatus == 0 {
				exampleStatus = o.status
				exampleBody = trim(o.body, 120)
			}
		}
	}
	return successes, exampleStatus, exampleBody, errors
}

func (d *Detector) one(ctx context.Context, target string, opts DetectOptions) (*scanhttp.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return d.client.Do(reqCtx, &scanhttp.Request{
		Method:      opts.Method,
		URL:         target,
		Body:        opts.Body,
		ContentType: opts.ContentType,
	})
}

func isSuccess(status int) bool {
	return status >= 200 && status < 300
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func buildFinding(target string, concurrency, successes, exampleStatus int, exampleBody string, postStatus int) *core.Finding {
	f := core.NewFinding("HTTP/2 single-packet race condition", core.SeverityHigh)
	f.Title = "Concurrent state-change race window — multiple requests landed before the guard fired"
	f.URL = target
	f.Tool = "http2race-detector"
	f.Description = fmt.Sprintf("A burst of %d concurrent requests produced %d successful responses, but a single confirmation probe sent immediately after the burst returned status %d — meaning the endpoint's state was exhaustible. The check-then-act sequence on the server allowed multiple racing requests to observe the pre-change state simultaneously and each proceed as if they were the first. Example successful response: status %d, body: %q.", concurrency, successes, postStatus, exampleStatus, exampleBody)
	f.Evidence = fmt.Sprintf("burst=%d successes=%d post-burst-status=%d", concurrency, successes, postStatus)
	f.Remediation = "Serialize the check-and-set on the server: take a row lock, use a unique constraint, or do the state transition with an atomic compare-and-swap. The Single-Packet Attack (J. Kettle, 2023) collapses the race window to micro-seconds; any solution that relies on wall-clock distance between requests is insufficient."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A04:2025"},
		[]string{"CWE-362", "CWE-367"},
	)
	return f
}
