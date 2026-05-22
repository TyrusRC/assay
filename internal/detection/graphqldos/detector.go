package graphqldos

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector probes a GraphQL endpoint for resource-exhaustion attack
// surface: alias amplification, query-depth bomb, and batched-query
// acceptance. These are the three vectors most commonly missed when a
// team adds depth/complexity limits to one resolver but forgets the
// global guardrails.
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
func (d *Detector) Name() string { return "graphqldos" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Probes a GraphQL endpoint for resource-exhaustion attack surface: alias amplification, query-depth bombs, and batched-query acceptance — DoS primitives commonly missed by per-resolver complexity limits."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	// AliasCount is how many aliases to pack into the amplification query.
	AliasCount int
	// DepthCount is how many nesting levels to send.
	DepthCount int
	// BatchCount is how many queries to send in the batched-query array.
	BatchCount int
	// Timeout per request.
	Timeout time.Duration
}

// DefaultOptions returns conservative but indicative defaults — large
// enough to reveal missing limits, small enough to be safe against any
// production server in seconds.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		AliasCount: 100,
		DepthCount: 25,
		BatchCount: 20,
		Timeout:    10 * time.Second,
	}
}

// DetectionResult carries findings and the list of techniques that
// triggered.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Techniques []string
}

// Detect runs the three probes. The detector self-gates on a GraphQL
// response shape — non-GraphQL endpoints get exactly one round-trip.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:   make([]*core.Finding, 0),
		Techniques: make([]string, 0),
	}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}
	if opts.AliasCount <= 0 {
		opts.AliasCount = DefaultOptions().AliasCount
	}
	if opts.DepthCount <= 0 {
		opts.DepthCount = DefaultOptions().DepthCount
	}
	if opts.BatchCount <= 0 {
		opts.BatchCount = DefaultOptions().BatchCount
	}

	if !d.looksLikeGraphQL(ctx, target, opts) {
		return res, nil
	}

	if d.probeAliasAmplification(ctx, target, opts) {
		res.Techniques = append(res.Techniques, "alias_amplification")
		res.Findings = append(res.Findings, buildFinding("alias_amplification", target, opts))
	}
	if d.probeQueryDepth(ctx, target, opts) {
		res.Techniques = append(res.Techniques, "query_depth_unbounded")
		res.Findings = append(res.Findings, buildFinding("query_depth_unbounded", target, opts))
	}
	if d.probeBatchedQuery(ctx, target, opts) {
		res.Techniques = append(res.Techniques, "batched_query_allowed")
		res.Findings = append(res.Findings, buildFinding("batched_query_allowed", target, opts))
	}

	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// looksLikeGraphQL gates the detector on a response shape that has a
// "data" or "errors" envelope.
func (d *Detector) looksLikeGraphQL(ctx context.Context, target string, opts DetectOptions) bool {
	resp, err := d.postJSON(ctx, target, `{"query":"{ __typename }"}`, opts.Timeout)
	if err != nil || resp == nil {
		return false
	}
	if !strings.Contains(strings.ToLower(resp.ContentType), "json") {
		return false
	}
	return strings.Contains(resp.Body, `"data"`) || strings.Contains(resp.Body, `"errors"`)
}

// probeAliasAmplification fires a single query with AliasCount
// aliases of __typename. A server with an alias / complexity limit
// returns 4xx or an "errors" envelope without a "data" key.
func (d *Detector) probeAliasAmplification(ctx context.Context, target string, opts DetectOptions) bool {
	var sb strings.Builder
	sb.WriteString(`{"query":"{`)
	for i := 0; i < opts.AliasCount; i++ {
		fmt.Fprintf(&sb, " a%d: __typename", i)
	}
	sb.WriteString(` }"}`)
	resp, err := d.postJSON(ctx, target, sb.String(), opts.Timeout)
	if err != nil || resp == nil {
		return false
	}
	return looksLikeSuccess(resp)
}

// probeQueryDepth fires a deeply-nested fragment-style query. The
// server is expected to reject anything past a depth of ~10; accepting
// 25 reveals a missing depth limit.
func (d *Detector) probeQueryDepth(ctx context.Context, target string, opts DetectOptions) bool {
	var sb strings.Builder
	sb.WriteString(`{"query":"{ __schema`)
	for i := 0; i < opts.DepthCount; i++ {
		sb.WriteString(` { types`)
	}
	for i := 0; i < opts.DepthCount; i++ {
		sb.WriteString(` }`)
	}
	sb.WriteString(` }"}`)
	resp, err := d.postJSON(ctx, target, sb.String(), opts.Timeout)
	if err != nil || resp == nil {
		return false
	}
	return looksLikeSuccess(resp)
}

// probeBatchedQuery sends a JSON array of N queries in one POST. Some
// servers (Apollo with batching enabled, Yoga, older Hot Chocolate)
// process the entire array unbounded, multiplying every cost by N.
func (d *Detector) probeBatchedQuery(ctx context.Context, target string, opts DetectOptions) bool {
	var sb strings.Builder
	sb.WriteString(`[`)
	for i := 0; i < opts.BatchCount; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"query":"{ __typename }"}`)
	}
	sb.WriteString(`]`)
	resp, err := d.postJSON(ctx, target, sb.String(), opts.Timeout)
	if err != nil || resp == nil {
		return false
	}
	// Batched success: top-level array response with multiple data
	// envelopes. A single envelope (and no array) is the rejection.
	trimmed := strings.TrimSpace(resp.Body)
	if !strings.HasPrefix(trimmed, "[") {
		return false
	}
	return strings.Count(resp.Body, `"data"`) >= 2
}

// looksLikeSuccess returns true when the response is a 2xx with a
// JSON body containing a "data" envelope — i.e., the server actually
// processed the heavy query instead of refusing it.
func looksLikeSuccess(resp *scanhttp.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	if !strings.Contains(strings.ToLower(resp.ContentType), "json") {
		return false
	}
	return strings.Contains(resp.Body, `"data"`)
}

func (d *Detector) postJSON(ctx context.Context, target, body string, timeout time.Duration) (*scanhttp.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.client.Do(reqCtx, &scanhttp.Request{
		Method:      "POST",
		URL:         target,
		Body:        body,
		ContentType: "application/json",
	})
}

func buildFinding(technique, target string, opts DetectOptions) *core.Finding {
	titles := map[string]string{
		"alias_amplification":   "GraphQL alias amplification — N-fold cost multiplication on a single request accepted",
		"query_depth_unbounded": "GraphQL query depth unbounded — deeply nested selection accepted",
		"batched_query_allowed": "GraphQL batched-query DoS — server processes an unbounded array of queries per request",
	}
	descs := map[string]string{
		"alias_amplification":   fmt.Sprintf("The server accepted a single query containing %d aliases of the same field. Aliases let a client request the same expensive resolver N times in one request without paying N round-trips, and absent a per-request alias/complexity limit, an attacker can amplify any expensive operation to DoS-grade load.", opts.AliasCount),
		"query_depth_unbounded": fmt.Sprintf("The server accepted a query nested %d levels deep. Recursive types (User → friends → User → friends...) plus unbounded depth give an attacker an exponential blow-up in resolver work for a constant-size request. Apollo/Yoga/Hot Chocolate all ship depth-limit middleware that this server is missing.", opts.DepthCount),
		"batched_query_allowed": fmt.Sprintf("The server processed an array of %d queries in one HTTP request. Per-request rate limits become meaningless when one request equals N logical requests; per-resolver cost limits don't apply to the batch dimension. Either cap the batch size to a small constant or disable batching entirely.", opts.BatchCount),
	}
	f := core.NewFinding("GraphQL resource-exhaustion attack surface", core.SeverityMedium)
	f.Title = titles[technique]
	f.URL = target
	f.Tool = "graphqldos-detector"
	f.Description = descs[technique]
	f.Evidence = "single probe returned a successful GraphQL data envelope for the heavy query"
	f.Remediation = "Add a global query-complexity / alias-count / depth-limit middleware (Apollo `@graphql-tools/depth-limit`, Yoga `useDepthLimit`, Hot Chocolate `MaxAllowedFieldCycleDepth`). Cap batched queries to a small constant or disable batching on user-facing endpoints."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A04:2025"},
		[]string{"CWE-770", "CWE-400"},
	)
	return f
}
