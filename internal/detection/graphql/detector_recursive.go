package graphql

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// RecursiveOptions configures the recursive / amplification cost probes.
//
// All four probes (recursive fragments, type-recursion, field-duplication,
// directive overload) share the same option struct because they all use the
// same baseline-vs-probe comparison: send a tiny baseline query, capture its
// duration / body size, send the probe query, and compare.
type RecursiveOptions struct {
	// FragmentDepth controls the nesting depth used by the recursive
	// fragment query. 50 is well over any legitimate query depth but
	// small enough to type-out clearly in the probe payload.
	FragmentDepth int
	// TypeIntrospectionDepth is the number of `fields { type { ... } }`
	// chains in the __type recursion probe.
	TypeIntrospectionDepth int
	// DuplicationCount is the number of aliased copies of the same field
	// to pack into the amplification probe (default 100, matching the
	// canonical bug-bounty payload).
	DuplicationCount int
	// DirectiveCount is the number of @include/@skip directives to nest
	// into the overload probe.
	DirectiveCount int
	// TimeAmplificationFactor: probe response time must be at least
	// this multiple of the baseline to flag a finding (default 5).
	TimeAmplificationFactor float64
	// SizeAmplificationFactor: probe response body must be at least this
	// multiple of the baseline to flag a finding (default 100 for
	// fragment / type recursion, but compared against
	// DuplicationCount/2 for the duplication probe — see implementation).
	SizeAmplificationFactor float64
	// MaxResponseBytes caps how much of the response body we'll parse to
	// keep memory bounded against intentionally hostile servers.
	MaxResponseBytes int
}

// DefaultRecursiveOptions returns sane defaults for the recursive cost probes.
func DefaultRecursiveOptions() RecursiveOptions {
	return RecursiveOptions{
		FragmentDepth:           50,
		TypeIntrospectionDepth:  10,
		DuplicationCount:        100,
		DirectiveCount:          50,
		TimeAmplificationFactor: 5.0,
		SizeAmplificationFactor: 100.0,
		MaxResponseBytes:        4 * 1024 * 1024,
	}
}

func applyRecursiveDefaults(o RecursiveOptions) RecursiveOptions {
	d := DefaultRecursiveOptions()
	if o.FragmentDepth <= 0 {
		o.FragmentDepth = d.FragmentDepth
	}
	if o.TypeIntrospectionDepth <= 0 {
		o.TypeIntrospectionDepth = d.TypeIntrospectionDepth
	}
	if o.DuplicationCount <= 0 {
		o.DuplicationCount = d.DuplicationCount
	}
	if o.DirectiveCount <= 0 {
		o.DirectiveCount = d.DirectiveCount
	}
	if o.TimeAmplificationFactor <= 0 {
		o.TimeAmplificationFactor = d.TimeAmplificationFactor
	}
	if o.SizeAmplificationFactor <= 0 {
		o.SizeAmplificationFactor = d.SizeAmplificationFactor
	}
	if o.MaxResponseBytes <= 0 {
		o.MaxResponseBytes = d.MaxResponseBytes
	}
	return o
}

// baseline sends a tiny GraphQL probe (`{ __typename }`) to capture per-target
// latency and response size for amplification comparisons.
//
// We deliberately use __typename rather than a real field because every spec-
// compliant GraphQL server accepts it without authentication, and its response
// body is always a small fixed-shape object.
func (d *Detector) baseline(ctx context.Context, target string) (time.Duration, int, error) {
	body, err := d.BuildGraphQLRequest(`query { __typename }`, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("build baseline: %w", err)
	}
	resp, err := d.client.PostJSON(ctx, target, body)
	if err != nil {
		return 0, 0, fmt.Errorf("baseline request: %w", err)
	}
	// Treat absurd 5xx baselines as unusable — the server is misbehaving and
	// any amplification ratio would be meaningless.
	if resp.StatusCode >= 500 {
		return 0, 0, fmt.Errorf("baseline returned status %d", resp.StatusCode)
	}
	return resp.Duration, len(resp.Body), nil
}

// amplifies returns true if either the latency or body-size ratio of probe to
// baseline exceeds the configured threshold. A nil baseline (zero duration
// AND zero body) cannot be amplified — return false.
//
// The minBaseline guard avoids dividing by ~0 for very fast loopback servers
// where a 1ms baseline would make any non-trivial probe look "infinite".
func amplifies(probeDur, baseDur time.Duration, probeSize, baseSize int, opts RecursiveOptions) (timeAmp, sizeAmp float64, flag bool) {
	const minBaselineDur = time.Millisecond
	const minBaselineSize = 16

	bDur := baseDur
	if bDur < minBaselineDur {
		bDur = minBaselineDur
	}
	bSize := baseSize
	if bSize < minBaselineSize {
		bSize = minBaselineSize
	}

	timeAmp = float64(probeDur) / float64(bDur)
	sizeAmp = float64(probeSize) / float64(bSize)
	flag = timeAmp >= opts.TimeAmplificationFactor || sizeAmp >= opts.SizeAmplificationFactor
	return
}

// cappedBodyLen returns the effective body length used for comparisons; it
// honors the MaxResponseBytes cap so a malicious server can't trick us into
// over-allocating just by streaming a multi-GiB response.
func cappedBodyLen(body string, maxBytes int) int {
	if maxBytes > 0 && len(body) > maxBytes {
		return maxBytes
	}
	return len(body)
}

// newRecursiveFinding stamps the shared OWASP / API / CWE / tool metadata onto
// a finding produced by any of the four recursive-cost probes.
func newRecursiveFinding(findingType, target, description, evidence string) *core.Finding {
	f := core.NewFinding(findingType, core.SeverityHigh)
	f.URL = target
	f.Tool = "graphql-recursive-detector"
	f.Description = description
	f.Evidence = evidence
	f.Confidence = core.ConfidenceHigh
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A02:2025"},
		[]string{"CWE-400", "CWE-770"},
	)
	f.APITop10 = []string{"API4:2023"}
	f.Remediation = "Enforce query cost / depth / complexity analysis at the GraphQL gateway. " +
		"Reject queries that exceed configured complexity budgets before resolver execution. " +
		"For Apollo: use the operation-complexity / max-depth plugins. " +
		"For Hasura: configure depth, node and rate limits per role. " +
		"Forbid recursive fragments via static analysis or schema-aware validators."
	return f
}

// DetectRecursiveFragments probes whether the server accepts self-referencing
// fragments and processes them without cycle detection.
//
// The probe sends:
//
//	fragment F on User { friends { ...F } }
//	query { user(id: "x") { ...F } }
//
// A safe server rejects the query with a "Cannot spread fragment within itself"
// validation error. A vulnerable server either OOMs, returns a large expanded
// body, or stalls — we flag based on a 5x latency OR 100x body-size ratio
// relative to a `{ __typename }` baseline.
func (d *Detector) DetectRecursiveFragments(ctx context.Context, target string, opts RecursiveOptions) (*DetectionResult, error) {
	opts = applyRecursiveDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0), Endpoint: target}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	baseDur, baseSize, err := d.baseline(ctx, target)
	if err != nil {
		return result, err
	}

	probeQuery := buildRecursiveFragmentQuery(opts.FragmentDepth)
	body, err := d.BuildGraphQLRequest(probeQuery, nil)
	if err != nil {
		return result, fmt.Errorf("build recursive fragment request: %w", err)
	}
	resp, err := d.client.PostJSON(ctx, target, body)
	if err != nil {
		return result, fmt.Errorf("recursive fragment probe: %w", err)
	}
	// A server that crashes with a 5xx during recursive expansion is itself a
	// strong signal — but we only flag when the request *succeeds* (2xx) AND
	// amplifies, to avoid false positives from misconfigured proxies / WAFs.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Validation error like "Cannot spread fragment within itself" — safe.
		return result, nil
	}

	probeSize := cappedBodyLen(resp.Body, opts.MaxResponseBytes)
	timeAmp, sizeAmp, flag := amplifies(resp.Duration, baseDur, probeSize, baseSize, opts)
	if !flag {
		return result, nil
	}

	evidence := strings.Join([]string{
		fmt.Sprintf("baseline duration:   %s", baseDur),
		fmt.Sprintf("probe duration:      %s", resp.Duration),
		fmt.Sprintf("baseline body size:  %d bytes", baseSize),
		fmt.Sprintf("probe body size:     %d bytes", probeSize),
		fmt.Sprintf("time amplification:  %.1fx (threshold %.1fx)", timeAmp, opts.TimeAmplificationFactor),
		fmt.Sprintf("size amplification:  %.1fx (threshold %.1fx)", sizeAmp, opts.SizeAmplificationFactor),
	}, "\n")
	description := fmt.Sprintf(
		"The server accepted a self-referencing GraphQL fragment (depth %d) without cycle detection. "+
			"Response was %.1fx slower and/or %.1fx larger than baseline, indicating uncontrolled expansion. "+
			"An attacker can use this to mount a denial-of-service attack.",
		opts.FragmentDepth, timeAmp, sizeAmp,
	)
	f := newRecursiveFinding("GraphQL Recursive Fragment Cost", target, description, evidence)
	f.Metadata["timeAmplification"] = timeAmp
	f.Metadata["sizeAmplification"] = sizeAmp
	f.Metadata["fragmentDepth"] = opts.FragmentDepth
	result.Findings = append(result.Findings, f)
	return result, nil
}

// DetectTypeRecursion probes whether the server allows arbitrarily deep
// `__type { fields { type { fields { ... }}}}` chains.
//
// This is a special case of introspection abuse: even if regular query depth
// is limited, the introspection schema can be traversed recursively because
// every type ultimately points back to its own fields. Many engines lack a
// dedicated introspection-depth limit.
func (d *Detector) DetectTypeRecursion(ctx context.Context, target string, opts RecursiveOptions) (*DetectionResult, error) {
	opts = applyRecursiveDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0), Endpoint: target}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	baseDur, baseSize, err := d.baseline(ctx, target)
	if err != nil {
		return result, err
	}

	probeQuery := buildTypeRecursionQuery(opts.TypeIntrospectionDepth)
	body, err := d.BuildGraphQLRequest(probeQuery, nil)
	if err != nil {
		return result, fmt.Errorf("build __type recursion request: %w", err)
	}
	resp, err := d.client.PostJSON(ctx, target, body)
	if err != nil {
		return result, fmt.Errorf("__type recursion probe: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, nil
	}

	probeSize := cappedBodyLen(resp.Body, opts.MaxResponseBytes)
	timeAmp, sizeAmp, flag := amplifies(resp.Duration, baseDur, probeSize, baseSize, opts)
	if !flag {
		return result, nil
	}

	evidence := strings.Join([]string{
		fmt.Sprintf("baseline duration:   %s", baseDur),
		fmt.Sprintf("probe duration:      %s", resp.Duration),
		fmt.Sprintf("baseline body size:  %d bytes", baseSize),
		fmt.Sprintf("probe body size:     %d bytes", probeSize),
		fmt.Sprintf("time amplification:  %.1fx (threshold %.1fx)", timeAmp, opts.TimeAmplificationFactor),
		fmt.Sprintf("size amplification:  %.1fx (threshold %.1fx)", sizeAmp, opts.SizeAmplificationFactor),
	}, "\n")
	description := fmt.Sprintf(
		"The server processed a deeply chained __type introspection query (%d levels of fields { type { fields ... }}) "+
			"with %.1fx time and %.1fx size amplification over baseline. Introspection-depth limits are absent.",
		opts.TypeIntrospectionDepth, timeAmp, sizeAmp,
	)
	f := newRecursiveFinding("GraphQL Type Introspection Recursion", target, description, evidence)
	f.Metadata["timeAmplification"] = timeAmp
	f.Metadata["sizeAmplification"] = sizeAmp
	f.Metadata["typeIntrospectionDepth"] = opts.TypeIntrospectionDepth
	result.Findings = append(result.Findings, f)
	return result, nil
}

// DetectFieldDuplicationAmplification probes whether the server deduplicates
// repeated aliased calls to the same field with the same arguments.
//
// Most production servers do NOT dedupe — DataLoader and similar caches only
// dedupe inside a single resolver pass; the network-level request body grows
// linearly. The probe sends 100 aliased `user(id:"1")` calls and flags if the
// response inflates linearly (close to 100x the single-call baseline body).
func (d *Detector) DetectFieldDuplicationAmplification(ctx context.Context, target string, opts RecursiveOptions) (*DetectionResult, error) {
	opts = applyRecursiveDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0), Endpoint: target}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Baseline = single `user(id:"1")` call, not `__typename`, because we want
	// to measure per-field cost, not per-request overhead.
	singleQuery := `query { user(id: "1") { id name } }`
	singleBody, err := d.BuildGraphQLRequest(singleQuery, nil)
	if err != nil {
		return result, fmt.Errorf("build duplication baseline: %w", err)
	}
	singleResp, err := d.client.PostJSON(ctx, target, singleBody)
	if err != nil {
		return result, fmt.Errorf("duplication baseline request: %w", err)
	}
	if singleResp.StatusCode < 200 || singleResp.StatusCode >= 300 {
		return result, nil
	}

	baseDur := singleResp.Duration
	baseSize := len(singleResp.Body)

	probeQuery := buildFieldDuplicationQuery(opts.DuplicationCount)
	probeBody, err := d.BuildGraphQLRequest(probeQuery, nil)
	if err != nil {
		return result, fmt.Errorf("build duplication probe: %w", err)
	}
	probeResp, err := d.client.PostJSON(ctx, target, probeBody)
	if err != nil {
		return result, fmt.Errorf("duplication probe: %w", err)
	}

	// Hard server-side reject: alias-count limit kicked in. That IS the
	// correct defense — no finding.
	if probeResp.StatusCode == 429 || probeResp.StatusCode == 413 || probeResp.StatusCode == 400 {
		return result, nil
	}
	if probeResp.StatusCode < 200 || probeResp.StatusCode >= 300 {
		return result, nil
	}

	probeSize := cappedBodyLen(probeResp.Body, opts.MaxResponseBytes)

	// For duplication, the signal is "did response size grow roughly linearly
	// with N?" — a dedupe-aware server returns a single user object regardless
	// of how many aliases asked for it. We use a tighter threshold here: half
	// the DuplicationCount, because some shrink from compact JSON encoding is
	// expected.
	expectedRatio := float64(opts.DuplicationCount) / 2.0
	if expectedRatio < 5 {
		expectedRatio = 5
	}
	sizeAmp := float64(probeSize) / float64(maxInt(baseSize, 16))
	timeAmp := float64(probeResp.Duration) / float64(durMax(baseDur, time.Millisecond))

	if sizeAmp < expectedRatio && timeAmp < opts.TimeAmplificationFactor {
		return result, nil
	}

	evidence := strings.Join([]string{
		fmt.Sprintf("baseline single-call body:   %d bytes", baseSize),
		fmt.Sprintf("probe body (%d aliases):    %d bytes", opts.DuplicationCount, probeSize),
		fmt.Sprintf("size amplification:          %.1fx (expected linear ratio %.1fx)", sizeAmp, expectedRatio),
		fmt.Sprintf("baseline duration:           %s", baseDur),
		fmt.Sprintf("probe duration:              %s", probeResp.Duration),
		fmt.Sprintf("time amplification:          %.1fx", timeAmp),
	}, "\n")
	description := fmt.Sprintf(
		"The server returned a response that inflated linearly with the number of duplicated aliased calls "+
			"(%d copies of the same user(id:\"1\") field). Response body grew %.1fx vs. a single-call baseline, "+
			"indicating no per-request field deduplication. This amplifies the cost of any expensive resolver.",
		opts.DuplicationCount, sizeAmp,
	)
	f := newRecursiveFinding("GraphQL Field Duplication Amplification", target, description, evidence)
	f.Metadata["sizeAmplification"] = sizeAmp
	f.Metadata["timeAmplification"] = timeAmp
	f.Metadata["duplicationCount"] = opts.DuplicationCount
	result.Findings = append(result.Findings, f)
	return result, nil
}

// DetectDirectiveOverload probes whether the server processes queries with a
// large number of @include / @skip directives without complaint.
//
// Many engines evaluate every directive per-field per-resolver-pass; stacking
// dozens of them on a single field creates a multiplicative cost that maps
// directly to CPU time. A safe server caps directive count per node or per
// document.
func (d *Detector) DetectDirectiveOverload(ctx context.Context, target string, opts RecursiveOptions) (*DetectionResult, error) {
	opts = applyRecursiveDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0), Endpoint: target}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	baseDur, baseSize, err := d.baseline(ctx, target)
	if err != nil {
		return result, err
	}

	probeQuery := buildDirectiveOverloadQuery(opts.DirectiveCount)
	body, err := d.BuildGraphQLRequest(probeQuery, nil)
	if err != nil {
		return result, fmt.Errorf("build directive overload request: %w", err)
	}
	resp, err := d.client.PostJSON(ctx, target, body)
	if err != nil {
		return result, fmt.Errorf("directive overload probe: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, nil
	}

	probeSize := cappedBodyLen(resp.Body, opts.MaxResponseBytes)
	timeAmp, sizeAmp, flag := amplifies(resp.Duration, baseDur, probeSize, baseSize, opts)
	if !flag {
		return result, nil
	}

	evidence := strings.Join([]string{
		fmt.Sprintf("baseline duration:   %s", baseDur),
		fmt.Sprintf("probe duration:      %s", resp.Duration),
		fmt.Sprintf("baseline body size:  %d bytes", baseSize),
		fmt.Sprintf("probe body size:     %d bytes", probeSize),
		fmt.Sprintf("directives sent:     %d", opts.DirectiveCount),
		fmt.Sprintf("time amplification:  %.1fx (threshold %.1fx)", timeAmp, opts.TimeAmplificationFactor),
		fmt.Sprintf("size amplification:  %.1fx (threshold %.1fx)", sizeAmp, opts.SizeAmplificationFactor),
	}, "\n")
	description := fmt.Sprintf(
		"The server accepted a query carrying %d nested @include/@skip directives without rejection, "+
			"with %.1fx time and %.1fx size amplification over baseline. Directive count limits are absent.",
		opts.DirectiveCount, timeAmp, sizeAmp,
	)
	f := newRecursiveFinding("GraphQL Directive Overload", target, description, evidence)
	f.Metadata["timeAmplification"] = timeAmp
	f.Metadata["sizeAmplification"] = sizeAmp
	f.Metadata["directiveCount"] = opts.DirectiveCount
	result.Findings = append(result.Findings, f)
	return result, nil
}

// AnalyzeRecursiveResponse is a public helper that callers can use to make a
// flag decision from a captured response without re-issuing requests.
func AnalyzeRecursiveResponse(probeBody string, probeDur time.Duration, baseSize int, baseDur time.Duration, opts RecursiveOptions) (timeAmp, sizeAmp float64, flag bool) {
	opts = applyRecursiveDefaults(opts)
	probeSize := cappedBodyLen(probeBody, opts.MaxResponseBytes)
	return amplifies(probeDur, baseDur, probeSize, baseSize, opts)
}
