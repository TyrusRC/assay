package racecond

import (
	"fmt"
	"sort"
)

// raceSignal describes why we believe a race window was observed. We do
// NOT use simple "responses differ" as a signal — that fires on any
// timestamped or counter-incrementing endpoint and is the source of the
// legacy detector's false-positive problem.
type raceSignal struct {
	Kind     string // "multi-success", "collision-error", "duplicate-state"
	Evidence string
}

// shapeKey collapses a response down to the bits an analyzer should care
// about. Bodies are bucketed by hash so we see "same shape" vs "different
// shape" without retaining bytes.
type shapeKey struct {
	Status int
	Hash   string
}

// analyzeBaselineDiff compares a sequential warm-up baseline to the burst.
// It returns a non-nil signal only when the burst shows a response shape
// that can only be explained by the requests racing against shared
// mutable state. Two signals are recognized, in priority order:
//
//  1. duplicate-state — every baseline response is unique (so the endpoint
//     emits per-request distinguishable bodies), but two burst responses
//     share a body. Two requests observed the same pre-update state.
//  2. multi-success — a 2xx shape that the baseline saw at most once
//     appears two or more times in the burst. Classic "first-wins"
//     resource being applied multiple times due to a TOCTOU window.
//
// Why duplicate-state is checked first: the multi-success criterion can
// also be satisfied by inputs that are *really* duplicate-state, since
// burst-shape count ≥ 2 with baseline count ≤ 1 also matches. Honoring
// the more specific signal first gives clearer evidence to the operator.
//
// We deliberately do NOT emit a "collision-error" signal on burst-only
// 4xx, even though it looks suspicious. Any properly-locked limit-of-N
// resource (coupon counter, rate-limited API) produces 4xx under burst
// while the sequential baseline doesn't — that's the system working as
// intended. Reporting it would generate FPs on every well-built API.
func analyzeBaselineDiff(baseline, burst []recordedResponse) *raceSignal {
	if validCount(baseline) < 1 || validCount(burst) < 2 {
		return nil
	}

	baselineShapes := countShapes(baseline)
	burstShapes := countShapes(burst)

	// Signal 1: duplicate-state.
	if isAllUnique(baseline) {
		seen := make(map[string]int)
		for _, r := range burst {
			if r.Err != nil {
				continue
			}
			seen[r.BodyHash]++
			if seen[r.BodyHash] >= 2 {
				return &raceSignal{
					Kind: "duplicate-state",
					Evidence: fmt.Sprintf(
						"baseline produced unique bodies per request, but two burst responses shared body hash %s — two requests observed identical pre-update state",
						r.BodyHash),
				}
			}
		}
	}

	// Signal 2: multi-success.
	for k, burstCount := range burstShapes {
		if k.Status < 200 || k.Status >= 300 {
			continue
		}
		if burstCount < 2 {
			continue
		}
		if baselineShapes[k] <= 1 {
			return &raceSignal{
				Kind: "multi-success",
				Evidence: fmt.Sprintf(
					"burst returned the same 2xx response shape %d times; baseline saw it %d time(s) — likely multiple requests applied the same first-wins side effect",
					burstCount, baselineShapes[k]),
			}
		}
	}

	return nil
}

func countShapes(resps []recordedResponse) map[shapeKey]int {
	out := make(map[shapeKey]int)
	for _, r := range resps {
		if r.Err != nil {
			continue
		}
		out[shapeKey{Status: r.StatusCode, Hash: r.BodyHash}]++
	}
	return out
}

func validCount(resps []recordedResponse) int {
	n := 0
	for _, r := range resps {
		if r.Err == nil {
			n++
		}
	}
	return n
}

func isAllUnique(resps []recordedResponse) bool {
	seen := make(map[string]struct{})
	count := 0
	for _, r := range resps {
		if r.Err != nil {
			continue
		}
		count++
		if _, ok := seen[r.BodyHash]; ok {
			return false
		}
		seen[r.BodyHash] = struct{}{}
	}
	return count >= 2
}

// summarizeShapes renders the response distribution into a stable string
// for finding evidence — sorted by status, then body hash, so test
// expectations don't depend on map iteration order.
func summarizeShapes(resps []recordedResponse) string {
	shapes := countShapes(resps)
	keys := make([]shapeKey, 0, len(shapes))
	for k := range shapes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Status != keys[j].Status {
			return keys[i].Status < keys[j].Status
		}
		return keys[i].Hash < keys[j].Hash
	})
	var b []byte
	for i, k := range keys {
		if i > 0 {
			b = append(b, ", "...)
		}
		b = append(b, fmt.Sprintf("status=%d body=%s ×%d", k.Status, k.Hash, shapes[k])...)
	}
	return string(b)
}
