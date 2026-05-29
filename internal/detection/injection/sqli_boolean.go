package injection

import (
	"context"
	"net/url"

	"github.com/TyrusRC/assay/internal/detection/analysis"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// blindSQLiSimilarityThreshold is the Jaccard cutoff for considering
// two stripped response bodies "equivalent" in the boolean-blind probe.
// 0.9 matches the BooleanDifferential default and tolerates per-request
// nonces (CSRF tokens, request IDs) without merging genuinely different
// result-set responses.
const blindSQLiSimilarityThreshold = 0.9

// booleanPayloadPair describes one (true, false) probe pair plus a
// build strategy that decides how the payload is combined with the
// parameter's original value. Most real-world blind SQLi sinks need the
// injection APPENDED to the original value so the SQL clause stays
// syntactically valid; some sinks need the payload replacing the value.
// We probe both shapes per pair.
type booleanPayloadPair struct {
	name         string
	truePayload  string
	falsePayload string
}

var booleanPayloadPairs = []booleanPayloadPair{
	{"single-quote", "' AND '1'='1", "' AND '1'='2"},
	{"single-quote-or", "' OR '1'='1", "' OR '1'='2"},
	{"single-quote-comment", "' AND '1'='1' --", "' AND '1'='2' --"},
	{"double-quote", "\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
	{"numeric", " AND 1=1", " AND 1=2"},
	{"numeric-or", " OR 1=1", " OR 1=2"},
}

// DetectBoolean probes a parameter for boolean-based blind SQLi by
// sending (baseline, true-condition, false-condition) triples for each
// canonical payload pair and watching for a TRUE/FALSE-controlled
// response shape.
//
// Two payload shapes per pair: REPLACE (payload becomes the value) and
// APPEND (original value + payload). PortSwigger-style sinks
// (?category=Gifts) need APPEND; searchTerm-style sinks where the
// baseline matches nothing benefit from REPLACE. Differentials in
// either direction count — (baseline ≈ true, ≠ false) OR (baseline ≈
// false, ≠ true) — both shapes prove the parameter controls the query
// result. AnalyzeResponse alone misses every blind variant; this
// primitive is what closes the gap.
func (d *SQLiDetector) DetectBoolean(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method string,
) (*BooleanResult, error) {
	res := &BooleanResult{}
	if client == nil {
		return res, nil
	}

	originalValue := extractParamValue(targetURL, param)

	// Build candidate (truePayload, falsePayload) probes from the static
	// pairs × {REPLACE, APPEND} shapes. Empty originalValue collapses
	// APPEND onto REPLACE, so we dedupe by string.
	type probe struct {
		shape string
		t, f  string
	}
	seen := make(map[string]bool)
	var probes []probe
	for _, pair := range booleanPayloadPairs {
		add := func(shape, tp, fp string) {
			key := shape + "|" + tp + "|" + fp
			if seen[key] {
				return
			}
			seen[key] = true
			probes = append(probes, probe{shape, tp, fp})
		}
		add("replace", pair.truePayload, pair.falsePayload)
		if originalValue != "" {
			add("append", originalValue+pair.truePayload, originalValue+pair.falsePayload)
		}
	}

	// Baseline is the original URL — sent ONCE, reused across all probes.
	baselineResp, err := client.Get(ctx, targetURL)
	if err != nil || baselineResp == nil {
		return res, err
	}
	baselineStripped := analysis.StripDynamicContent(baselineResp.Body)

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		trueResp, err := client.SendPayload(ctx, targetURL, param, p.t, method)
		if err != nil || trueResp == nil {
			continue
		}
		falseResp, err := client.SendPayload(ctx, targetURL, param, p.f, method)
		if err != nil || falseResp == nil {
			continue
		}

		// Only meaningful if true and false are themselves divergent.
		// If true ≈ false, the parameter doesn't matter at all (or the
		// request is being WAFed identically) — no differential to claim.
		trueStripped := analysis.StripDynamicContent(trueResp.Body)
		falseStripped := analysis.StripDynamicContent(falseResp.Body)
		trueFalseSim := analysis.ResponseSimilarity(trueStripped, falseStripped)
		if trueFalseSim >= blindSQLiSimilarityThreshold {
			continue
		}

		baseTrueSim := analysis.ResponseSimilarity(baselineStripped, trueStripped)
		baseFalseSim := analysis.ResponseSimilarity(baselineStripped, falseStripped)

		baseTrueClose := baseTrueSim >= blindSQLiSimilarityThreshold
		baseFalseClose := baseFalseSim >= blindSQLiSimilarityThreshold

		// Differential in either direction:
		//   shape A: baseline ≈ true,  baseline ≠ false   (PortSwigger /catalog?category=Gifts)
		//   shape B: baseline ≈ false, baseline ≠ true    (no-match baseline, true reveals data)
		var confidence float64
		switch {
		case baseTrueClose && !baseFalseClose:
			confidence = baseTrueSim * (1.0 - baseFalseSim)
		case baseFalseClose && !baseTrueClose:
			confidence = baseFalseSim * (1.0 - baseTrueSim)
		default:
			continue
		}

		res.IsVulnerable = true
		res.DetectionType = "boolean-based"
		res.Confidence = confidence
		res.TruePayload = p.t
		res.FalsePayload = p.f
		return res, nil
	}
	return res, nil
}

// extractParamValue returns the current value of the named query
// parameter in rawURL, or "" if unset/malformed.
func extractParamValue(rawURL, param string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get(param)
}
