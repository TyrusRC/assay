package injection

import (
	"context"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/analysis"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// DetectBooleanAt is the location-aware variant of DetectBoolean. It accepts
// a send function so the caller can route through SendPayloadAt, making it
// work for header, path, cookie and JSON-body parameters — not just query.
//
// Unlike DetectBoolean, this method does not try to recover the parameter's
// "original value" from the URL query string. It sends REPLACE-only probes:
// each boolean pair is sent verbatim as the parameter value. This is the
// correct behaviour for non-query locations where the original value is
// unknown (headers, JSON body fields, path segments, cookies).
func (d *SQLiDetector) DetectBooleanAt(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL string,
	param core.Parameter,
	method string,
	send func(ctx context.Context, payload string) (*assayhttp.Response, error),
) (*BooleanResult, error) {
	res := &BooleanResult{}
	if client == nil {
		return res, nil
	}

	baselineResp, err := client.Get(ctx, targetURL)
	if err != nil || baselineResp == nil {
		return res, err
	}
	baselineStripped := analysis.StripDynamicContent(baselineResp.Body)

	// Also try with an empty send to establish what the endpoint returns
	// when the header/body is just a benign value.
	cleanResp, _ := send(ctx, "assay_baseline_probe")
	if cleanResp != nil {
		baselineResp = cleanResp
		baselineStripped = analysis.StripDynamicContent(cleanResp.Body)
	}

	for _, pair := range booleanPayloadPairs {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		trueResp, err := send(ctx, pair.truePayload)
		if err != nil || trueResp == nil {
			continue
		}
		falseResp, err := send(ctx, pair.falsePayload)
		if err != nil || falseResp == nil {
			continue
		}

		// Status-code differential: OR-bypass returns 200, false stays 401.
		if trueResp.StatusCode != falseResp.StatusCode {
			if trueResp.StatusCode != baselineResp.StatusCode || falseResp.StatusCode != baselineResp.StatusCode {
				res.IsVulnerable = true
				res.DetectionType = "boolean-based (status differential)"
				res.Confidence = 0.80
				res.TruePayload = pair.truePayload
				res.FalsePayload = pair.falsePayload
				return res, nil
			}
		}

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
		res.TruePayload = pair.truePayload
		res.FalsePayload = pair.falsePayload
		return res, nil
	}
	return res, nil
}
