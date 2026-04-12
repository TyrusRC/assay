package analysis

import (
	"context"

	skwshttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

// defaultSimilarityThreshold is the default threshold for considering two
// responses as "the same" in boolean differential analysis.
const defaultSimilarityThreshold = 0.9

// DifferentialResult contains the result of boolean differential analysis.
type DifferentialResult struct {
	// IsDifferential indicates whether a true boolean differential was detected.
	IsDifferential bool
	// Confidence is a value between 0.0 and 1.0 indicating how confident the
	// analysis is in its conclusion.
	Confidence float64
	// BaselineBody is the response body from the baseline (original) request.
	BaselineBody string
	// TrueBody is the response body from the true-condition payload request.
	TrueBody string
	// FalseBody is the response body from the false-condition payload request.
	FalseBody string
}

// BooleanDifferential performs boolean-based differential analysis by comparing
// responses from baseline, true-condition, and false-condition requests.
type BooleanDifferential struct {
	similarityThreshold float64
}

// NewBooleanDifferential creates a new BooleanDifferential analyzer with the
// default similarity threshold.
func NewBooleanDifferential() *BooleanDifferential {
	return &BooleanDifferential{
		similarityThreshold: defaultSimilarityThreshold,
	}
}

// Analyze sends three requests: a baseline (original parameter), a true-condition
// payload, and a false-condition payload. It then compares the responses:
// - baseline and false should be similar (both evaluate to "normal" behavior)
// - baseline and true should differ (true condition reveals different behavior)
// If baseline~false are similar AND baseline!=true, it reports a differential.
// Returns a DifferentialResult with confidence score.
func (bd *BooleanDifferential) Analyze(
	ctx context.Context,
	client *skwshttp.Client,
	targetURL, param, method, truePayload, falsePayload string,
) *DifferentialResult {
	result := &DifferentialResult{}

	// Send baseline request (original URL without payload modification).
	baselineResp, err := client.Get(ctx, targetURL)
	if err != nil {
		return result
	}
	result.BaselineBody = baselineResp.Body

	// Send true-condition payload.
	trueResp, err := client.SendPayload(ctx, targetURL, param, truePayload, method)
	if err != nil {
		return result
	}
	result.TrueBody = trueResp.Body

	// Send false-condition payload.
	falseResp, err := client.SendPayload(ctx, targetURL, param, falsePayload, method)
	if err != nil {
		return result
	}
	result.FalseBody = falseResp.Body

	// Compare: baseline and false should be similar.
	baselineFalseSimilar := IsSameResponse(baselineResp, falseResp, bd.similarityThreshold)

	// Compare: baseline and true should be different.
	baselineTrueSimilar := IsSameResponse(baselineResp, trueResp, bd.similarityThreshold)

	if baselineFalseSimilar && !baselineTrueSimilar {
		result.IsDifferential = true

		// Compute confidence based on how different the true response is from
		// baseline and how similar the false response is to baseline.
		strippedBaseline := StripDynamicContent(baselineResp.Body)
		strippedTrue := StripDynamicContent(trueResp.Body)
		strippedFalse := StripDynamicContent(falseResp.Body)

		trueSim := ResponseSimilarity(strippedBaseline, strippedTrue)
		falseSim := ResponseSimilarity(strippedBaseline, strippedFalse)

		// Confidence: how much false matches baseline * how much true diverges.
		result.Confidence = falseSim * (1.0 - trueSim)
	}

	return result
}
