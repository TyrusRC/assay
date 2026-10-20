package injection

import (
	"context"

	"github.com/TyrusRC/assay/internal/detection/analysis"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// differentialProbeValue is the clean baseline value sent to the
// parameter. It is alphanumeric to avoid accidentally triggering
// injection-shaped behaviour on its own.
const differentialProbeValue = "validtest123"

// differentialQuotePair is a (clean, broken) pair where the broken
// variant appends a SQL metacharacter. A response change between clean
// and broken indicates the metacharacter reached a SQL parser.
type differentialQuotePair struct {
	name   string
	clean  string
	broken string
}

var differentialQuotePairs = []differentialQuotePair{
	{"single-quote", differentialProbeValue, differentialProbeValue + "'"},
	{"double-quote", differentialProbeValue, differentialProbeValue + "\""},
	{"backslash", differentialProbeValue, differentialProbeValue + "\\"},
}

// differentialConfirmPair is a (true, false) pair used to confirm that
// the differential is SQL-controlled, not a generic WAF/input-validation
// artefact.
type differentialConfirmPair struct {
	name         string
	truePayload  string
	falsePayload string
}

var differentialConfirmPairs = []differentialConfirmPair{
	{"string-and", differentialProbeValue + "' AND '1'='1", differentialProbeValue + "' AND '1'='2"},
	{"string-or", differentialProbeValue + "' OR '1'='1", differentialProbeValue + "' OR '1'='2"},
	{"numeric-and", "1 AND 1=1", "1 AND 1=2"},
}

// DetectDifferential probes a parameter for SQL injection by observing
// response-shape changes when SQL metacharacters are appended.
//
// Unlike DetectBoolean, this method does NOT extract the parameter's
// current value from the query string: all payloads go through
// client.SendPayload, which (via ForParam / SendPayloadAt) dispatches to
// the correct location (JSON body, header, path segment, cookie, query).
// This makes it work on JSON body and header params where
// extractParamValue returns "".
func (d *SQLiDetector) DetectDifferential(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method string,
) (*BooleanResult, error) {
	res := &BooleanResult{}
	if client == nil {
		return res, nil
	}

	// Phase 1: send a clean probe twice to establish stability.
	cleanResp1, err := client.SendPayload(ctx, targetURL, param, differentialProbeValue, method)
	if err != nil || cleanResp1 == nil {
		return res, err
	}
	cleanResp2, err := client.SendPayload(ctx, targetURL, param, differentialProbeValue, method)
	if err != nil || cleanResp2 == nil {
		return res, err
	}

	clean1 := analysis.StripDynamicContent(cleanResp1.Body)
	clean2 := analysis.StripDynamicContent(cleanResp2.Body)
	if analysis.ResponseSimilarity(clean1, clean2) < blindSQLiSimilarityThreshold {
		return res, nil
	}

	// Phase 2: for each quote pair, check if the metacharacter changes
	// the response shape.
	for _, qp := range differentialQuotePairs {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		brokenResp, err := client.SendPayload(ctx, targetURL, param, qp.broken, method)
		if err != nil || brokenResp == nil {
			continue
		}
		brokenBody := analysis.StripDynamicContent(brokenResp.Body)

		cleanBrokenSim := analysis.ResponseSimilarity(clean1, brokenBody)
		if cleanBrokenSim >= blindSQLiSimilarityThreshold {
			continue
		}

		// Phase 3: confirm the differential is SQL-controlled with a
		// true/false boolean pair.
		confirmed, trueP, falseP, conf := d.confirmDifferential(ctx, client, targetURL, param, method, clean1)
		if !confirmed {
			// No confirmation — still report at lower confidence based on
			// the quote-break alone. A response change on metacharacter
			// insertion that cannot be confirmed with boolean pairs is
			// suspicious but not conclusive.
			continue
		}

		res.IsVulnerable = true
		res.DetectionType = "response-differential"
		res.Confidence = conf
		res.TruePayload = trueP
		res.FalsePayload = falseP
		return res, nil
	}

	return res, nil
}

// confirmDifferential sends (true, false) confirmation pairs and checks
// whether exactly one of them matches the clean baseline.
func (d *SQLiDetector) confirmDifferential(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method, cleanBody string,
) (confirmed bool, truePayload, falsePayload string, confidence float64) {
	for _, cp := range differentialConfirmPairs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		trueResp, err := client.SendPayload(ctx, targetURL, param, cp.truePayload, method)
		if err != nil || trueResp == nil {
			continue
		}
		falseResp, err := client.SendPayload(ctx, targetURL, param, cp.falsePayload, method)
		if err != nil || falseResp == nil {
			continue
		}

		trueBody := analysis.StripDynamicContent(trueResp.Body)
		falseBody := analysis.StripDynamicContent(falseResp.Body)

		trueFalseSim := analysis.ResponseSimilarity(trueBody, falseBody)
		if trueFalseSim >= blindSQLiSimilarityThreshold {
			continue
		}

		cleanTrueSim := analysis.ResponseSimilarity(cleanBody, trueBody)
		cleanFalseSim := analysis.ResponseSimilarity(cleanBody, falseBody)

		trueClose := cleanTrueSim >= blindSQLiSimilarityThreshold
		falseClose := cleanFalseSim >= blindSQLiSimilarityThreshold

		switch {
		case trueClose && !falseClose:
			confidence = cleanTrueSim * (1.0 - cleanFalseSim)
		case falseClose && !trueClose:
			confidence = cleanFalseSim * (1.0 - cleanTrueSim)
		default:
			continue
		}

		return true, cp.truePayload, cp.falsePayload, confidence
	}
	return false, "", "", 0
}
