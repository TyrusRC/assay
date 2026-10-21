package scanner

import (
	"context"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// canaryString is a unique string used to detect reflection in responses.
const canaryString = "skws7x8q9"

// ClassifyParameter sends probe requests for a single parameter to detect
// reflection, content type, and classification. It modifies the parameter in place.
func ClassifyParameter(ctx context.Context, client *http.Client, targetURL string, param *core.Parameter, method string) {
	// Always set classification from name heuristics
	param.Classify()

	// Use the param's own method when set (body params from forms have
	// Method=POST), falling back to the scan method.
	probeMethod := method
	if param.Method != "" {
		probeMethod = param.Method
	}
	probeURL := targetURL
	if param.SourceURL != "" {
		probeURL = param.SourceURL
	}

	// Try to send canary to detect reflection
	resp, err := client.SendPayload(ctx, probeURL, param.Name, canaryString, probeMethod)
	if err != nil {
		return
	}

	// Content-type negotiation for body params: if form-urlencoded
	// returns 500, the endpoint may only accept JSON (SPA / JS-driven).
	// Retry with JSON; if it works, tag the param so all subsequent
	// probes use JSON instead of form-urlencoded.
	if resp.StatusCode == 500 && param.Location == core.ParamLocationBody && param.ContentType == "" {
		jsonResp, jsonErr := client.SendPayloadInJSON(ctx, probeURL, param.Name, canaryString)
		if jsonErr == nil && jsonResp != nil && jsonResp.StatusCode != 500 {
			resp = jsonResp
			param.ContentType = "application/json"
		}
	}

	// Record content type from response (if not already set by negotiation)
	if param.ContentType == "" {
		param.ContentType = resp.ContentType
	}

	// Check if canary is reflected in response body or headers
	if strings.Contains(resp.Body, canaryString) {
		param.Reflected = true
		return
	}

	// Also check response headers for reflection
	for _, v := range resp.Headers {
		if strings.Contains(v, canaryString) {
			param.Reflected = true
			return
		}
	}
}

// ClassifyParameters runs ClassifyParameter on each parameter in the slice.
// Parameters are modified in place with Reflected, ContentType, and Classification fields set.
func ClassifyParameters(ctx context.Context, client *http.Client, targetURL string, params []core.Parameter, method string) {
	for i := range params {
		select {
		case <-ctx.Done():
			// Still classify remaining from heuristics
			for j := i; j < len(params); j++ {
				params[j].Classify()
			}
			return
		default:
		}
		ClassifyParameter(ctx, client, targetURL, &params[i], method)
	}
}
