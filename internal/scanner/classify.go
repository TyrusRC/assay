package scanner

import (
	"context"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// canaryString is a unique string used to detect reflection in responses.
const canaryString = "skws7x8q9"

// ClassifyParameter sends probe requests for a single parameter to detect
// reflection, content type, and classification. It modifies the parameter in place.
func ClassifyParameter(ctx context.Context, client *http.Client, targetURL string, param *core.Parameter, method string) {
	// Always set classification from name heuristics
	param.Classify()

	// Try to send canary to detect reflection
	resp, err := client.SendPayload(ctx, targetURL, param.Name, canaryString, method)
	if err != nil {
		return
	}

	// Record content type from response
	param.ContentType = resp.ContentType

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
