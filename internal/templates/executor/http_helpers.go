package executor

import (
	"fmt"

	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/templates"
	"github.com/TyrusRC/assay/internal/templates/matchers"
)

// clientForRequest returns a client clone with per-request redirect
// settings applied.
func (e *Executor) clientForRequest(httpReq *templates.HTTPRequest) *http.Client {
	if httpReq.Redirects {
		return e.client.Clone().WithFollowRedirects(true)
	}
	return e.client.Clone().WithFollowRedirects(false)
}

// mergeExtractedIntoVars merges extracted data from a result into the
// vars map, making values available for interpolation in subsequent
// requests in the same template execution.
func (e *Executor) mergeExtractedIntoVars(result *templates.ExecutionResult, vars map[string]interface{}) {
	if result.ExtractedData == nil {
		return
	}
	for k, v := range result.ExtractedData {
		if len(v) > 0 {
			vars[k] = v[0]
		}
	}
}

// buildMatcherResponse constructs a matchers.Response from an HTTP
// response so the matcher engine sees a stable shape regardless of
// whether the request used the structured or raw-request path.
func buildMatcherResponse(resp *http.Response) *matchers.Response {
	return &matchers.Response{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Headers,
		Body:          resp.Body,
		ContentLength: int(resp.ContentLength),
		ContentType:   resp.ContentType,
		URL:           resp.URL,
		Raw:           fmt.Sprintf("HTTP/1.1 %s\n%s", resp.Status, resp.Body),
		Duration:      resp.Duration,
	}
}
