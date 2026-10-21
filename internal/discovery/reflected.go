package discovery

import (
	"context"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// ReflectedParamDiscoverer tries common parameter names and checks if the
// value is reflected in the response. This catches hidden query parameters
// that aren't exposed via HTML forms or links.
type ReflectedParamDiscoverer struct {
	client *http.Client
}

// NewReflectedParamDiscoverer creates a new ReflectedParamDiscoverer.
func NewReflectedParamDiscoverer() *ReflectedParamDiscoverer {
	return &ReflectedParamDiscoverer{}
}

// WithClient sets the HTTP client.
func (r *ReflectedParamDiscoverer) WithClient(c *http.Client) *ReflectedParamDiscoverer {
	r.client = c
	return r
}

// Name returns the discoverer identifier.
func (r *ReflectedParamDiscoverer) Name() string {
	return "reflected-param"
}

// commonParams is a list of commonly injectable query/form parameter names.
var commonParams = []string{
	"id", "name", "q", "query", "search", "s",
	"page", "url", "file", "path", "dir",
	"cmd", "exec", "command",
	"user", "username", "email", "password",
	"redirect", "next", "return", "goto", "target",
	"template", "lang", "locale", "theme",
	"callback", "cb", "jsonp",
	"sort", "order", "orderby", "sort_by",
	"filter", "category", "type", "action",
	"input", "data", "value", "text", "content", "body", "message",
	"title", "comment", "description",
	"token", "key", "api_key",
	"format", "output", "view", "mode",
	"debug", "test", "admin",
	"ref", "reference", "source",
	"host", "domain", "site",
	"ip", "port", "address",
	"from", "to", "date", "start", "end",
	"limit", "offset", "count", "size", "num",
	"include", "require", "load", "read", "fetch",
	"payload", "expr", "expression", "code",
}

// Discover tries common parameter names and returns those that produce
// a different response (reflected value, different body, status change).
func (r *ReflectedParamDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	if r.client == nil || resp == nil {
		return nil, nil
	}

	baselineBody := resp.Body
	baselineLen := len(baselineBody)
	marker := "assayprobe7x3k"

	var params []core.Parameter
	for _, name := range commonParams {
		select {
		case <-ctx.Done():
			return params, nil
		default:
		}

		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		probeURL := targetURL + sep + name + "=" + marker

		probeResp, err := r.client.Get(ctx, probeURL)
		if err != nil {
			continue
		}

		// Check for reflection or significant body change
		reflected := strings.Contains(probeResp.Body, marker)
		bodyChanged := abs(len(probeResp.Body)-baselineLen) > 10

		if reflected || bodyChanged {
			params = append(params, core.Parameter{
				Name:      name,
				Location:  core.ParamLocationQuery,
				Value:     "",
				Type:      "string",
				SourceURL: targetURL,
			})
		}
	}

	return params, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
