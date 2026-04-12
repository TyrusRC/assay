package discovery

import (
	"context"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// injectableHeaders is the list of HTTP headers commonly used in injection attacks.
var injectableHeaders = []string{
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Real-IP",
	"User-Agent",
	"Host",
	"Origin",
	"X-Original-URL",
	"X-Rewrite-URL",
	"Forwarded",
	"X-Client-IP",
	"True-Client-IP",
}

// HeaderDiscoverer returns a static list of commonly injectable HTTP headers.
type HeaderDiscoverer struct{}

// NewHeaderDiscoverer creates a new HeaderDiscoverer.
func NewHeaderDiscoverer() *HeaderDiscoverer {
	return &HeaderDiscoverer{}
}

// Name returns the discoverer identifier.
func (h *HeaderDiscoverer) Name() string {
	return "header"
}

// Discover returns injectable header parameters.
// The response is not used since headers are a static known set.
func (h *HeaderDiscoverer) Discover(_ context.Context, _ string, _ *http.Response) ([]core.Parameter, error) {
	params := make([]core.Parameter, 0, len(injectableHeaders))
	for _, header := range injectableHeaders {
		params = append(params, core.Parameter{
			Name:     header,
			Location: core.ParamLocationHeader,
			Value:    "",
			Type:     "string",
		})
	}
	return params, nil
}

// InjectableHeaders returns the list of injectable header names.
func InjectableHeaders() []string {
	result := make([]string, len(injectableHeaders))
	copy(result, injectableHeaders)
	return result
}
