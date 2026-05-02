package discovery

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// JSRouteDiscoverer extracts query parameters from URLs in JavaScript code.
type JSRouteDiscoverer struct{}

// NewJSRouteDiscoverer creates a new JSRouteDiscoverer.
func NewJSRouteDiscoverer() *JSRouteDiscoverer {
	return &JSRouteDiscoverer{}
}

// Name returns the discoverer identifier.
func (j *JSRouteDiscoverer) Name() string {
	return "jsroute"
}

var jsURLRegex = regexp.MustCompile(`["']([^"']*\?[^"']+)["']`)

// Discover extracts query parameters from URLs found in JavaScript content.
func (j *JSRouteDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	if !j.isJSContent(resp.ContentType) {
		return nil, nil
	}

	matches := jsURLRegex.FindAllStringSubmatch(resp.Body, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	for _, m := range matches {
		rawURL := m[1]
		idx := strings.Index(rawURL, "?")
		if idx < 0 {
			continue
		}
		queryStr := rawURL[idx+1:]
		values, err := url.ParseQuery(queryStr)
		if err != nil {
			continue
		}
		for key, vals := range values {
			if seen[key] {
				continue
			}
			seen[key] = true
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			params = append(params, core.Parameter{
				Name:     key,
				Location: core.ParamLocationQuery,
				Value:    val,
			})
		}
	}

	return params, nil
}

// isJSContent checks if the content type is JavaScript or JSON.
func (j *JSRouteDiscoverer) isJSContent(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "application/json")
}
