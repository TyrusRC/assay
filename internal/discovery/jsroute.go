package discovery

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// JSRouteDiscoverer extracts query parameters from URLs in JavaScript code.
type JSRouteDiscoverer struct{ client *http.Client }

// NewJSRouteDiscoverer creates a new JSRouteDiscoverer.
func NewJSRouteDiscoverer() *JSRouteDiscoverer {
	return &JSRouteDiscoverer{}
}

// WithClient lets the discoverer fetch the <script src> files a page links and
// scan each for URL literals, instead of only scanning a JS response it was
// handed. The client carries the scan's scope and rate limit.
func (j *JSRouteDiscoverer) WithClient(c *http.Client) *JSRouteDiscoverer {
	j.client = c
	return j
}

// Name returns the discoverer identifier.
func (j *JSRouteDiscoverer) Name() string {
	return "jsroute"
}

var (
	jsURLRegex     = regexp.MustCompile(`["']([^"']*\?[^"']+)["']`)
	scriptSrcRegex = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
)

// maxScriptFetches bounds how many external scripts one page fetch pulls.
const maxScriptFetches = 20

// Discover extracts query parameters from URL literals in JavaScript. When the
// handed response is JS it scans that directly; otherwise, with a client, it
// fetches the page's <script src> files and scans each.
func (j *JSRouteDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	// The response itself is JavaScript — scan it (the previous behavior).
	if j.isJSContent(resp.ContentType) {
		j.collect(resp.Body, seen, &params)
		return params, nil
	}

	// Otherwise treat it as a page: fetch each linked script and scan it.
	if j.client == nil {
		return nil, nil
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil
	}
	fetched := make(map[string]bool)
	for _, m := range scriptSrcRegex.FindAllStringSubmatch(resp.Body, -1) {
		if len(fetched) >= maxScriptFetches {
			break
		}
		ref, perr := url.Parse(strings.TrimSpace(m[1]))
		if perr != nil {
			continue
		}
		abs := base.ResolveReference(ref).String()
		if fetched[abs] {
			continue
		}
		fetched[abs] = true
		rr, ferr := j.client.Get(ctx, abs)
		if ferr != nil || rr == nil || rr.Body == "" {
			continue
		}
		j.collect(rr.Body, seen, &params)
	}
	return params, nil
}

// collect extracts query-parameter names from URL literals in a JS body.
func (j *JSRouteDiscoverer) collect(body string, seen map[string]bool, params *[]core.Parameter) {
	for _, m := range jsURLRegex.FindAllStringSubmatch(body, -1) {
		rawURL := m[1]
		idx := strings.Index(rawURL, "?")
		if idx < 0 {
			continue
		}
		values, err := url.ParseQuery(rawURL[idx+1:])
		if err != nil {
			continue
		}
		for key, vals := range values {
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			*params = append(*params, core.Parameter{
				Name:     key,
				Location: core.ParamLocationQuery,
				Value:    val,
			})
		}
	}
}

// isJSContent checks if the content type is JavaScript or JSON.
func (j *JSRouteDiscoverer) isJSContent(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "application/json")
}
