package discovery

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// JSFetchDiscoverer extracts HTTP endpoint params from JavaScript
// fetch(), axios, and jQuery AJAX calls found in inline or linked scripts.
type JSFetchDiscoverer struct{ client *http.Client }

func NewJSFetchDiscoverer() *JSFetchDiscoverer { return &JSFetchDiscoverer{} }

func (d *JSFetchDiscoverer) WithClient(c *http.Client) *JSFetchDiscoverer {
	d.client = c
	return d
}

func (d *JSFetchDiscoverer) Name() string { return "jsfetch" }

// Patterns for common JS HTTP client calls.
var (
	// fetch('/path', { method: 'POST', body: JSON.stringify({k1, k2}) })
	fetchRe = regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`)
	// fetch body: JSON.stringify({...})
	fetchBodyRe = regexp.MustCompile(`JSON\.stringify\s*\(\s*\{([^}]{1,500})\}`)
	// axios.post('/path', {k1: v, k2: v})  or axios.get/put/patch/delete
	axiosMethodRe = regexp.MustCompile(`axios\.(post|get|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]`)
	// second arg object keys: axios.post('/x', { key1: ..., key2: ... })
	axiosBodyRe = regexp.MustCompile(`axios\.(?:post|put|patch)\s*\([^,]+,\s*\{([^}]{1,500})\}`)
	// $.ajax({ url: '/path', type: 'POST', data: {k1: v} })
	jqAjaxURLRe  = regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*?url\s*:\s*['"]([^'"]+)['"]`)
	jqAjaxTypeRe = regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*?type\s*:\s*['"](\w+)['"]`)
	jqAjaxDataRe = regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*?data\s*:\s*\{([^}]{1,500})\}`)
	// $.post('/path', {k1: v})  $.get('/path', {k1: v})
	jqShortRe = regexp.MustCompile(`\$\.(post|get)\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*\{([^}]{1,500})\})?`)
	// method: 'POST' inside fetch options
	fetchMethodRe = regexp.MustCompile(`method\s*:\s*['"](\w+)['"]`)
)

// extractKeys pulls identifiers from a JS object literal body like "k1, k2"
// or "k1: v1, k2: v2" or "k1: 'v', k2: someVar".
func extractKeys(objBody string) []string {
	var keys []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(objBody, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, ":"); idx > 0 {
			part = strings.TrimSpace(part[:idx])
		}
		// Strip quotes
		part = strings.Trim(part, "\"' \t\n\r")
		if part == "" || len(part) > 30 || strings.ContainsAny(part, "(){}[]= \t") || seen[part] {
			continue
		}
		seen[part] = true
		keys = append(keys, part)
	}
	return keys
}

func (d *JSFetchDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}
	base, _ := url.Parse(targetURL)
	if base == nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	// Collect JS sources: inline <script> blocks + the page body itself.
	bodies := []string{resp.Body}
	if d.client != nil {
		for _, m := range scriptSrcRegex.FindAllStringSubmatch(resp.Body, maxScriptFetches) {
			ref, err := url.Parse(strings.TrimSpace(m[1]))
			if err != nil {
				continue
			}
			abs := base.ResolveReference(ref).String()
			rr, err := d.client.Get(ctx, abs)
			if err != nil || rr == nil {
				continue
			}
			bodies = append(bodies, rr.Body)
		}
	}

	add := func(name, loc, ct, method, ep string) {
		key := name + ":" + loc + ":" + ep
		if seen[key] || name == "" {
			return
		}
		seen[key] = true
		params = append(params, core.Parameter{
			Name:        name,
			Location:    loc,
			ContentType: ct,
			Method:      method,
			SourceURL:   ep,
		})
	}

	resolve := func(raw string) string {
		ref, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return base.ResolveReference(ref).String()
	}

	for _, js := range bodies {
		// --- fetch() ---
		for _, m := range fetchRe.FindAllStringSubmatchIndex(js, -1) {
			ep := resolve(js[m[2]:m[3]])
			if ep == "" {
				continue
			}
			// Look ahead ~500 chars for method + body
			window := js[m[0]:min(m[1]+500, len(js))]
			method := "GET"
			if mm := fetchMethodRe.FindStringSubmatch(window); mm != nil {
				method = strings.ToUpper(mm[1])
			}
			if bm := fetchBodyRe.FindStringSubmatch(window); bm != nil {
				for _, k := range extractKeys(bm[1]) {
					add(k, core.ParamLocationBody, "application/json", method, ep)
				}
			}
		}
		// --- axios ---
		for _, m := range axiosMethodRe.FindAllStringSubmatch(js, -1) {
			method := strings.ToUpper(m[1])
			ep := resolve(m[2])
			if ep == "" {
				continue
			}
			if method == "GET" {
				continue // query params handled by jsroute
			}
			// Find body keys in the same call
			if bm := axiosBodyRe.FindStringSubmatch(js[strings.Index(js, m[0]):min(strings.Index(js, m[0])+600, len(js))]); bm != nil {
				for _, k := range extractKeys(bm[1]) {
					add(k, core.ParamLocationBody, "application/json", method, ep)
				}
			}
		}
		// --- $.ajax ---
		if um := jqAjaxURLRe.FindStringSubmatch(js); um != nil {
			ep := resolve(um[1])
			method := "GET"
			if tm := jqAjaxTypeRe.FindStringSubmatch(js); tm != nil {
				method = strings.ToUpper(tm[1])
			}
			if dm := jqAjaxDataRe.FindStringSubmatch(js); dm != nil {
				loc := core.ParamLocationQuery
				ct := ""
				if method != "GET" {
					loc = core.ParamLocationBody
					ct = "application/json"
				}
				for _, k := range extractKeys(dm[1]) {
					add(k, loc, ct, method, ep)
				}
			}
		}
		// --- $.post / $.get ---
		for _, m := range jqShortRe.FindAllStringSubmatch(js, -1) {
			method := strings.ToUpper(m[1])
			ep := resolve(m[2])
			if ep == "" {
				continue
			}
			if m[3] != "" {
				loc := core.ParamLocationQuery
				ct := ""
				if method == "POST" {
					loc = core.ParamLocationBody
					ct = "application/json"
				}
				for _, k := range extractKeys(m[3]) {
					add(k, loc, ct, method, ep)
				}
			}
		}
	}
	return params, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
