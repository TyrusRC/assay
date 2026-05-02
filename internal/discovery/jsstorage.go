package discovery

import (
	"context"
	"regexp"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Patterns for detecting JavaScript storage API calls.
var (
	// localStorage.setItem("key", ...) or localStorage.setItem('key', ...)
	localStorageSetItemRe = regexp.MustCompile(`localStorage\.setItem\s*\(\s*["']([^"']+)["']`)
	// sessionStorage.setItem("key", ...) or sessionStorage.setItem('key', ...)
	sessionStorageSetItemRe = regexp.MustCompile(`sessionStorage\.setItem\s*\(\s*["']([^"']+)["']`)
	// localStorage["key"] = or localStorage['key'] =
	localStorageBracketRe = regexp.MustCompile(`localStorage\s*\[\s*["']([^"']+)["']\s*\]`)
	// sessionStorage["key"] = or sessionStorage['key'] =
	sessionStorageBracketRe = regexp.MustCompile(`sessionStorage\s*\[\s*["']([^"']+)["']\s*\]`)
	// localStorage.key = (dot notation assignment)
	localStorageDotRe = regexp.MustCompile(`localStorage\.(\w+)\s*=`)
	// sessionStorage.key = (dot notation assignment)
	sessionStorageDotRe = regexp.MustCompile(`sessionStorage\.(\w+)\s*=`)
	// document.cookie = "name=
	documentCookieRe = regexp.MustCompile(`document\.cookie\s*=\s*["']([^"'=]+)=`)
)

// localStorageBuiltins are localStorage properties that are not storage keys.
var localStorageBuiltins = map[string]bool{
	"setItem": true, "getItem": true, "removeItem": true,
	"clear": true, "key": true, "length": true,
}

// JSStorageDiscoverer extracts injectable parameters from JavaScript storage API calls
// found in HTML/JS responses.
type JSStorageDiscoverer struct{}

// NewJSStorageDiscoverer creates a new JSStorageDiscoverer.
func NewJSStorageDiscoverer() *JSStorageDiscoverer {
	return &JSStorageDiscoverer{}
}

// Name returns the discoverer identifier.
func (j *JSStorageDiscoverer) Name() string {
	return "jsstorage"
}

// Discover extracts storage-related parameters from JavaScript in the response body.
func (j *JSStorageDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	body := resp.Body
	var params []core.Parameter
	seen := make(map[string]bool)

	// localStorage.setItem("key", ...)
	for _, match := range localStorageSetItemRe.FindAllStringSubmatch(body, -1) {
		key := "localstorage:" + match[1]
		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     match[1],
				Location: core.ParamLocationLocalStorage,
				Value:    "",
				Type:     "string",
			})
		}
	}

	// sessionStorage.setItem("key", ...)
	for _, match := range sessionStorageSetItemRe.FindAllStringSubmatch(body, -1) {
		key := "sessionstorage:" + match[1]
		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     match[1],
				Location: core.ParamLocationSessionStorage,
				Value:    "",
				Type:     "string",
			})
		}
	}

	// localStorage["key"] = ...
	for _, match := range localStorageBracketRe.FindAllStringSubmatch(body, -1) {
		key := "localstorage:" + match[1]
		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     match[1],
				Location: core.ParamLocationLocalStorage,
				Value:    "",
				Type:     "string",
			})
		}
	}

	// sessionStorage["key"] = ...
	for _, match := range sessionStorageBracketRe.FindAllStringSubmatch(body, -1) {
		key := "sessionstorage:" + match[1]
		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     match[1],
				Location: core.ParamLocationSessionStorage,
				Value:    "",
				Type:     "string",
			})
		}
	}

	// localStorage.key = ... (dot notation, skip built-in methods)
	for _, match := range localStorageDotRe.FindAllStringSubmatch(body, -1) {
		if localStorageBuiltins[match[1]] {
			continue
		}
		key := "localstorage:" + match[1]
		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     match[1],
				Location: core.ParamLocationLocalStorage,
				Value:    "",
				Type:     "string",
			})
		}
	}

	// sessionStorage.key = ... (dot notation, skip built-in methods)
	for _, match := range sessionStorageDotRe.FindAllStringSubmatch(body, -1) {
		if localStorageBuiltins[match[1]] {
			continue
		}
		key := "sessionstorage:" + match[1]
		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     match[1],
				Location: core.ParamLocationSessionStorage,
				Value:    "",
				Type:     "string",
			})
		}
	}

	// document.cookie = "name=..."
	for _, match := range documentCookieRe.FindAllStringSubmatch(body, -1) {
		key := "cookie:" + match[1]
		if !seen[key] {
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     match[1],
				Location: core.ParamLocationCookie,
				Value:    "",
				Type:     "string",
			})
		}
	}

	return params, nil
}
