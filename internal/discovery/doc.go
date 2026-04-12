// Package discovery provides auto-discovery of injectable parameters from HTTP responses.
//
// It supports discovering parameters from multiple sources:
//   - HTML forms (inputs, textareas, selects)
//   - Cookies from Set-Cookie response headers
//   - Common injectable HTTP headers
//   - JSON response body fields
//   - URL path segments (base64, hex, resource IDs)
//   - JavaScript localStorage/sessionStorage API calls
//
// All discoverers implement the Discoverer interface and are orchestrated
// by the Pipeline which runs them concurrently and deduplicates results.
package discovery
