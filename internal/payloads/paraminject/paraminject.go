// Package paraminject provides shared helpers for detectors that
// perform per-URL-parameter payload injection.
//
// Each of the parameter-injection detectors (esi, solrinject, phpinject,
// javareflect, nodejsinject, arginject, fileops) follows the same shape:
// fetch a baseline response, then for every URL parameter try every
// payload, looking for a marker that wasn't in the baseline. The
// boilerplate is identical across detectors — this package extracts it.
//
// The exported helpers are intentionally narrow: HTTP fetching with a
// body cap, URL-parameter mutation, string truncation for evidence
// logging, and substring-set match. Marker-specific logic stays in each
// detector because the marker definition is the per-class signal.
package paraminject

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Fetch issues a single GET against target, caps the body at
// maxBodyBytes, and returns the response body as a string alongside
// the http.Response (or an error). The caller must use the supplied
// context for cancellation; the function does not impose its own timeout
// — callers wrap the context with their per-detector timeout instead.
func Fetch(ctx context.Context, client *http.Client, target string, maxBodyBytes int64) (string, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if maxBodyBytes <= 0 {
		maxBodyBytes = 64 << 10
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(body), resp, nil
}

// InjectParam returns a copy of u with the named query parameter set
// to value. Mutating the original url.URL is avoided so callers can
// reuse the parsed baseline across many injections.
func InjectParam(u *url.URL, name, value string) string {
	uCopy := *u
	q := uCopy.Query()
	q.Set(name, value)
	uCopy.RawQuery = q.Encode()
	return uCopy.String()
}

// ContainsAny reports whether any of the patterns appears in s.
// Substring (not regex) check.
func ContainsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// FirstNewMatch returns the first pattern present in body that is NOT
// present in baseline. Empty string means no new match. Used by
// per-detector evaluation-marker logic.
func FirstNewMatch(body, baseline string, patterns []string) string {
	for _, p := range patterns {
		if strings.Contains(body, p) && !strings.Contains(baseline, p) {
			return p
		}
	}
	return ""
}

// Truncate clamps s to n runes (not bytes) and appends an ellipsis if
// truncation occurred. Used by Evidence strings to keep finding payloads
// readable in reports.
func Truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
