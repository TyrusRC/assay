package jsmining

import (
	"net/url"
	"regexp"
	"strings"
)

// Patterns recognized as endpoint-bearing call shapes or literal forms.
// Each pattern captures the URL string in group 1. Patterns are kept
// individually anchored so a single string literal can match at most one
// shape, and so the regex engine does not backtrack across the whole
// minified bundle.
var (
	// fetch("..."), fetch('...')
	reFetch = regexp.MustCompile(`\bfetch\s*\(\s*["']([^"']+)["']`)

	// axios.METHOD("..."), where METHOD is one of the verb helpers axios
	// exposes (get/post/put/patch/delete/head/options) plus the bare
	// axios("...") form. We accept any identifier after the dot to cover
	// custom instances like api.get("...").
	reAxios = regexp.MustCompile(`\b(?:axios|[A-Za-z_$][\w$]*)\.(?:get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']`)

	// $.ajax({url:"..."}) — jQuery's options-object form. The url key
	// can appear with or without quotes around the key name, but in
	// practice minifiers preserve neither order nor whitespace, so we
	// search for the url: token inside the ajax(...) opening.
	reJQueryAjax = regexp.MustCompile(`\$\s*\.\s*ajax\s*\(\s*\{[^}]*?\burl\s*:\s*["']([^"']+)["']`)

	// xhr.open("METHOD", "URL", ...) — XMLHttpRequest. The first arg is
	// the method, the second the URL. We accept any object name, since
	// the XHR object is usually a local variable.
	reXHROpen = regexp.MustCompile(`\.open\s*\(\s*["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']\s*,\s*["']([^"']+)["']`)

	// Path-shaped string literals. We match anything that:
	//   - starts with `/`
	//   - then has at least one path segment
	//   - lives inside single or double quotes
	// We deliberately do NOT require the segment to look like an "API"
	// path; downstream filtering decides what's interesting. We DO
	// require at least one slash inside the captured string to avoid
	// matching ordinary short strings.
	rePathLiteral = regexp.MustCompile(`["'](/[A-Za-z0-9_\-./\[\]{}+*?:=&]+)["']`)

	// Absolute URL literals.
	reAbsURL = regexp.MustCompile(`["'](https?://[^"'<>\s]+)["']`)
)

// Mine extracts endpoint URLs from JavaScript source code and resolves
// them against baseURL. Returns absolute URLs (or path strings when
// baseURL is empty), deduplicated, in stable insertion order.
//
// Pure string analysis; no network calls.
func Mine(jsSource, baseURL string) []string {
	if jsSource == "" {
		return nil
	}

	var base *url.URL
	if baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil {
			base = u
		}
	}

	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		// Filter out non-HTTP schemes that masquerade as URLs.
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "data:") ||
			strings.HasPrefix(lower, "javascript:") ||
			strings.HasPrefix(lower, "blob:") ||
			strings.HasPrefix(lower, "mailto:") {
			return
		}

		resolved := resolveURL(base, raw)
		if resolved == "" {
			return
		}
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}

	// Run all recognizers. Order matters only for stable output; dedup
	// keeps the first occurrence.
	for _, re := range []*regexp.Regexp{
		reFetch,
		reAxios,
		reJQueryAjax,
		reXHROpen,
		reAbsURL,
		rePathLiteral,
	} {
		for _, m := range re.FindAllStringSubmatch(jsSource, -1) {
			if len(m) >= 2 {
				add(m[1])
			}
		}
	}

	return out
}

// resolveURL joins a relative path with base; returns the path as-is
// when base is nil. Absolute URLs are returned unchanged.
//
// Template/regex characters ({, }, [, ], +, *, ?) commonly appear in
// route patterns mined from JS bundles. The standard library's
// url.ResolveReference percent-encodes them, which destroys the very
// shape callers want to see. We resolve via string concatenation when
// the input is a plain path so those characters survive untouched.
func resolveURL(base *url.URL, raw string) string {
	// Already absolute? Pass through.
	if strings.HasPrefix(strings.ToLower(raw), "http://") ||
		strings.HasPrefix(strings.ToLower(raw), "https://") {
		return raw
	}
	if base == nil {
		return raw
	}
	if strings.HasPrefix(raw, "/") {
		// Build scheme://host + raw to preserve template/regex chars.
		// Strip any trailing slash from the host portion (url.URL.Host
		// never has one, but be defensive).
		return base.Scheme + "://" + base.Host + raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}
