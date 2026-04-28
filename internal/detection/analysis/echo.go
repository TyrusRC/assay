// Package analysis provides shared response-analysis helpers used across
// detectors to reduce false positives caused by payload reflection.
package analysis

import "strings"

// StripEcho removes every occurrence of payload — raw and in all common
// reflection encodings — from body. Detectors match on substring
// indicators in the response body (e.g. "httpbin.org", "X-Injected:",
// "RFITEST"). When the target app echoes our payload back into the page
// (the near-universal behavior for search/category parameters reflected
// into hidden inputs, JS objects, breadcrumb links, and pagination
// links) those indicators appear inside our own input, not in
// server-fetched content. Stripping the echo first lets subsequent
// matching run only over "unreflected" portions of the response,
// eliminating a huge class of false positives.
//
// Encodings covered:
//   - raw
//   - URL-encoded with upper/lower hex, with `%20` for spaces
//   - URL-encoded with upper/lower hex, with `+` for spaces
//     (application/x-www-form-urlencoded style)
//   - HTML entity encoded (&lt; &gt; &amp; &quot; &#39;)
//
// Letter-case of unreserved characters in the payload is preserved — many
// apps only lowercase the hex digits, not the alphabetic content.
func StripEcho(body, payload string) string {
	if payload == "" {
		return body
	}
	variants := map[string]struct{}{payload: {}}
	add := func(v string) {
		if v != "" && v != payload {
			variants[v] = struct{}{}
		}
	}
	add(urlEncodeAll(payload, true, false))
	add(urlEncodeAll(payload, false, false))
	add(urlEncodeAll(payload, true, true))
	add(urlEncodeAll(payload, false, true))
	add(htmlEscape(payload))

	out := body
	for v := range variants {
		if strings.Contains(out, v) {
			out = strings.ReplaceAll(out, v, "")
		}
	}
	return out
}

// urlEncodeAll returns the percent-encoded form of s. `upperHex` toggles
// hex digit case (e.g. %3A vs %3a). `plusForSpace` selects the
// application/x-www-form-urlencoded space convention (`+`) instead of
// `%20`. Apps vary on both dimensions.
func urlEncodeAll(s string, upperHex, plusForSpace bool) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	hex := "0123456789ABCDEF"
	if !upperHex {
		hex = "0123456789abcdef"
	}
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' && plusForSpace:
			b.WriteByte('+')
		case strings.IndexByte(unreserved, c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
		}
	}
	return b.String()
}

// htmlEscape returns s with the standard HTML special characters replaced
// by their entity references. Covers the forms most commonly used by
// server-side templating engines when rendering a reflected value into an
// HTML attribute or text node.
func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
