package cachedeception

import (
	"strings"
)

// looksCacheable returns true if response headers indicate the response
// will be (or was) stored by a shared cache. This is the second leg of
// cache deception — even if the application returns private content at a
// deceptive URL, the bug only matters when a downstream cache stores it.
//
// We honor three signal classes:
//
//   - Explicit Cache-Control directives that ALLOW caching: "public",
//     "max-age=N" with N > 0, OR no directive at all (default cacheable
//     in HTTP/1.1 §13.4 when paired with a static-looking extension).
//
//   - Cache-vendor headers visible on the response: cf-cache-status,
//     x-cache, x-served-by, x-cache-status, akamai-cache-status, fastly-*.
//     A header that says HIT/MISS/STORE is the cache announcing itself.
//
//   - Age header presence — proves a cache touched the response (set when
//     a cache serves a stored copy).
//
// Returns false on any of: Cache-Control: no-store, Cache-Control: private,
// or Cache-Control: max-age=0 with no public directive — the cache's own
// docs say "do not store", so probably it didn't.
func looksCacheable(headers map[string]string) bool {
	cc := headerValue(headers, "Cache-Control")
	cclower := strings.ToLower(cc)

	// Hard negatives — cache says do-not-store.
	if strings.Contains(cclower, "no-store") {
		return false
	}
	// Some CDNs ignore "private" but conservatively treat it as a negative.
	if strings.Contains(cclower, "private") {
		return false
	}

	// Hard positives — cache vendor announcing itself.
	for _, name := range cacheVendorHeaders {
		if v := headerValue(headers, name); v != "" {
			return true
		}
	}

	// Hard positive — explicit "public" or any positive max-age.
	if strings.Contains(cclower, "public") {
		return true
	}
	if hasPositiveMaxAge(cclower) {
		return true
	}

	// Default-cacheable case: HTTP/1.1 says GET with no Cache-Control is
	// cacheable. We do NOT use this as a positive on its own — too noisy.
	// Relying solely on it would flag every static asset on every server.
	return false
}

// cacheVendorHeaders are the response headers caches and CDNs use to
// announce "this came from the cache." Presence is enough — we do not
// require HIT specifically, since STORE/MISS still proves a cache is in
// the path.
var cacheVendorHeaders = []string{
	"X-Cache",
	"X-Cache-Status",
	"X-Cache-Hits",
	"CF-Cache-Status",
	"Age",
	"Akamai-Cache-Status",
	"X-Akamai-Cache-Status",
	"X-Served-By",
	"X-Fastly-Cache",
	"Fastly-Debug-Path",
	"Via",
}

// headerValue does a case-insensitive header lookup. Go's net/http stores
// canonical-cased keys in the response Header map but our internal Client
// returns plain map[string]string with whatever the server sent, so we
// have to walk it.
func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// hasPositiveMaxAge returns true if the Cache-Control directive contains
// a max-age=N with N >= 1. We deliberately don't try to parse the entire
// CC grammar — too easy to disagree with the cache that will actually
// process this; the directive vendors care about is the literal string.
func hasPositiveMaxAge(cc string) bool {
	idx := strings.Index(cc, "max-age=")
	if idx == -1 {
		return false
	}
	v := cc[idx+len("max-age="):]
	end := strings.IndexAny(v, ", ")
	if end >= 0 {
		v = v[:end]
	}
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// bodySimilar returns true if two bodies are similar enough that we
// believe the same private response was returned at both URLs.
//
// Equal bodies are the strongest signal. For real-world apps that include
// per-request nonces (CSRF tokens, request IDs in HTML), strict equality
// fails too often; we fall back to a Jaccard-ish overlap on tokenized
// content, with a high threshold so cosmetic differences (timestamp lines)
// don't bring up a finding but a different page does.
//
// Parameter minTokens guards against tiny pages where a few-token overlap
// could accidentally match — a one-line "OK" body should not match a
// one-line "ERR" body via this heuristic alone.
func bodySimilar(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	// Cheap pre-filter: bodies with very different lengths are not the
	// same response. 25% length tolerance.
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return false
	}
	if la*4 < lb*3 || lb*4 < la*3 {
		return false
	}
	at := tokenize(a)
	bt := tokenize(b)
	if len(at) < 8 || len(bt) < 8 {
		// Bodies too small for reliable similarity — fall back to strict
		// equality (already failed) so return false.
		return false
	}
	overlap := jaccard(at, bt)
	return overlap >= 0.85
}

// tokenize splits a body on whitespace and lowercases — good enough for
// "is this the same page" comparisons without dragging in a full HTML
// parser. The set is bounded by len(s)/2 so a degenerate input doesn't
// blow up the comparison.
func tokenize(s string) map[string]struct{} {
	out := make(map[string]struct{}, len(s)/8)
	cur := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == '<' || c == '>' || c == '"' || c == '\'' {
			if len(cur) > 0 {
				out[strings.ToLower(string(cur))] = struct{}{}
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out[strings.ToLower(string(cur))] = struct{}{}
	}
	return out
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	intersect := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersect++
		}
	}
	union := len(a) + len(b) - intersect
	if union == 0 {
		return 0
	}
	return float64(intersect) / float64(union)
}
