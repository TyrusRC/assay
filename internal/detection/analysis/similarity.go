package analysis

import (
	"regexp"
	"strings"

	skwshttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

// tokenize splits a string into a set of unique lowercase word tokens.
func tokenize(s string) map[string]struct{} {
	tokens := make(map[string]struct{})
	for _, word := range strings.Fields(s) {
		tokens[strings.ToLower(word)] = struct{}{}
	}
	return tokens
}

// ResponseSimilarity returns a value from 0.0 to 1.0 representing the Jaccard
// similarity between two response bodies. It tokenizes both bodies into words
// and computes the Jaccard index (intersection size / union size).
// If both bodies are empty, it returns 1.0. If exactly one is empty, it returns 0.0.
func ResponseSimilarity(a, b string) float64 {
	tokensA := tokenize(a)
	tokensB := tokenize(b)

	// Both empty after tokenization means identical (empty).
	if len(tokensA) == 0 && len(tokensB) == 0 {
		return 1.0
	}

	// One empty and the other not: no similarity.
	if len(tokensA) == 0 || len(tokensB) == 0 {
		return 0.0
	}

	// Compute intersection size.
	intersectionSize := 0
	for token := range tokensA {
		if _, ok := tokensB[token]; ok {
			intersectionSize++
		}
	}

	// Union size = |A| + |B| - |intersection|.
	unionSize := len(tokensA) + len(tokensB) - intersectionSize

	if unionSize == 0 {
		return 1.0
	}

	return float64(intersectionSize) / float64(unionSize)
}

// dynamicPatterns contains compiled regular expressions for known dynamic tokens
// that change between requests and should be stripped before response comparison.
var dynamicPatterns = []*regexp.Regexp{
	// UUIDs (v4 and general format: 8-4-4-4-12 hex digits).
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),

	// ISO 8601 timestamps: 2024-01-31T12:00:00Z or with offset.
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?`),

	// Unix timestamps (10-13 digit numbers that look like epoch seconds or milliseconds).
	regexp.MustCompile(`\b1[0-9]{9,12}\b`),

	// CSRF token values in hidden form inputs.
	regexp.MustCompile(`(<input[^>]*name=["'](?:csrf|_csrf|csrf_token|csrfmiddlewaretoken|_token|authenticity_token)[^>]*value=["'])[^"']*?(["'])`),

	// Nonce attributes.
	regexp.MustCompile(`(nonce=["'])[^"']*?(["'])`),

	// Cache-busting query strings like ?v=1706745600 or ?_=1706745600.
	regexp.MustCompile(`\?(?:v|_|cb|cache|ts)=[0-9a-zA-Z]+`),

	// Hex session IDs (32+ character hex strings preceded by = or whitespace).
	regexp.MustCompile(`(?:=|\s)[0-9a-fA-F]{32,}\b`),
}

// dynamicReplacements provides the replacement strings corresponding to each
// dynamicPatterns entry. Patterns with capture groups use $1$2 to preserve the
// surrounding structure while blanking the dynamic value.
var dynamicReplacements = []string{
	"",       // UUIDs
	"",       // ISO 8601
	"",       // Unix timestamps
	"${1}${2}", // CSRF tokens (keep input tag structure)
	"${1}${2}", // Nonce attributes
	"",       // Cache-busting query strings
	"",       // Hex session IDs
}

// StripDynamicContent removes known dynamic tokens from a response body before
// comparison. It strips: CSRF tokens, timestamps (Unix epoch, ISO 8601), UUIDs,
// random session IDs, nonce values, and cache-busting query strings.
func StripDynamicContent(body string) string {
	if body == "" {
		return ""
	}

	result := body
	for i, pattern := range dynamicPatterns {
		result = pattern.ReplaceAllString(result, dynamicReplacements[i])
	}
	return result
}

// IsSameResponse compares two responses using a similarity threshold. It strips
// dynamic content from both response bodies, compares status codes, and then
// checks whether the body similarity meets the threshold. Returns false if
// either response is nil.
func IsSameResponse(a, b *skwshttp.Response, threshold float64) bool {
	if a == nil || b == nil {
		return false
	}

	// Different status codes means different responses.
	if a.StatusCode != b.StatusCode {
		return false
	}

	strippedA := StripDynamicContent(a.Body)
	strippedB := StripDynamicContent(b.Body)

	similarity := ResponseSimilarity(strippedA, strippedB)
	return similarity >= threshold
}
