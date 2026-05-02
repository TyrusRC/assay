// Package matchers provides response matching capabilities for nuclei templates.
package matchers

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

// Response represents an HTTP response for matching.
type Response struct {
	StatusCode    int
	Headers       map[string]string
	Body          string
	ContentLength int
	ContentType   string
	URL           string
	Protocol      string // For interactsh matching
	Raw           string
	Duration      time.Duration // Response time for time-based detection
}

// MatcherEngine evaluates matchers against responses.
type MatcherEngine struct {
	// Cache for compiled regex patterns
	regexCache map[string]*regexp.Regexp
	regexMu    sync.RWMutex

	// DSL expression evaluator
	dslEngine *DSLEngine
}

// New creates a new matcher engine.
func New() *MatcherEngine {
	return &MatcherEngine{
		regexCache: make(map[string]*regexp.Regexp),
		dslEngine:  NewDSLEngine(),
	}
}

// MatchResult contains the result of matching.
type MatchResult struct {
	Matched  bool
	Name     string
	Extracts []string
}

// Match evaluates a single matcher against a response.
func (e *MatcherEngine) Match(m *templates.Matcher, resp *Response, data map[string]interface{}) *MatchResult {
	result := &MatchResult{
		Name: m.Name,
	}

	var matched bool
	switch m.Type {
	case "word":
		matched = e.matchWord(m, resp)
	case "regex":
		matched, result.Extracts = e.matchRegex(m, resp)
	case "status":
		matched = e.matchStatus(m, resp)
	case "size":
		matched = e.matchSize(m, resp)
	case "binary":
		matched = e.matchBinary(m, resp)
	case "dsl":
		matched = e.matchDSL(m, resp, data)
	case "xpath":
		matched, result.Extracts = e.matchXPath(m, resp)
	case "time":
		matched = e.matchTime(m, resp, data)
	default:
		return result
	}

	// Handle negative matching
	if m.Negative {
		matched = !matched
	}

	result.Matched = matched
	return result
}

// MatchAll evaluates all matchers with the specified condition.
func (e *MatcherEngine) MatchAll(matchers []templates.Matcher, condition string, resp *Response, data map[string]interface{}) (bool, map[string][]string) {
	if len(matchers) == 0 {
		return true, nil
	}

	extracts := make(map[string][]string)
	condition = strings.ToLower(condition)
	if condition == "" {
		condition = "or" // Default to OR
	}

	var matchedCount int
	var nonInternalCount int
	for _, m := range matchers {
		// Skip internal matchers for final result
		if m.Internal {
			continue
		}

		nonInternalCount++
		result := e.Match(&m, resp, data)
		if result.Matched {
			matchedCount++
			if m.Name != "" && len(result.Extracts) > 0 {
				extracts[m.Name] = result.Extracts
			}
		}

		// Short-circuit for AND condition
		if condition == "and" && !result.Matched {
			return false, nil
		}

		// Short-circuit for OR condition
		if condition == "or" && result.Matched {
			return true, extracts
		}
	}

	if condition == "and" {
		return matchedCount == nonInternalCount, extracts
	}

	return matchedCount > 0, extracts
}

// matchWord checks for word matches in the response.
func (e *MatcherEngine) matchWord(m *templates.Matcher, resp *Response) bool {
	content := e.getMatchPart(m.Part, resp)
	if m.Encoding == "hex" {
		if decoded, err := hexDecode(content); err == nil {
			content = string(decoded)
		}
	}

	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	matchCount := 0
	for _, word := range m.Words {
		checkContent := content
		checkWord := word

		if m.CaseInsensitive {
			checkContent = strings.ToLower(content)
			checkWord = strings.ToLower(word)
		}

		if strings.Contains(checkContent, checkWord) {
			matchCount++
			if condition == "or" {
				return true
			}
		} else if condition == "and" {
			return false
		}
	}

	if condition == "and" {
		return matchCount == len(m.Words)
	}
	return matchCount > 0
}

// matchRegex checks for regex matches in the response.
func (e *MatcherEngine) matchRegex(m *templates.Matcher, resp *Response) (bool, []string) {
	content := e.getMatchPart(m.Part, resp)
	if m.Encoding == "hex" {
		if decoded, err := hexDecode(content); err == nil {
			content = string(decoded)
		}
	}

	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	var extracts []string
	matchCount := 0

	for _, pattern := range m.Regex {
		re, err := e.getCompiledRegex(pattern, m.CaseInsensitive)
		if err != nil {
			continue
		}

		if re.MatchString(content) {
			matchCount++

			// Extract matched groups
			matches := re.FindStringSubmatch(content)
			if len(matches) > 1 {
				extracts = append(extracts, matches[1:]...)
			}

			if condition == "or" {
				return true, extracts
			}
		} else if condition == "and" {
			return false, nil
		}
	}

	if condition == "and" {
		return matchCount == len(m.Regex), extracts
	}
	return matchCount > 0, extracts
}

// matchStatus checks for status code matches.
func (e *MatcherEngine) matchStatus(m *templates.Matcher, resp *Response) bool {
	for _, status := range m.Status {
		if resp.StatusCode == status {
			return true
		}
	}
	return false
}

// matchSize checks for content length matches.
func (e *MatcherEngine) matchSize(m *templates.Matcher, resp *Response) bool {
	for _, size := range m.Size {
		if resp.ContentLength == size {
			return true
		}
	}
	return false
}

// matchBinary checks for binary pattern matches.
func (e *MatcherEngine) matchBinary(m *templates.Matcher, resp *Response) bool {
	rawContent := e.getMatchPart(m.Part, resp)
	if m.Encoding == "hex" {
		if decoded, err := hexDecode(rawContent); err == nil {
			rawContent = string(decoded)
		}
	}
	content := []byte(rawContent)

	for _, hexPattern := range m.Binary {
		pattern, err := hexDecode(hexPattern)
		if err != nil {
			continue
		}
		if bytes.Contains(content, pattern) {
			return true
		}
	}
	return false
}

// matchDSL evaluates DSL expressions.
func (e *MatcherEngine) matchDSL(m *templates.Matcher, resp *Response, data map[string]interface{}) bool {
	// Build full header string
	var headerSb strings.Builder
	for k, v := range resp.Headers {
		headerSb.WriteString(k)
		headerSb.WriteString(": ")
		headerSb.WriteString(v)
		headerSb.WriteString("\n")
	}
	headerStr := headerSb.String()

	// Build raw = headers + body
	rawStr := headerStr + "\n" + resp.Body

	// Build context for DSL evaluation
	ctx := map[string]interface{}{
		"status_code":    resp.StatusCode,
		"content_length": resp.ContentLength,
		"content_type":   resp.ContentType,
		"body":           resp.Body,
		"url":            resp.URL,
		"header":         headerStr,
		"all_headers":    headerStr,
		"raw":            rawStr,
		"duration":       resp.Duration.Seconds(),
	}

	// Add individual header_* fields
	for k, v := range resp.Headers {
		ctx["header_"+strings.ToLower(strings.ReplaceAll(k, "-", "_"))] = v
	}

	// Merge with provided data
	for k, v := range data {
		ctx[k] = v
	}

	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	matchCount := 0
	for _, expr := range m.DSL {
		if e.dslEngine.Evaluate(expr, ctx) {
			matchCount++
			if condition == "or" {
				return true
			}
		} else if condition == "and" {
			return false
		}
	}

	if condition == "and" {
		return matchCount == len(m.DSL)
	}
	return matchCount > 0
}

// getMatchPart extracts the part of response to match against.
func (e *MatcherEngine) getMatchPart(part string, resp *Response) string {
	switch strings.ToLower(part) {
	case "body":
		return resp.Body
	case "header", "headers":
		var sb strings.Builder
		for k, v := range resp.Headers {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
		return sb.String()
	case "status":
		return strconv.Itoa(resp.StatusCode)
	case "content_type":
		return resp.ContentType
	case "interactsh_protocol":
		return resp.Protocol
	case "raw":
		return resp.Raw
	case "", "all":
		// Return everything
		var sb strings.Builder
		sb.WriteString("HTTP/1.1 ")
		sb.WriteString(strconv.Itoa(resp.StatusCode))
		sb.WriteString("\n")
		for k, v := range resp.Headers {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
		sb.WriteString(resp.Body)
		return sb.String()
	default:
		// Try to find a header with this name
		if v, ok := resp.Headers[part]; ok {
			return v
		}
		return resp.Body
	}
}

// getCompiledRegex returns a compiled regex, using cache if available.
func (e *MatcherEngine) getCompiledRegex(pattern string, caseInsensitive bool) (*regexp.Regexp, error) {
	cacheKey := pattern
	if caseInsensitive {
		cacheKey = "(?i)" + pattern
		pattern = "(?i)" + pattern
	}

	// Check cache with read lock
	e.regexMu.RLock()
	if re, ok := e.regexCache[cacheKey]; ok {
		e.regexMu.RUnlock()
		return re, nil
	}
	e.regexMu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Store in cache with write lock
	e.regexMu.Lock()
	e.regexCache[cacheKey] = re
	e.regexMu.Unlock()

	return re, nil
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 {
		s = "0" + s
	}

	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		result[i/2] = byte(b)
	}
	return result, nil
}

// matchTime evaluates time-based matchers for timing attacks detection.
func (e *MatcherEngine) matchTime(m *templates.Matcher, resp *Response, data map[string]interface{}) bool {
	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	// Get baseline and tolerance from data if available
	var baseline time.Duration
	if b, ok := data["baseline_duration"].(time.Duration); ok {
		baseline = b
	}

	var tolerance time.Duration = 100 * time.Millisecond // Default tolerance for == comparisons
	if t, ok := data["time_tolerance"].(time.Duration); ok {
		tolerance = t
	}

	var multiplier float64 = 1.0
	if mult, ok := data["time_multiplier"].(float64); ok {
		multiplier = mult
	}

	matchCount := 0
	for _, expr := range m.DSL {
		if e.evaluateTimeExpression(expr, resp.Duration, baseline, tolerance, multiplier) {
			matchCount++
			if condition == "or" {
				return true
			}
		} else if condition == "and" {
			return false
		}
	}

	if condition == "and" {
		return matchCount == len(m.DSL)
	}
	return matchCount > 0
}

// evaluateTimeExpression evaluates a single time comparison expression.
func (e *MatcherEngine) evaluateTimeExpression(expr string, duration, baseline, tolerance time.Duration, multiplier float64) bool {
	expr = strings.TrimSpace(expr)

	// Parse operator and value from expression
	var operator string
	var valueStr string

	// Handle multiplier expressions like ">= baseline * 3"
	if strings.Contains(expr, "baseline") {
		if strings.Contains(expr, ">=") {
			operator = ">="
		} else if strings.Contains(expr, "<=") {
			operator = "<="
		} else if strings.Contains(expr, ">") {
			operator = ">"
		} else if strings.Contains(expr, "<") {
			operator = "<"
		} else if strings.Contains(expr, "==") {
			operator = "=="
		}

		threshold := time.Duration(float64(baseline) * multiplier)
		return e.compareTime(duration, threshold, tolerance, operator)
	}

	// Parse standard expressions like "> 5s", "< 2s", ">= 3s", "<= 1s", "== 2s"
	if strings.HasPrefix(expr, ">=") {
		operator = ">="
		valueStr = strings.TrimSpace(expr[2:])
	} else if strings.HasPrefix(expr, "<=") {
		operator = "<="
		valueStr = strings.TrimSpace(expr[2:])
	} else if strings.HasPrefix(expr, "==") {
		operator = "=="
		valueStr = strings.TrimSpace(expr[2:])
	} else if strings.HasPrefix(expr, ">") {
		operator = ">"
		valueStr = strings.TrimSpace(expr[1:])
	} else if strings.HasPrefix(expr, "<") {
		operator = "<"
		valueStr = strings.TrimSpace(expr[1:])
	} else {
		return false
	}

	threshold, err := time.ParseDuration(valueStr)
	if err != nil {
		return false
	}

	return e.compareTime(duration, threshold, tolerance, operator)
}

// compareTime performs time comparison with the given operator.
func (e *MatcherEngine) compareTime(duration, threshold, tolerance time.Duration, operator string) bool {
	switch operator {
	case ">":
		return duration > threshold
	case "<":
		return duration < threshold
	case ">=":
		return duration >= threshold
	case "<=":
		return duration <= threshold
	case "==":
		// Use tolerance for equality comparison
		diff := duration - threshold
		if diff < 0 {
			diff = -diff
		}
		return diff <= tolerance
	default:
		return false
	}
}
