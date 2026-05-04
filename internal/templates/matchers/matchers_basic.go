package matchers

import (
	"bytes"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

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
	var headerSb strings.Builder
	for k, v := range resp.Headers {
		headerSb.WriteString(k)
		headerSb.WriteString(": ")
		headerSb.WriteString(v)
		headerSb.WriteString("\n")
	}
	headerStr := headerSb.String()

	rawStr := headerStr + "\n" + resp.Body

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

	for k, v := range resp.Headers {
		ctx["header_"+strings.ToLower(strings.ReplaceAll(k, "-", "_"))] = v
	}

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
