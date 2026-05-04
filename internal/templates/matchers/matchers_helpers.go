package matchers

import (
	"regexp"
	"strconv"
	"strings"
)

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
