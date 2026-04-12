package executor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// extractRegex extracts data using regex patterns.
func extractRegex(patterns []string, content string, group int) []string {
	var results []string

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if group > 0 && group < len(match) {
				results = append(results, match[group])
			} else if len(match) > 1 {
				results = append(results, match[1])
			} else if len(match) > 0 {
				results = append(results, match[0])
			}
		}
	}

	return results
}

// extractKVal extracts key-value pairs from headers.
func extractKVal(keys []string, headers map[string]string) []string {
	var results []string

	for _, key := range keys {
		// Try exact match first
		if v, ok := headers[key]; ok {
			results = append(results, v)
			continue
		}

		// Try case-insensitive match
		keyLower := strings.ToLower(key)
		for k, v := range headers {
			if strings.ToLower(k) == keyLower {
				results = append(results, v)
				break
			}
		}
	}

	return results
}

// extractJSON extracts data from JSON using simple path expressions.
// It supports JQ-like pipe syntax for array iteration, e.g. ".[] | .name".
func extractJSON(paths []string, content string) []string {
	var results []string

	var data interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return results
	}

	for _, path := range paths {
		if strings.Contains(path, "|") {
			parts := strings.SplitN(path, "|", 2)
			selector := strings.TrimSpace(parts[0])
			field := strings.TrimSpace(parts[1])
			if selector == ".[]" {
				fieldName := strings.TrimPrefix(field, ".")
				if arr, ok := data.([]interface{}); ok {
					for _, item := range arr {
						if m, ok := item.(map[string]interface{}); ok {
							if v, ok := m[fieldName]; ok {
								results = append(results, fmt.Sprintf("%v", v))
							}
						}
					}
				}
			}
			continue
		}
		value := extractJSONPath(data, path)
		if value != "" {
			results = append(results, value)
		}
	}

	return results
}

// extractJSONPath extracts a value from JSON using a simple dot-notation path.
func extractJSONPath(data interface{}, path string) string {
	parts := strings.Split(path, ".")

	current := data
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			if next, ok := v[part]; ok {
				current = next
			} else {
				return ""
			}
		case []interface{}:
			// Try to get first element
			if len(v) > 0 {
				if m, ok := v[0].(map[string]interface{}); ok {
					if next, ok := m[part]; ok {
						current = next
					} else {
						return ""
					}
				}
			}
		default:
			return ""
		}
	}

	// Convert result to string
	switch v := current.(type) {
	case string:
		return v
	case float64:
		// Format as integer if it's a whole number
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return fmt.Sprintf("%g", v)
	case bool:
		return strconv.FormatBool(v)
	case nil:
		return "null"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// extractXPath extracts data using XPath expressions.
// Note: This is a simplified implementation. Full XPath requires an XML parser.
func extractXPath(paths []string, content string) []string {
	var results []string

	// Simple tag extraction for basic XPath like //tag or /root/tag
	for _, path := range paths {
		// Remove // prefix
		path = strings.TrimPrefix(path, "//")
		path = strings.TrimPrefix(path, "/")

		// Get the last tag in the path
		parts := strings.Split(path, "/")
		tag := parts[len(parts)-1]

		// Handle attribute selectors like tag[@attr='value']
		if idx := strings.Index(tag, "["); idx > 0 {
			tag = tag[:idx]
		}

		// Simple regex-based extraction
		pattern := `<` + regexp.QuoteMeta(tag) + `[^>]*>([^<]*)</` + regexp.QuoteMeta(tag) + `>`
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				results = append(results, match[1])
			}
		}
	}

	return results
}
