package scanner

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// uuidPattern matches UUID-like strings in path segments.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// numericPattern matches purely numeric path segments.
var numericPattern = regexp.MustCompile(`^[0-9]+$`)

// extractParameters extracts testable parameters from the target URL.
// It returns query parameters and path segments that look like IDs.
func (s *InternalScanner) extractParameters(target *core.Target) []core.Parameter {
	return s.extractParametersWithConfig(target, nil)
}

// extractParametersWithConfig extracts testable parameters from the target URL
// and scan configuration. It identifies query params, cookie params, and
// path segments that look like IDs (numeric or UUID).
func (s *InternalScanner) extractParametersWithConfig(target *core.Target, scanConfig *Config) []core.Parameter {
	var params []core.Parameter
	seen := make(map[string]bool)

	// Parse URL to get query parameters
	parsedURL, err := url.Parse(target.URL())
	if err != nil {
		return params
	}

	// Extract query parameters
	for key, values := range parsedURL.Query() {
		seenKey := "query:" + key
		if !seen[seenKey] {
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			params = append(params, core.Parameter{
				Name:     key,
				Location: core.ParamLocationQuery,
				Value:    value,
				Type:     "string",
			})
			seen[seenKey] = true
		}
	}

	// Extract cookie parameters from config
	if scanConfig != nil && scanConfig.Cookies != "" {
		cookies := strings.Split(scanConfig.Cookies, ";")
		for _, cookie := range cookies {
			cookie = strings.TrimSpace(cookie)
			if cookie == "" {
				continue
			}
			parts := strings.SplitN(cookie, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			seenKey := "cookie:" + name
			if !seen[seenKey] {
				params = append(params, core.Parameter{
					Name:     name,
					Location: core.ParamLocationCookie,
					Value:    value,
					Type:     "string",
				})
				seen[seenKey] = true
			}
		}
	}

	// Extract path segments that look like IDs (numeric or UUID)
	pathSegments := strings.Split(parsedURL.Path, "/")
	segmentIdx := 0
	for _, seg := range pathSegments {
		if seg == "" {
			continue
		}
		if numericPattern.MatchString(seg) {
			seenKey := fmt.Sprintf("path:%d", segmentIdx)
			if !seen[seenKey] {
				params = append(params, core.Parameter{
					Name:     fmt.Sprintf("path_%d", segmentIdx),
					Location: core.ParamLocationPath,
					Value:    seg,
					Type:     "number",
				})
				seen[seenKey] = true
			}
		} else if uuidPattern.MatchString(seg) {
			seenKey := fmt.Sprintf("path:%d", segmentIdx)
			if !seen[seenKey] {
				params = append(params, core.Parameter{
					Name:     fmt.Sprintf("path_%d", segmentIdx),
					Location: core.ParamLocationPath,
					Value:    seg,
					Type:     "string",
				})
				seen[seenKey] = true
			}
		}
		segmentIdx++
	}

	return params
}
