package executor

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

// runExtractors runs extractors against a response.
// Internal extractors store their first extracted value into vars for subsequent request interpolation.
func (e *Executor) runExtractors(extractors []templates.Extractor, resp *matchers.Response, vars map[string]interface{}) map[string][]string {
	result := make(map[string][]string)
	dslEngine := matchers.NewDSLEngine()

	for _, ext := range extractors {
		var extracted []string
		content := e.getExtractPart(ext.Part, resp)

		switch ext.Type {
		case "regex":
			extracted = extractRegex(ext.Regex, content, ext.Group)
		case "kval":
			extracted = extractKVal(ext.KVal, resp.Headers)
		case "json":
			extracted = extractJSON(ext.JSON, content)
		case "xpath":
			extracted = extractXPath(ext.XPath, content)
		case "dsl":
			extracted = extractDSL(dslEngine, ext.DSL, vars)
		}

		if len(extracted) == 0 || ext.Name == "" {
			continue
		}

		if ext.Internal {
			// Store first value in vars for subsequent request interpolation
			vars[ext.Name] = extracted[0]
		} else {
			result[ext.Name] = extracted
		}
	}

	return result
}

// extractDSL evaluates DSL expressions and returns their string results.
func extractDSL(engine *matchers.DSLEngine, expressions []string, ctx map[string]interface{}) []string {
	var results []string
	for _, expr := range expressions {
		val := engine.EvaluateString(expr, ctx)
		if val != "" {
			results = append(results, val)
		}
	}
	return results
}

// getExtractPart gets the part of response to extract from.
func (e *Executor) getExtractPart(part string, resp *matchers.Response) string {
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
	default:
		return resp.Body
	}
}

// buildVariables builds the variable context for interpolation.
func (e *Executor) buildVariables(tmpl *templates.Template, targetURL string) map[string]interface{} {
	vars := make(map[string]interface{})

	// Add executor config variables
	for k, v := range e.config.Variables {
		vars[k] = v
	}

	// Add template variables
	for k, v := range tmpl.Variables {
		vars[k] = v
	}

	// Add target info
	parsedURL, err := url.Parse(targetURL)
	if err == nil {
		vars["BaseURL"] = targetURL // Full URL with path, matching Nuclei's {{BaseURL}}
		vars["RootURL"] = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		vars["Hostname"] = parsedURL.Hostname()
		vars["FQDN"] = parsedURL.Hostname() // DNS alias for Hostname
		vars["Host"] = parsedURL.Host
		vars["Port"] = parsedURL.Port()
		vars["Path"] = parsedURL.Path
		vars["Scheme"] = parsedURL.Scheme
	}

	return vars
}

// buildURL combines base URL with path.
func (e *Executor) buildURL(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + path
	}

	// Handle {{BaseURL}} prefix
	path = strings.Replace(path, "{{BaseURL}}", "", 1)
	path = strings.Replace(path, "{{RootURL}}", "", 1)

	if strings.HasPrefix(path, "/") {
		parsed.Path = path
	} else {
		parsed.Path = parsed.Path + "/" + path
	}

	return parsed.String()
}

// interpolate replaces template variables in a string.
func (e *Executor) interpolate(s string, vars map[string]interface{}) string {
	result := s

	for k, v := range vars {
		placeholder := "{{" + k + "}}"
		switch val := v.(type) {
		case string:
			result = strings.ReplaceAll(result, placeholder, val)
		case int:
			result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%d", val))
		case float64:
			result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%f", val))
		default:
			result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", val))
		}
	}

	return result
}

// parseRawRequest parses a raw HTTP request string.
func parseRawRequest(raw string) (method, path, body string, headers map[string]string) {
	headers = make(map[string]string)

	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 {
		return "GET", "/", "", headers
	}

	// Parse request line
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	} else {
		method = "GET"
		path = "/"
	}

	// Parse headers and body
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			bodyStart = i + 1
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			headers[key] = value
		}
	}

	// Extract body
	if bodyStart > 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	return method, path, body, headers
}

// applyFuzzType applies the fuzz type (replace, prefix, postfix) to a value.
func applyFuzzType(original, payload, fuzzType string) string {
	switch fuzzType {
	case "prefix":
		return payload + original
	case "postfix":
		return original + payload
	case "replace":
		return payload
	default:
		return payload
	}
}
