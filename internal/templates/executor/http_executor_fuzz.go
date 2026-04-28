package executor

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

// executeFuzzing executes fuzzing rules against the target.
func (e *Executor) executeFuzzing(ctx context.Context, client *http.Client, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string, vars map[string]interface{}) []*templates.ExecutionResult {
	var results []*templates.ExecutionResult

	for _, rule := range httpReq.Fuzzing {
		fuzzPayloads := e.generateFuzzPayloads(&rule, vars)

		for _, payload := range fuzzPayloads {
			result := e.executeFuzzRequest(ctx, client, tmpl, httpReq, targetURL, &rule, payload, vars)
			results = append(results, result)

			if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
				return results
			}
		}
	}

	return results
}

// executeFuzzRequest executes a single fuzz request.
func (e *Executor) executeFuzzRequest(ctx context.Context, client *http.Client, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string, rule *templates.FuzzingRule, payload string, vars map[string]interface{}) *templates.ExecutionResult {
	result := &templates.ExecutionResult{
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		URL:          targetURL,
		Timestamp:    time.Now(),
	}

	method := httpReq.Method
	if method == "" {
		method = "GET"
	}

	var requestURL string
	var body string
	headers := make(map[string]string)

	// Copy template headers
	for k, v := range httpReq.Headers {
		headers[k] = e.interpolate(v, vars)
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Error = err
		return result
	}

	switch rule.Part {
	case "query":
		// Fuzz query parameters
		query := parsedURL.Query()
		if rule.KeysAll {
			for key := range query {
				query.Set(key, applyFuzzType(query.Get(key), payload, rule.Type))
			}
		} else if len(rule.Keys) > 0 {
			for _, key := range rule.Keys {
				if query.Has(key) {
					query.Set(key, applyFuzzType(query.Get(key), payload, rule.Type))
				}
			}
		}
		parsedURL.RawQuery = query.Encode()
		requestURL = parsedURL.String()

	case "body":
		requestURL = targetURL
		body = applyFuzzType(httpReq.Body, payload, rule.Type)
		if headers["Content-Type"] == "" {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}

	case "header":
		requestURL = targetURL
		for _, key := range rule.Keys {
			headers[key] = applyFuzzType(headers[key], payload, rule.Type)
		}

	case "path":
		path := parsedURL.Path
		parsedURL.Path = applyFuzzType(path, payload, rule.Type)
		requestURL = parsedURL.String()

	default:
		requestURL = targetURL
	}

	// Build request
	req := &http.Request{
		Method:  method,
		URL:     requestURL,
		Body:    body,
		Headers: headers,
	}

	// Inject session cookies before executing
	if cookieHeader := e.session.CookieHeader(requestURL); cookieHeader != "" {
		if req.Headers["Cookie"] == "" {
			req.Headers["Cookie"] = cookieHeader
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		result.Error = err
		return result
	}

	// Store response cookies in session
	e.session.ParseResponseURL(requestURL, resp.Headers)

	result.Request = fmt.Sprintf("%s %s [fuzz=%s]", method, requestURL, payload)

	// Build matcher response
	matcherResp := buildMatcherResponse(resp)

	// Evaluate matchers
	matched, extracts := e.matcherEngine.MatchAll(httpReq.Matchers, httpReq.MatchersCondition, matcherResp, vars)
	result.Matched = matched
	result.ExtractedData = extracts

	if matched {
		result.MatchedAt = requestURL
		result.Response = resp.Body
		if len(result.Response) > 500 {
			result.Response = result.Response[:500] + "..."
		}
	}

	return result
}

// generateFuzzPayloads generates payloads from a fuzzing rule.
func (e *Executor) generateFuzzPayloads(rule *templates.FuzzingRule, vars map[string]interface{}) []string {
	var payloads []string

	// Use fuzz field if specified
	if len(rule.Fuzz) > 0 {
		for _, f := range rule.Fuzz {
			payloads = append(payloads, e.interpolate(f, vars))
		}
	}

	// Use values field if specified
	if len(rule.Values) > 0 {
		for _, v := range rule.Values {
			payloads = append(payloads, e.interpolate(v, vars))
		}
	}

	return payloads
}
