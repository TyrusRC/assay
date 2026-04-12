package executor

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

// executeHTTP executes an HTTP request from a template.
func (e *Executor) executeHTTP(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	// Build variables context
	vars := e.buildVariables(tmpl, targetURL)

	// If payloads are defined, generate combinations and execute for each.
	if len(httpReq.Payloads) > 0 {
		resolved := ResolvePayloads(httpReq.Payloads)
		combos := GeneratePayloadCombinations(resolved, httpReq.AttackType)

		for _, combo := range combos {
			payloadVars := make(map[string]interface{}, len(vars)+len(combo))
			for k, v := range vars {
				payloadVars[k] = v
			}
			for k, v := range combo {
				payloadVars[k] = v
			}

			for _, path := range httpReq.Path {
				interpolatedPath := e.interpolate(path, payloadVars)
				requestURL := e.buildURL(targetURL, interpolatedPath)
				body := e.interpolate(httpReq.Body, payloadVars)
				result := e.executeRequest(ctx, tmpl, httpReq, requestURL, httpReq.Method, body, payloadVars)
				results = append(results, result)
				e.mergeExtractedIntoVars(result, vars)
				if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
					return results, nil
				}
			}

			for _, raw := range httpReq.Raw {
				result := e.executeRawRequest(ctx, tmpl, httpReq, raw, targetURL, payloadVars)
				results = append(results, result)
				e.mergeExtractedIntoVars(result, vars)
				if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
					return results, nil
				}
			}
		}

		return results, nil
	}

	// Handle path-based requests
	if len(httpReq.Path) > 0 {
		for _, path := range httpReq.Path {
			// Interpolate variables in path
			interpolatedPath := e.interpolate(path, vars)
			requestURL := e.buildURL(targetURL, interpolatedPath)

			result := e.executeRequest(ctx, tmpl, httpReq, requestURL, httpReq.Method, httpReq.Body, vars)
			results = append(results, result)
			e.mergeExtractedIntoVars(result, vars)

			if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
				return results, nil
			}
		}
	}

	// Handle raw requests
	if len(httpReq.Raw) > 0 {
		for _, raw := range httpReq.Raw {
			// Parse and execute raw request
			result := e.executeRawRequest(ctx, tmpl, httpReq, raw, targetURL, vars)
			results = append(results, result)
			e.mergeExtractedIntoVars(result, vars)

			if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
				return results, nil
			}
		}
	}

	// Handle fuzzing
	if len(httpReq.Fuzzing) > 0 {
		fuzzResults := e.executeFuzzing(ctx, tmpl, httpReq, targetURL, vars)
		results = append(results, fuzzResults...)
	}

	return results, nil
}

// executeRequest executes a single HTTP request and evaluates matchers.
func (e *Executor) executeRequest(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, requestURL, method, body string, vars map[string]interface{}) *templates.ExecutionResult {
	result := &templates.ExecutionResult{
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		URL:          requestURL,
		Timestamp:    time.Now(),
	}

	if method == "" {
		method = "GET"
	}

	// Interpolate body
	interpolatedBody := e.interpolate(body, vars)

	// Build request
	req := &http.Request{
		Method:  method,
		URL:     requestURL,
		Body:    interpolatedBody,
		Headers: make(map[string]string),
	}

	// Add headers
	for k, v := range httpReq.Headers {
		req.Headers[k] = e.interpolate(v, vars)
	}

	// Set content type for POST
	if method == "POST" && req.Body != "" && req.Headers["Content-Type"] == "" {
		req.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	// Execute request
	resp, err := e.client.Do(ctx, req)
	if err != nil {
		result.Error = err
		return result
	}

	result.Request = fmt.Sprintf("%s %s", method, requestURL)

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

	// Run extractors
	extracted := e.runExtractors(httpReq.Extractors, matcherResp, vars)
	for k, v := range extracted {
		if result.ExtractedData == nil {
			result.ExtractedData = make(map[string][]string)
		}
		result.ExtractedData[k] = v
	}

	return result
}

// executeRawRequest parses and executes a raw HTTP request.
func (e *Executor) executeRawRequest(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, raw, targetURL string, vars map[string]interface{}) *templates.ExecutionResult {
	// Interpolate variables in raw request
	interpolatedRaw := e.interpolate(raw, vars)

	// Parse raw request
	method, path, body, headers := parseRawRequest(interpolatedRaw)

	// Build full URL
	requestURL := e.buildURL(targetURL, path)

	result := &templates.ExecutionResult{
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		URL:          requestURL,
		Timestamp:    time.Now(),
	}

	// Build request
	req := &http.Request{
		Method:  method,
		URL:     requestURL,
		Body:    body,
		Headers: headers,
	}

	// Merge with template headers
	for k, v := range httpReq.Headers {
		if req.Headers[k] == "" {
			req.Headers[k] = e.interpolate(v, vars)
		}
	}

	// Execute request
	resp, err := e.client.Do(ctx, req)
	if err != nil {
		result.Error = err
		return result
	}

	result.Request = interpolatedRaw

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

// executeFuzzing executes fuzzing rules against the target.
func (e *Executor) executeFuzzing(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string, vars map[string]interface{}) []*templates.ExecutionResult {
	var results []*templates.ExecutionResult

	for _, rule := range httpReq.Fuzzing {
		fuzzPayloads := e.generateFuzzPayloads(&rule, vars)

		for _, payload := range fuzzPayloads {
			result := e.executeFuzzRequest(ctx, tmpl, httpReq, targetURL, &rule, payload, vars)
			results = append(results, result)

			if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
				return results
			}
		}
	}

	return results
}

// executeFuzzRequest executes a single fuzz request.
func (e *Executor) executeFuzzRequest(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string, rule *templates.FuzzingRule, payload string, vars map[string]interface{}) *templates.ExecutionResult {
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

	// Execute request
	req := &http.Request{
		Method:  method,
		URL:     requestURL,
		Body:    body,
		Headers: headers,
	}

	resp, err := e.client.Do(ctx, req)
	if err != nil {
		result.Error = err
		return result
	}

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

// mergeExtractedIntoVars merges extracted data from a result into the vars map,
// making values available for interpolation in subsequent requests.
func (e *Executor) mergeExtractedIntoVars(result *templates.ExecutionResult, vars map[string]interface{}) {
	if result.ExtractedData == nil {
		return
	}
	for k, v := range result.ExtractedData {
		if len(v) > 0 {
			vars[k] = v[0]
		}
	}
}

// buildMatcherResponse constructs a matchers.Response from an HTTP response.
func buildMatcherResponse(resp *http.Response) *matchers.Response {
	return &matchers.Response{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Headers,
		Body:          resp.Body,
		ContentLength: int(resp.ContentLength),
		ContentType:   resp.ContentType,
		URL:           resp.URL,
		Raw:           fmt.Sprintf("HTTP/1.1 %s\n%s", resp.Status, resp.Body),
		Duration:      resp.Duration,
	}
}
