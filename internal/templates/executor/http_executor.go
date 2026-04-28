package executor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

// executeHTTP executes an HTTP request from a template.
func (e *Executor) executeHTTP(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string) ([]*templates.ExecutionResult, error) {
	// Race condition mode: send multiple concurrent requests.
	if httpReq.Race && httpReq.RaceCount > 0 {
		vars := e.buildVariables(tmpl, targetURL)
		return e.executeHTTPRace(ctx, tmpl, httpReq, targetURL, vars)
	}

	// Use req-condition path when all responses must be collected before matching.
	if httpReq.ReqCondition {
		return e.executeHTTPWithReqCondition(ctx, tmpl, httpReq, targetURL)
	}

	// Create per-request-block client once.
	client := e.clientForRequest(httpReq)

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
				result := e.executeRequest(ctx, client, tmpl, httpReq, requestURL, httpReq.Method, body, payloadVars)
				results = append(results, result)
				e.mergeExtractedIntoVars(result, vars)
				if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
					return results, nil
				}
			}

			for _, raw := range httpReq.Raw {
				result := e.executeRawRequest(ctx, client, tmpl, httpReq, raw, targetURL, payloadVars)
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

			result := e.executeRequest(ctx, client, tmpl, httpReq, requestURL, httpReq.Method, httpReq.Body, vars)
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
			result := e.executeRawRequest(ctx, client, tmpl, httpReq, raw, targetURL, vars)
			results = append(results, result)
			e.mergeExtractedIntoVars(result, vars)

			if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
				return results, nil
			}
		}
	}

	// Handle fuzzing
	if len(httpReq.Fuzzing) > 0 {
		fuzzResults := e.executeFuzzing(ctx, client, tmpl, httpReq, targetURL, vars)
		results = append(results, fuzzResults...)
	}

	return results, nil
}

// executeHTTPRace sends RaceCount concurrent requests for each path and collects all results.
func (e *Executor) executeHTTPRace(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string, vars map[string]interface{}) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create per-request-block client once for all race goroutines.
	client := e.clientForRequest(httpReq)

	for _, path := range httpReq.Path {
		interpolatedPath := e.interpolate(path, vars)
		requestURL := e.buildURL(targetURL, interpolatedPath)

		for i := 0; i < httpReq.RaceCount; i++ {
			wg.Add(1)
			// Copy vars for goroutine safety.
			goroutineVars := make(map[string]interface{}, len(vars))
			for k, v := range vars {
				goroutineVars[k] = v
			}
			go func(url string, gv map[string]interface{}) {
				defer wg.Done()
				result := e.executeRequest(ctx, client, tmpl, httpReq, url, httpReq.Method, httpReq.Body, gv)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}(requestURL, goroutineVars)
		}
	}

	wg.Wait()
	return results, nil
}

// executeHTTPWithReqCondition executes all path-based requests sequentially,
// accumulates indexed variables (status_code_N, body_N, header_N, content_length_N),
// then evaluates matchers once against the last response with all accumulated vars.
func (e *Executor) executeHTTPWithReqCondition(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string) ([]*templates.ExecutionResult, error) {
	vars := e.buildVariables(tmpl, targetURL)

	// Create per-request-block client once.
	client := e.clientForRequest(httpReq)

	type responseEntry struct {
		result      *templates.ExecutionResult
		matcherResp *matchers.Response
		requestURL  string
	}

	var entries []responseEntry

	// Collect all path-based responses
	for _, path := range httpReq.Path {
		interpolatedPath := e.interpolate(path, vars)
		requestURL := e.buildURL(targetURL, interpolatedPath)

		resp, reqStr, err := e.doRequest(ctx, client, httpReq, requestURL, httpReq.Method, httpReq.Body, vars)

		result := &templates.ExecutionResult{
			TemplateID:   tmpl.ID,
			TemplateName: tmpl.Info.Name,
			Severity:     tmpl.Info.Severity,
			URL:          requestURL,
			Timestamp:    time.Now(),
		}

		if err != nil {
			result.Error = err
			entries = append(entries, responseEntry{result: result, requestURL: requestURL})
			continue
		}

		result.Request = reqStr
		mr := buildMatcherResponse(resp)
		entries = append(entries, responseEntry{result: result, matcherResp: mr, requestURL: requestURL})
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Build accumulated vars with indexed keys
	for i, entry := range entries {
		n := i + 1
		if entry.matcherResp != nil {
			vars[fmt.Sprintf("status_code_%d", n)] = entry.matcherResp.StatusCode
			vars[fmt.Sprintf("body_%d", n)] = entry.matcherResp.Body
			vars[fmt.Sprintf("content_length_%d", n)] = entry.matcherResp.ContentLength
			// Flatten headers to a single string for header_N
			var headerStr strings.Builder
			for k, v := range entry.matcherResp.Headers {
				headerStr.WriteString(k)
				headerStr.WriteString(": ")
				headerStr.WriteString(v)
				headerStr.WriteString("\n")
			}
			vars[fmt.Sprintf("header_%d", n)] = headerStr.String()
		}
	}

	// Evaluate matchers against the last successful response
	last := entries[len(entries)-1]
	if last.matcherResp != nil {
		matched, extracts := e.matcherEngine.MatchAll(httpReq.Matchers, httpReq.MatchersCondition, last.matcherResp, vars)
		if matched {
			last.result.Matched = true
			last.result.MatchedAt = last.requestURL
			last.result.ExtractedData = extracts
			last.result.Response = last.matcherResp.Body
			if len(last.result.Response) > 500 {
				last.result.Response = last.result.Response[:500] + "..."
			}
		}
	}

	results := make([]*templates.ExecutionResult, 0, len(entries))
	for _, entry := range entries {
		results = append(results, entry.result)
	}
	return results, nil
}

// clientForRequest returns a client clone with per-request redirect settings applied.
func (e *Executor) clientForRequest(httpReq *templates.HTTPRequest) *http.Client {
	if httpReq.Redirects {
		return e.client.Clone().WithFollowRedirects(true)
	}
	return e.client.Clone().WithFollowRedirects(false)
}

// doRequest builds and executes an HTTP request, returning the response, request string, and any error.
// It injects session cookies before the request and stores response cookies afterward.
func (e *Executor) doRequest(ctx context.Context, client *http.Client, httpReq *templates.HTTPRequest, requestURL, method, body string, vars map[string]interface{}) (*http.Response, string, error) {
	if method == "" {
		method = "GET"
	}

	interpolatedBody := e.interpolate(body, vars)

	req := &http.Request{
		Method:  method,
		URL:     requestURL,
		Body:    interpolatedBody,
		Headers: make(map[string]string),
	}

	for k, v := range httpReq.Headers {
		req.Headers[k] = e.interpolate(v, vars)
	}

	if method == "POST" && req.Body != "" && req.Headers["Content-Type"] == "" {
		req.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	// Inject session cookies before executing
	if cookieHeader := e.session.CookieHeader(requestURL); cookieHeader != "" {
		if req.Headers["Cookie"] == "" {
			req.Headers["Cookie"] = cookieHeader
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, "", err
	}

	// Store response cookies in session
	e.session.ParseResponseURL(requestURL, resp.Headers)

	return resp, fmt.Sprintf("%s %s", method, requestURL), nil
}

// executeRequest executes a single HTTP request and evaluates matchers.
func (e *Executor) executeRequest(ctx context.Context, client *http.Client, tmpl *templates.Template, httpReq *templates.HTTPRequest, requestURL, method, body string, vars map[string]interface{}) *templates.ExecutionResult {
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

	// Inject session cookies before executing
	if cookieHeader := e.session.CookieHeader(requestURL); cookieHeader != "" {
		if req.Headers["Cookie"] == "" {
			req.Headers["Cookie"] = cookieHeader
		}
	}

	// Execute request
	resp, err := client.Do(ctx, req)
	if err != nil {
		result.Error = err
		return result
	}

	// Store response cookies in session
	e.session.ParseResponseURL(requestURL, resp.Headers)

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
func (e *Executor) executeRawRequest(ctx context.Context, client *http.Client, tmpl *templates.Template, httpReq *templates.HTTPRequest, raw, targetURL string, vars map[string]interface{}) *templates.ExecutionResult {
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

	// Inject session cookies before executing
	if cookieHeader := e.session.CookieHeader(requestURL); cookieHeader != "" {
		if req.Headers["Cookie"] == "" {
			req.Headers["Cookie"] = cookieHeader
		}
	}

	// Execute request
	resp, err := client.Do(ctx, req)
	if err != nil {
		result.Error = err
		return result
	}

	// Store response cookies in session
	e.session.ParseResponseURL(requestURL, resp.Headers)

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
