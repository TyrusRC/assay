package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/templates"
)

// doRequest builds and executes an HTTP request, returning the response,
// request string, and any error. Injects session cookies before the
// request and stores response cookies afterward.
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

	// Inject session cookies before executing.
	if cookieHeader := e.session.CookieHeader(requestURL); cookieHeader != "" {
		if req.Headers["Cookie"] == "" {
			req.Headers["Cookie"] = cookieHeader
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, "", err
	}

	// Store response cookies in session.
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
	e.session.ParseResponseURL(requestURL, resp.Headers)
	result.Request = fmt.Sprintf("%s %s", method, requestURL)

	matcherResp := buildMatcherResponse(resp)
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

	extracted := e.runExtractors(httpReq.Extractors, matcherResp, vars)
	for k, v := range extracted {
		if result.ExtractedData == nil {
			result.ExtractedData = make(map[string][]string)
		}
		result.ExtractedData[k] = v
	}
	return result
}

// executeRawRequest parses and executes a raw HTTP request (the form
// used by templates that ship a full HTTP request blob rather than
// the structured fields).
func (e *Executor) executeRawRequest(ctx context.Context, client *http.Client, tmpl *templates.Template, httpReq *templates.HTTPRequest, raw, targetURL string, vars map[string]interface{}) *templates.ExecutionResult {
	interpolatedRaw := e.interpolate(raw, vars)
	method, path, body, headers := parseRawRequest(interpolatedRaw)
	requestURL := e.buildURL(targetURL, path)

	result := &templates.ExecutionResult{
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		URL:          requestURL,
		Timestamp:    time.Now(),
	}

	req := &http.Request{
		Method:  method,
		URL:     requestURL,
		Body:    body,
		Headers: headers,
	}
	// Merge with template headers (template wins on collision-free keys).
	for k, v := range httpReq.Headers {
		if req.Headers[k] == "" {
			req.Headers[k] = e.interpolate(v, vars)
		}
	}
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
	e.session.ParseResponseURL(requestURL, resp.Headers)
	result.Request = interpolatedRaw

	matcherResp := buildMatcherResponse(resp)
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

	extracted := e.runExtractors(httpReq.Extractors, matcherResp, vars)
	for k, v := range extracted {
		if result.ExtractedData == nil {
			result.ExtractedData = make(map[string][]string)
		}
		result.ExtractedData[k] = v
	}
	return result
}
