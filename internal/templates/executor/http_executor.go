// Package executor runs Nuclei-style templates. The HTTP request portion
// of execution is split across:
//
//	http_executor.go — dispatch (executeHTTP, executeHTTPRace,
//	                   executeHTTPWithReqCondition)
//	http_request.go  — actual request execution (doRequest,
//	                   executeRequest, executeRawRequest)
//	http_helpers.go  — small per-request helpers (clientForRequest,
//	                   mergeExtractedIntoVars, buildMatcherResponse)
package executor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/templates"
	"github.com/TyrusRC/assay/internal/templates/matchers"
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

	// Handle path-based requests.
	if len(httpReq.Path) > 0 {
		for _, path := range httpReq.Path {
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

	// Handle raw requests.
	if len(httpReq.Raw) > 0 {
		for _, raw := range httpReq.Raw {
			result := e.executeRawRequest(ctx, client, tmpl, httpReq, raw, targetURL, vars)
			results = append(results, result)
			e.mergeExtractedIntoVars(result, vars)

			if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
				return results, nil
			}
		}
	}

	// Handle fuzzing.
	if len(httpReq.Fuzzing) > 0 {
		fuzzResults := e.executeFuzzing(ctx, client, tmpl, httpReq, targetURL, vars)
		results = append(results, fuzzResults...)
	}

	return results, nil
}

// executeHTTPRace sends RaceCount concurrent requests for each path and
// collects all results. Used by templates that exercise a time-of-check-
// to-time-of-use race window.
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

// executeHTTPWithReqCondition executes all path-based requests
// sequentially, accumulates indexed variables (status_code_N, body_N,
// header_N, content_length_N), then evaluates matchers once against the
// last response with all accumulated vars.
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

	// Collect all path-based responses.
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

	// Build accumulated vars with indexed keys.
	for i, entry := range entries {
		n := i + 1
		if entry.matcherResp != nil {
			vars[fmt.Sprintf("status_code_%d", n)] = entry.matcherResp.StatusCode
			vars[fmt.Sprintf("body_%d", n)] = entry.matcherResp.Body
			vars[fmt.Sprintf("content_length_%d", n)] = entry.matcherResp.ContentLength
			// Flatten headers to a single string for header_N.
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

	// Evaluate matchers against the last successful response.
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
