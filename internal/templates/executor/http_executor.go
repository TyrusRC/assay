// Package executor runs Nuclei-style templates. The HTTP request portion
// of execution is split across:
//
//	http_executor.go         — main dispatch (executeHTTP)
//	http_executor_special.go — race, req-condition, unsafe raw, pipeline
//	http_executor_fuzz.go    — fuzz-mode execution
//	http_request.go          — actual request execution (doRequest,
//	                           executeRequest, executeRawRequest)
//	http_helpers.go          — small per-request helpers (clientForRequest,
//	                           mergeExtractedIntoVars, buildMatcherResponse)
package executor

import (
	"context"

	"github.com/TyrusRC/assay/internal/templates"
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

			body := e.interpolate(httpReq.Body, vars)
			result := e.executeRequest(ctx, client, tmpl, httpReq, requestURL, httpReq.Method, body, vars)
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

	// Handle unsafe raw requests — send bytes over a raw TCP connection
	// without HTTP-level normalization, needed for smuggling templates.
	if httpReq.UnsafeRaw && len(httpReq.Raw) > 0 {
		for _, raw := range httpReq.Raw {
			result := e.executeUnsafeRawRequest(ctx, tmpl, httpReq, raw, targetURL, vars)
			results = append(results, result)
			e.mergeExtractedIntoVars(result, vars)
			if result.Matched && (httpReq.StopAtFirstMatch || e.config.StopAtFirstMatch) {
				return results, nil
			}
		}
	}

	// Pipeline mode: send all path-based requests over a single TCP
	// connection without waiting for intermediate responses.
	if httpReq.Pipeline && len(httpReq.Path) > 1 {
		pipeResults := e.executeHTTPPipeline(ctx, tmpl, httpReq, targetURL, vars)
		results = append(results, pipeResults...)
		return results, nil
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
