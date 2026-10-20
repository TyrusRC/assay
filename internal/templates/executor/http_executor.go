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
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
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
				body := e.interpolate(httpReq.Body, gv)
				result := e.executeRequest(ctx, client, tmpl, httpReq, url, httpReq.Method, body, gv)
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

// executeUnsafeRawRequest sends a raw HTTP request over a plain TCP (or
// TLS) connection without any HTTP-level normalization. This is required
// for HTTP request smuggling templates where the precise byte sequence on
// the wire matters (malformed Content-Length, Transfer-Encoding mismatches,
// etc.). The response is read as raw bytes and parsed minimally.
func (e *Executor) executeUnsafeRawRequest(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, raw, targetURL string, vars map[string]interface{}) *templates.ExecutionResult {
	interpolatedRaw := e.interpolate(raw, vars)

	result := &templates.ExecutionResult{
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		URL:          targetURL,
		Timestamp:    time.Now(),
		Request:      interpolatedRaw,
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		result.Error = fmt.Errorf("unsafe raw: parse target: %w", err)
		return result
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: e.config.Timeout}
	var conn net.Conn
	if parsed.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		result.Error = fmt.Errorf("unsafe raw: dial %s: %w", addr, err)
		return result
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(e.config.Timeout)
	}
	conn.SetDeadline(deadline)

	// Normalise line endings to \r\n and ensure double CRLF terminates
	// headers when not already present.
	payload := strings.ReplaceAll(interpolatedRaw, "\r\n", "\n")
	payload = strings.ReplaceAll(payload, "\n", "\r\n")

	if _, err := io.WriteString(conn, payload); err != nil {
		result.Error = fmt.Errorf("unsafe raw: write: %w", err)
		return result
	}

	respBuf, err := io.ReadAll(io.LimitReader(conn, 10<<20))
	if err != nil && len(respBuf) == 0 {
		result.Error = fmt.Errorf("unsafe raw: read: %w", err)
		return result
	}

	respStr := string(respBuf)
	statusCode, headers, body := parseRawHTTPResponse(respStr)

	mr := &matchers.Response{
		StatusCode:    statusCode,
		Headers:       headers,
		Body:          body,
		ContentLength: len(body),
		Raw:           respStr,
	}

	matched, extracts := e.matcherEngine.MatchAll(httpReq.Matchers, httpReq.MatchersCondition, mr, vars)
	result.Matched = matched
	result.ExtractedData = extracts
	if matched {
		result.MatchedAt = targetURL
		result.Response = body
		if len(result.Response) > 500 {
			result.Response = result.Response[:500] + "..."
		}
	}
	return result
}

// parseRawHTTPResponse minimally parses a raw HTTP response into status
// code, headers map, and body. Tolerant of malformed responses — returns
// best-effort values.
func parseRawHTTPResponse(raw string) (int, map[string]string, string) {
	headers := make(map[string]string)
	idx := strings.Index(raw, "\r\n\r\n")
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
	}
	var headerBlock, body string
	if idx >= 0 {
		headerBlock = raw[:idx]
		body = raw[idx:]
		// Strip the separator itself.
		if strings.HasPrefix(body, "\r\n\r\n") {
			body = body[4:]
		} else if strings.HasPrefix(body, "\n\n") {
			body = body[2:]
		}
	} else {
		headerBlock = raw
	}

	lines := strings.Split(headerBlock, "\n")
	statusCode := 0
	if len(lines) > 0 {
		// e.g. "HTTP/1.1 200 OK"
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &statusCode)
		}
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if ci := strings.Index(line, ":"); ci > 0 {
			headers[strings.TrimSpace(line[:ci])] = strings.TrimSpace(line[ci+1:])
		}
	}
	return statusCode, headers, body
}

// executeHTTPPipeline sends multiple HTTP requests over a single TCP
// connection without waiting for intermediate responses (HTTP pipelining).
// This is used for HTTP/2 desync and pipeline-based race templates.
func (e *Executor) executeHTTPPipeline(ctx context.Context, tmpl *templates.Template, httpReq *templates.HTTPRequest, targetURL string, vars map[string]interface{}) []*templates.ExecutionResult {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		r := &templates.ExecutionResult{
			TemplateID: tmpl.ID, TemplateName: tmpl.Info.Name,
			Severity: tmpl.Info.Severity, URL: targetURL,
			Timestamp: time.Now(), Error: err,
		}
		return []*templates.ExecutionResult{r}
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: e.config.Timeout}
	var conn net.Conn
	if parsed.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		r := &templates.ExecutionResult{
			TemplateID: tmpl.ID, TemplateName: tmpl.Info.Name,
			Severity: tmpl.Info.Severity, URL: targetURL,
			Timestamp: time.Now(), Error: err,
		}
		return []*templates.ExecutionResult{r}
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(e.config.Timeout)
	}
	conn.SetDeadline(deadline)

	// Build and send all requests back-to-back.
	var reqStrings []string
	for _, path := range httpReq.Path {
		interpolatedPath := e.interpolate(path, vars)
		requestURL := e.buildURL(targetURL, interpolatedPath)
		method := httpReq.Method
		if method == "" {
			method = "GET"
		}
		body := e.interpolate(httpReq.Body, vars)

		var sb strings.Builder
		u, _ := url.Parse(requestURL)
		reqPath := u.RequestURI()
		sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, reqPath))
		sb.WriteString(fmt.Sprintf("Host: %s\r\n", host))
		for k, v := range httpReq.Headers {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, e.interpolate(v, vars)))
		}
		if body != "" {
			sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		sb.WriteString("\r\n")
		if body != "" {
			sb.WriteString(body)
		}
		raw := sb.String()
		reqStrings = append(reqStrings, raw)
		io.WriteString(conn, raw)
	}

	// Read all responses.
	reader := bufio.NewReaderSize(conn, 64*1024)
	var results []*templates.ExecutionResult
	for i, path := range httpReq.Path {
		interpolatedPath := e.interpolate(path, vars)
		requestURL := e.buildURL(targetURL, interpolatedPath)

		result := &templates.ExecutionResult{
			TemplateID:   tmpl.ID,
			TemplateName: tmpl.Info.Name,
			Severity:     tmpl.Info.Severity,
			URL:          requestURL,
			Timestamp:    time.Now(),
		}
		if i < len(reqStrings) {
			result.Request = reqStrings[i]
		}

		// Read response: status line, headers, body.
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			result.Error = fmt.Errorf("pipeline: read status: %w", err)
			results = append(results, result)
			break
		}

		statusCode := 0
		if parts := strings.Fields(statusLine); len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &statusCode)
		}

		hdrs := make(map[string]string)
		contentLength := 0
		for {
			line, err := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" || err != nil {
				break
			}
			if ci := strings.Index(line, ":"); ci > 0 {
				k := strings.TrimSpace(line[:ci])
				v := strings.TrimSpace(line[ci+1:])
				hdrs[k] = v
				if strings.EqualFold(k, "Content-Length") {
					fmt.Sscanf(v, "%d", &contentLength)
				}
			}
		}

		var body string
		if contentLength > 0 {
			buf := make([]byte, contentLength)
			io.ReadFull(reader, buf)
			body = string(buf)
		}

		mr := &matchers.Response{
			StatusCode:    statusCode,
			Headers:       hdrs,
			Body:          body,
			ContentLength: contentLength,
			Raw:           statusLine + body,
		}

		matched, extracts := e.matcherEngine.MatchAll(httpReq.Matchers, httpReq.MatchersCondition, mr, vars)
		result.Matched = matched
		result.ExtractedData = extracts
		if matched {
			result.MatchedAt = requestURL
			result.Response = body
			if len(result.Response) > 500 {
				result.Response = result.Response[:500] + "..."
			}
		}
		results = append(results, result)
	}
	return results
}
