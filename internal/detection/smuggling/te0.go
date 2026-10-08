package smuggling

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// BuildTE0Payload builds a TE.0 desync probe. TE.0 is the Transfer-Encoding
// analogue of CL.0: the front-end honors `Transfer-Encoding: chunked` and reads
// the chunked body, while the back-end ignores TE and treats the request as
// bodyless. The chunked body therefore becomes the start of a new request on the
// same connection. The smuggled request is a benign GET, so the probe is
// read-only. Seen on some cloud front-ends that strip TE before an origin that
// does not re-parse it.
func BuildTE0Payload(host, path, canary string) string {
	smuggled := "GET /" + canary + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"\r\n"
	// One chunk carrying the smuggled request, then the zero-chunk terminator.
	chunk := strconv.FormatInt(int64(len(smuggled)), 16) + "\r\n" + smuggled + "\r\n"
	body := chunk + "0\r\n\r\n"

	return "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		body
}

// DetectTE0 tests for a TE.0 desync using the same structural signal as CL.0 and
// 0.CL: a single outer request that elicits two or more responses on one
// connection, while a baseline request elicits one. Structural confirmation
// keeps this low-FP, unlike timing- or header-only heuristics that struggle to
// separate real desync from ordinary pipelining.
func (d *Detector) DetectTE0(ctx context.Context, target, path string) *Result {
	result := &Result{Type: TypeTE0}

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
		result.Evidence = "Baseline already produced multiple responses; TE.0 signal would be ambiguous"
		return result
	}

	probe := BuildTE0Payload(host, path, "assaycanary")
	result.Request = probe

	probeRaw, _, err := SendRawRequest(ctx, addr, probe, d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("TE.0 probe failed: %v", err)
		return result
	}
	result.Response = probeRaw

	if CountResponses(probeRaw) < 2 {
		return result
	}

	result.Vulnerable = true
	result.Confidence = 0.8
	result.Evidence = "Chunked outer request elicited multiple responses on one connection: the " +
		"back-end ignored Transfer-Encoding and treated the request as bodyless, so the chunked " +
		"body started a new request (TE.0 desync)"
	result.FrontendBehavior = "Honors Transfer-Encoding: chunked"
	result.BackendBehavior = "Ignores Transfer-Encoding; treats request as bodyless"
	return result
}
