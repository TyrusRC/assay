package smuggling

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// BuildCL0Payload builds a CL.0 desync probe. The outer request carries a
// Content-Length that exactly covers a complete smuggled request in its body.
// A compliant back-end reads the body as the outer request's body and returns
// one response; a CL.0-vulnerable back-end ignores the Content-Length, parses
// the body as a second request, and returns a second response on the same
// connection. The smuggled request is a benign GET to a canary path, so the
// probe is read-only.
func BuildCL0Payload(host, path, canary string) string {
	smuggled := "GET /" + canary + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"\r\n"

	return "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)\r\n" +
		"Content-Length: " + strconv.Itoa(len(smuggled)) + "\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		smuggled
}

// CountResponses counts complete HTTP response status lines in a raw byte
// stream read from a single connection. More than one means the server emitted
// multiple responses — the structural signal for a CL.0 desync.
func CountResponses(raw string) int {
	count := 0
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "HTTP/1.") || strings.HasPrefix(line, "HTTP/2") {
			count++
		}
	}
	return count
}

// DetectCL0 tests for a CL.0 desync. Detection is structural, not timing-based:
// the probe is vulnerable only when a single outer request elicits two or more
// responses on one connection while a normal baseline request elicits one. This
// avoids the false positives that pure timing oracles produce.
func (d *Detector) DetectCL0(ctx context.Context, target, path string) *Result {
	result := &Result{Type: TypeCL0}

	host, port, err := ExtractHostPort(target)
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to parse target: %v", err)
		return result
	}
	addr := net.JoinHostPort(host, port)

	// Baseline: a normal request must yield exactly one response.
	baseRaw, _, err := SendRawRequest(ctx, addr, BuildBaselineRequest(host, path), d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("Baseline request failed: %v", err)
		return result
	}
	if CountResponses(baseRaw) > 1 {
		// The server pipelines/keep-alives extra responses even for a benign
		// request; the double-response signal would be ambiguous here.
		result.Evidence = "Baseline already produced multiple responses; CL.0 signal would be ambiguous"
		return result
	}

	canary := "assaycanary"
	probe := BuildCL0Payload(host, path, canary)
	result.Request = probe

	probeRaw, _, err := SendRawRequest(ctx, addr, probe, d.config.Timeout)
	if err != nil {
		result.Evidence = fmt.Sprintf("CL.0 probe failed: %v", err)
		return result
	}
	result.Response = probeRaw

	if CountResponses(probeRaw) < 2 {
		return result
	}

	result.Vulnerable = true
	result.Confidence = 0.85
	result.Evidence = "Outer request elicited multiple responses on one connection: " +
		"back-end ignored Content-Length and processed the smuggled request (CL.0 desync)"
	result.FrontendBehavior = "Forwards Content-Length"
	result.BackendBehavior = "Ignores Content-Length (treats body as next request)"
	return result
}
