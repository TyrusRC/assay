// Package smuggling provides HTTP Request Smuggling payloads for detecting
// CL.TE, TE.CL, and TE.TE vulnerabilities.
//
// HTTP Request Smuggling occurs when front-end and back-end servers
// interpret the boundary of HTTP requests differently, allowing attackers
// to "smuggle" malicious requests.
//
// Payload tables live in separate files alongside this one:
//
//	payloads_clte.go     — Content-Length-wins-then-Transfer-Encoding-wins
//	payloads_tecl.go     — Transfer-Encoding-wins-then-Content-Length-wins
//	payloads_tete.go     — both servers parse Transfer-Encoding but disagree
//	                       on obfuscated forms
//	obfuscations.go      — TE header obfuscation building blocks
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
// These are used to test how servers parse headers differently.
func GetTEObfuscations() []string {
	return teObfuscations
}
