// Package smuggling provides HTTP Request Smuggling vulnerability detection.
//
// HTTP Request Smuggling exploits discrepancies in how front-end and back-end
// servers parse HTTP request boundaries, allowing attackers to bypass security
// controls, access unauthorized resources, or poison web caches.
//
// # Vulnerability Types
//
// CL.TE (Content-Length takes precedence on frontend):
//   - Frontend server uses Content-Length header
//   - Backend server uses Transfer-Encoding header
//   - Attacker can smuggle requests by sending conflicting headers
//
// TE.CL (Transfer-Encoding takes precedence on frontend):
//   - Frontend server uses Transfer-Encoding header
//   - Backend server uses Content-Length header
//   - Chunked encoding terminates early, leaving smuggled data
//
// TE.TE (Transfer-Encoding obfuscation):
//   - Both servers use Transfer-Encoding
//   - One server fails to process obfuscated TE header
//   - Falls back to Content-Length, enabling smuggling
//
// # Detection Techniques
//
// The detector uses timing-based and differential response analysis:
//
//   - Timing: Vulnerable servers show timing delays when processing
//     conflicting headers (backend waits for more data)
//
//   - Differential: Different responses indicate header parsing
//     discrepancies between frontend and backend
//
// # Raw Socket Communication
//
// Standard HTTP clients normalize headers, making smuggling detection
// impossible. This package uses raw TCP sockets to send malformed
// requests with precise header control.
//
// # OWASP References
//
//   - WSTG-INPV-15: Testing for HTTP Request Smuggling
//   - CWE-444: Inconsistent Interpretation of HTTP Requests
//   - A05:2021: Security Misconfiguration
//
// # Usage
//
//	detector := smuggling.NewDetector()
//	ctx := context.Background()
//	results := detector.Detect(ctx, "example.com:80", "/")
//
//	for _, result := range results {
//	    if result.Vulnerable {
//	        fmt.Printf("Vulnerable to %s: %s\n", result.Type, result.Evidence)
//	    }
//	}
//
// # Security Considerations
//
// HTTP Request Smuggling tests can:
//   - Disrupt normal server operation
//   - Affect other users' requests (in shared environments)
//   - Cause cache poisoning
//
// Always test only with proper authorization.
package smuggling
