// Package cssinj provides CSS injection payloads for testing whether
// applications properly sanitize user input reflected in CSS contexts.
//
// Payloads include CSS expression(), url(), @import directives, and
// behavior-based payloads that can lead to data exfiltration or
// arbitrary code execution in older browsers.
//
// OWASP mappings:
//   - WSTG-CLNT-05 (Testing for CSS Injection)
//   - CWE-1236 (Improper Neutralization of Formula Elements in a CSV File)
package cssinj
