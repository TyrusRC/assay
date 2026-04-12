// Package htmlinj provides HTML injection payloads for testing
// whether applications properly encode user input before reflecting
// it in HTML responses.
//
// Payloads include common HTML tags that should be encoded by secure
// applications: bold tags, image tags, div elements, anchor links,
// and WAF bypass variants using case mixing and attribute obfuscation.
//
// OWASP mappings:
//   - WSTG-CLNT-03 (Testing for HTML Injection)
//   - CWE-79 (Improper Neutralization of Input During Web Page Generation)
package htmlinj
