// Package htmlinj provides HTML injection vulnerability detection.
//
// The detector identifies HTML injection vulnerabilities by injecting common
// HTML tags into parameters and checking whether they appear unencoded in the
// response body, indicating the application fails to sanitize user input.
//
// Detection techniques:
//   - Reflection-based: inject HTML tags and check for unencoded reflection
//   - WAF bypass: use encoding tricks to evade web application firewalls
//
// OWASP mappings:
//   - WSTG-CLNT-03 (Testing for HTML Injection)
//   - A03:2021 (Injection)
//   - CWE-79 (Improper Neutralization of Input During Web Page Generation)
package htmlinj
