// Package cssinj provides CSS injection vulnerability detection.
//
// The detector identifies CSS injection vulnerabilities by injecting CSS
// payloads (expression(), url(), @import) into parameters reflected in
// style contexts and checking whether they appear unfiltered in the response.
//
// Detection techniques:
//   - Reflection-based: inject CSS payloads and check for unfiltered reflection
//   - Style breakout: inject payloads that break out of style attributes
//   - WAF bypass: use encoding tricks to evade web application firewalls
//
// OWASP mappings:
//   - WSTG-CLNT-05 (Testing for CSS Injection)
//   - A03:2021 (Injection)
//   - CWE-1236 (Improper Neutralization of Formula Elements)
package cssinj
