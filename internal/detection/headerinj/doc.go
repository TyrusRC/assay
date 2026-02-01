// Package headerinj provides detection for HTTP Header Injection vulnerabilities.
//
// Header injection occurs when user-controlled input is included in HTTP
// response headers without proper sanitization, allowing attackers to inject
// arbitrary headers or split the HTTP response.
//
// Detection techniques:
//   - CRLF sequence injection into header values
//   - Response splitting verification
//   - WAF bypass techniques for filtered inputs
//
// OWASP mappings:
//   - WSTG-INPV-15 (Testing for HTTP Splitting/Smuggling)
//   - A03:2021 (Injection)
//   - CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
package headerinj
