// Package sessionfixation provides detection for Session Fixation
// vulnerabilities (OWASP WSTG-SESS-03).
//
// Detection techniques:
//   - Pre-authentication session acceptance: a session cookie value chosen by
//     an attacker is presented to the login endpoint before authentication.
//     If the server keeps the same identifier after login instead of issuing
//     a freshly generated one, an attacker who fixated the victim's session
//     can hijack the authenticated session.
//   - Query-string session acceptance: some legacy applications honor session
//     identifiers passed via URL parameters. If a protected resource accepts
//     a session id presented through the query string, the application is
//     trivially fixable.
//
// OWASP mappings:
//   - WSTG-SESS-03 (Testing for Session Fixation)
//   - A01:2025 (Broken Access Control)
//   - CWE-384 (Session Fixation)
package sessionfixation
