// Package storage provides detection for cookie and session management vulnerabilities.
// It checks for missing security attributes on cookies (Secure, HttpOnly, SameSite),
// overly broad Domain attributes, cookie injection via parameters, and low-entropy
// session IDs that may be predictable.
//
// OWASP references:
//   - WSTG-SESS-02: Cookie Attributes
//   - WSTG-SESS-03: Session Fixation
package storage
