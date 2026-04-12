// Package storageinj detects client-side storage injection vulnerabilities.
//
// It uses a headless browser to test whether values stored in localStorage,
// sessionStorage, document.cookie, or window.name are unsafely reflected
// into the DOM, enabling DOM-based XSS attacks.
//
// It also checks for sensitive data (tokens, passwords, API keys) stored
// insecurely in client-side storage.
//
// OWASP mappings:
//   - WSTG-CLNT-12: Testing for Client-side Storage
//   - A03:2025: Injection
//   - A02:2025: Cryptographic Failures (sensitive data in storage)
//   - CWE-79: Cross-site Scripting
//   - CWE-922: Insecure Storage of Sensitive Information
package storageinj
