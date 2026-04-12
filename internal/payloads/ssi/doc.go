// Package ssi provides Server-Side Include (SSI) injection payloads for testing
// whether applications process SSI directives from user-controlled input.
//
// Payloads include SSI exec, include, echo, and config directives that
// should be rejected or sanitized by secure applications.
//
// OWASP mappings:
//   - WSTG-INPV-08 (Testing for SSI Injection)
//   - CWE-97 (Improper Neutralization of Server-Side Includes Within a Web Page)
package ssi
