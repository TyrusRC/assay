// Package idor provides Insecure Direct Object Reference (IDOR) and
// Broken Object Level Authorization (BOLA) vulnerability detection.
//
// IDOR vulnerabilities occur when an application exposes direct references
// to internal objects (such as database keys, file paths, or other identifiers)
// and fails to verify that the user is authorized to access those objects.
//
// This package supports detection of:
//   - Numeric ID manipulation (id=1 -> id=2)
//   - UUID parameter testing
//   - Base64-encoded ID manipulation
//   - Hex-encoded ID manipulation
//   - Path-based IDs (/users/123/profile)
//   - Query-based IDs (?user_id=123)
//   - Body-based IDs (JSON/form data)
//
// Detection techniques include:
//   - Response comparison for content differences
//   - Status code analysis (200 vs 403/404)
//   - Content-length comparison
//   - Sensitive data exposure detection
//   - Authorization bypass detection
//
// OWASP Mappings:
//   - WSTG-ATHZ-04: Testing for Insecure Direct Object References
//   - A01:2021: Broken Access Control
//   - API1:2023: Broken Object Level Authorization
//   - CWE-639: Authorization Bypass Through User-Controlled Key
package idor
