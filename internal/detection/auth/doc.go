// Package auth provides detection for authentication security vulnerabilities.
//
// The detector tests for common authentication weaknesses including default
// credentials, account enumeration via response discrepancies, and weak
// lockout mechanisms that fail to limit excessive authentication attempts.
//
// Detection techniques:
//   - Default credential testing against common username/password pairs
//   - Account enumeration via observable response differences
//   - Brute-force protection analysis through lockout mechanism testing
//
// OWASP mappings:
//   - WSTG-ATHN-02 (Testing for Default Credentials)
//   - WSTG-IDNT-04 (Testing for Account Enumeration)
//   - WSTG-ATHN-03 (Testing for Weak Lock Out Mechanism)
//   - A07:2021 (Identification and Authentication Failures)
//   - CWE-798 (Use of Hard-coded Credentials)
//   - CWE-204 (Observable Response Discrepancy)
//   - CWE-307 (Improper Restriction of Excessive Authentication Attempts)
package auth
