// Package mfabypass provides detection for Multi-Factor Authentication (MFA)
// bypass weaknesses (WSTG-ATHN-11).
//
// Detection techniques:
//   - Step-skip: log in with username/password, then access protected
//     resource using the partial session WITHOUT submitting the OTP step.
//   - Null OTP value: submit empty / "0" / null OTP values and check whether
//     they are accepted by weak validators.
//   - Brute-force: submit 20 wrong OTPs in rapid succession and check
//     whether a rate-limit / lockout response is ever emitted.
//   - Response manipulation: replay the MFA submission while flipping a
//     verification cookie/header from false to true.
//
// OWASP mappings:
//   - WSTG-ATHN-11 (Testing Multi-Factor Authentication)
//   - A07:2025 (Identification and Authentication Failures)
//   - CWE-287 (Improper Authentication)
//   - CWE-307 (Improper Restriction of Excessive Authentication Attempts)
package mfabypass
