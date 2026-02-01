// Package tls provides SSL/TLS configuration analysis and vulnerability detection.
//
// The analyzer inspects the TLS configuration of target servers to identify
// weak cryptographic settings, certificate issues, and protocol-level
// vulnerabilities that could compromise transport layer security.
//
// Analysis capabilities:
//   - Protocol version detection (SSLv3, TLS 1.0/1.1/1.2/1.3)
//   - Cipher suite strength evaluation
//   - Certificate validity and expiration checking
//   - Certificate chain verification
//   - Self-signed certificate detection
//   - HSTS header requirement enforcement
//
// OWASP mappings:
//   - WSTG-CRYP-01 (Testing for Weak Transport Layer Security)
//   - A02:2021 (Cryptographic Failures)
//   - CWE-295 (Improper Certificate Validation)
//   - CWE-298 (Improper Validation of Certificate Expiration)
//   - CWE-319 (Cleartext Transmission of Sensitive Information)
//   - CWE-326 (Inadequate Encryption Strength)
package tls
