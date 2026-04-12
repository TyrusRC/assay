// Package deser provides insecure deserialization vulnerability detection.
//
// The detector identifies deserialization vulnerabilities by sending serialized
// object markers and checking for platform-specific error responses that indicate
// the application is processing serialized input.
//
// Supported platforms:
//   - Java (ObjectInputStream, Base64-encoded markers)
//   - PHP (serialize/unserialize)
//   - Python (pickle deserialization)
//   - .NET (BinaryFormatter, ViewState, JSON type discriminators)
//
// Detection techniques:
//   - Serialized object marker injection
//   - Error-based detection via platform-specific error patterns
//   - Status code differential analysis
//
// OWASP mappings:
//   - WSTG-INPV-11 (Testing for Deserialization)
//   - A08:2021 (Software and Data Integrity Failures)
//   - CWE-502 (Deserialization of Untrusted Data)
package deser
