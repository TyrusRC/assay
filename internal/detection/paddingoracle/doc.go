// Package paddingoracle probes a target endpoint for the classic
// CBC-mode padding-oracle side channel (WSTG-CRYP-02). The detector
// takes an encrypted token (base64- or hex-encoded) carried in a query
// parameter, flips the last byte of the ciphertext through every
// possible value (0..255) and re-submits the tampered token. Server
// responses are bucketed by (HTTP status, body-length band, response-
// time band); a discriminable oracle exists when 2+ distinct buckets
// emerge — most commonly the single "valid padding" response (200/302
// or a different error string) standing out from a sea of 500s.
//
// The detector is intentionally surgical: it only mutates the last
// byte of the final CBC block (the byte that controls PKCS#7 padding
// validity) and caps the probe budget at 256 attempts. A constant-
// time server that returns the same status / body length / timing
// regardless of payload will produce a single bucket and emit no
// finding.
//
// References:
//   - WSTG-CRYP-02 (Padding Oracle)
//   - OWASP Top 10 A04:2025 (Cryptographic Failures)
//   - CWE-209 (Information Exposure Through an Error Message)
//   - CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
//   - Vaudenay, "Security Flaws Induced by CBC Padding" (Eurocrypt 2002)
package paddingoracle
