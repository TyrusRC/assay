// Package ssrf provides Server-Side Request Forgery vulnerability detection.
// It uses multiple detection techniques including:
//   - Response-based detection (cloud metadata, internal services)
//   - Error message analysis
//   - Out-of-band callback detection
//   - DNS rebinding and bypass techniques
package ssrf
