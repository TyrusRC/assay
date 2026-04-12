// Package racecond provides Race Condition vulnerability detection.
// It uses concurrent request testing to detect time-of-check to time-of-use
// (TOCTOU) vulnerabilities by:
//   - Sending multiple identical requests in parallel
//   - Comparing response consistency across concurrent requests
//   - Detecting state-changing operations that succeed multiple times
package racecond
