// Package behavior provides behavior-based vulnerability detection.
//
// Unlike signature-based detection, this package analyzes application responses
// to identify anomalies that indicate vulnerabilities without relying on specific
// payload signatures. It establishes a baseline response and compares subsequent
// probe results to detect deviations.
//
// Supported behavioral anomaly types:
//   - Timing anomalies (response time deviations)
//   - Content anomalies (unexpected response body changes)
//   - Status anomalies (HTTP status code differences)
//   - Error disclosure (verbose error messages in responses)
//   - Reflection (input echoed back in responses)
//   - Redirect anomalies (unexpected redirect behavior)
//   - Header anomalies (response header deviations)
package behavior
