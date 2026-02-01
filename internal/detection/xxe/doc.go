// Package xxe provides XML External Entity injection vulnerability detection.
// It uses multiple detection techniques including:
//   - Classic in-band XXE (file content in response)
//   - Error-based XXE (file content in error messages)
//   - Blind/OOB XXE (external callbacks)
//   - Parameter entity based XXE
package xxe
